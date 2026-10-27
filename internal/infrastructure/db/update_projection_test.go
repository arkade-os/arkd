package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	pgdb "github.com/arkade-os/arkd/internal/infrastructure/db/postgres"
	bitcointxdecoder "github.com/arkade-os/arkd/internal/infrastructure/tx-decoder/bitcoin"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestUpdateProjectionsAfterOffchainTxEvents(t *testing.T) {
	ctx := t.Context()
	t.Run("batched finalization spends its input", func(t *testing.T) {
		svc := newProjectionTestService(t, newProjectionTestDBs(t))
		_, events := finalizedSubDustEvents(t)
		accepted := events[1].(domain.OffchainTxAccepted)
		var checkpoint string
		for _, checkpoint = range accepted.SignedCheckpointTxs {
			break
		}
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(checkpoint), true)
		require.NoError(t, err)
		prevout := ptx.UnsignedTx.TxIn[0].PreviousOutPoint
		input := domain.Outpoint{Txid: prevout.Hash.String(), VOut: prevout.Index}
		require.NoError(t, svc.Vtxos().AddVtxos(
			ctx, []domain.Vtxo{{Outpoint: input, Amount: 1000}},
		))

		svc.(*service).updateProjectionsAfterOffchainTxEvents(events)
		vtxos, err := svc.Vtxos().GetVtxos(ctx, []domain.Outpoint{input})
		require.NoError(t, err)
		require.Len(t, vtxos, 1)
		require.True(t, vtxos[0].Spent)
	})

	// Covers the finalized-offchain-tx projection's swept/dust persistence. The swept state is
	// derived from swept_vtxo (non-dust outputs of a swept/expired tx) or from a dust marker
	// landing in swept_marker (sub-dust outputs).
	t.Run("finalized swept tx", func(t *testing.T) {
		// A non-dust output of a swept (here, expired) tx must land in swept_vtxo or
		// it reads back as unswept despite Swept being set on the struct.
		t.Run("non-dust output persisted as swept", func(t *testing.T) {
			svc := newProjectionTestService(t, newProjectionTestDBs(t))

			// Ark tx with one non-dust taproot output.
			prevoutHash, err := chainhash.NewHashFromStr(randomString(t, 32))
			require.NoError(t, err)
			taprootScript := append([]byte{0x51, 0x20}, make([]byte, 32)...)
			// nolint
			rand.Read(taprootScript[2:])
			ptx, err := psbt.New(
				[]*wire.OutPoint{{Hash: *prevoutHash, Index: 0}},
				[]*wire.TxOut{{Value: 10000, PkScript: taprootScript}},
				3, 0, []uint32{wire.MaxTxInSequenceNum},
			)
			require.NoError(t, err)
			addPrevouts(t, ptx)
			arkTx, err := ptx.B64Encode()
			require.NoError(t, err)
			sweptArkTxid := ptx.UnsignedTx.TxID()

			checkpointTxid := randomString(t, 32)
			checkpointTx := randomTx(t)

			// Expiry in the past marks the tx swept at projection time.
			events := []domain.Event{
				domain.OffchainTxRequested{
					OffchainTxEvent: domain.OffchainTxEvent{
						Id: sweptArkTxid, Type: domain.EventTypeOffchainTxRequested,
					},
					ArkTx:                 arkTx,
					UnsignedCheckpointTxs: map[string]string{checkpointTxid: checkpointTx},
					StartingTimestamp:     time.Now().Add(-2 * time.Hour).Unix(),
				},
				domain.OffchainTxAccepted{
					OffchainTxEvent: domain.OffchainTxEvent{
						Id: sweptArkTxid, Type: domain.EventTypeOffchainTxAccepted,
					},
					CommitmentTxids:     map[string]string{checkpointTxid: randomString(t, 32)},
					RootCommitmentTxid:  randomString(t, 32),
					FinalArkTx:          arkTx,
					SignedCheckpointTxs: map[string]string{checkpointTxid: checkpointTx},
					ExpiryTimestamp:     time.Now().Add(-time.Hour).Unix(),
					Depth:               1,
				},
				domain.OffchainTxFinalized{
					OffchainTxEvent: domain.OffchainTxEvent{
						Id: sweptArkTxid, Type: domain.EventTypeOffchainTxFinalized,
					},
					FinalCheckpointTxs: map[string]string{checkpointTxid: checkpointTx},
					Timestamp:          time.Now().Unix(),
				},
			}
			require.NoError(t, svc.Events().Save(ctx, domain.OffchainTxTopic, sweptArkTxid, events))

			outpoint := domain.Outpoint{Txid: sweptArkTxid, VOut: 0}
			require.Eventually(t, func() bool {
				vtxos, err := svc.Vtxos().GetVtxos(ctx, []domain.Outpoint{outpoint})
				return err == nil && len(vtxos) == 1 && vtxos[0].Swept
			}, 5*time.Second, 100*time.Millisecond,
				"non-dust output of a swept tx must read back as swept")
		})

		// A sub-dust (OP_RETURN) output is swept via its dust marker landing in
		// swept_marker, independent of tx expiry.
		t.Run("sub-dust output persisted as swept", func(t *testing.T) {
			svc := newProjectionTestService(t, newProjectionTestDBs(t))

			outpoint, events := finalizedSubDustEvents(t)
			svc.(*service).updateProjectionsAfterOffchainTxEvents(events)

			vtxos, err := svc.Vtxos().GetVtxos(ctx, []domain.Outpoint{outpoint})
			require.NoError(t, err)
			require.Len(t, vtxos, 1, "sub-dust output must be persisted as a vtxo")
			require.True(t, vtxos[0].Swept,
				"a sub-dust vtxo must read back as swept so it is never spendable")
		})

		// Money-safety: if the dust marker sweep fails, the projection must abort
		// before AddVtxos so no spendable sub-dust vtxo is ever created.
		t.Run("dust marker sweep failure leaves no spendable vtxo", func(t *testing.T) {
			svc := newProjectionTestService(t, newProjectionTestDBs(t))

			// A failed projection must not notify downstream, so record any dispatch.
			var dispatched atomic.Bool
			svc.RegisterOffchainTxUpdateHandler(func(domain.OffchainTx) {
				dispatched.Store(true)
			})

			// AddMarker still creates the dust marker, but BulkSweepMarkers (which
			// runs before AddVtxos) errors, so the projection must abort and never
			// create the vtxo row. If AddVtxos ran first, or the failure were only
			// logged, the sub-dust output would be left spendable: this is exactly
			// the regression this subtest guards.
			svc.(*service).markerStore = &failingBulkSweepMarkerStore{
				MarkerRepository: svc.Markers(),
				err:              errors.New("forced swept write failure"),
			}

			outpoint, events := finalizedSubDustEvents(t)
			svc.(*service).updateProjectionsAfterOffchainTxEvents(events)

			vtxos, err := svc.Vtxos().GetVtxos(ctx, []domain.Outpoint{outpoint})
			require.NoError(t, err)
			require.Empty(t, vtxos,
				"a failed swept write must abort the projection before the vtxo is created")
			require.Never(t, dispatched.Load, 200*time.Millisecond, 20*time.Millisecond,
				"a failed projection must not dispatch the offchain update")
		})
	})
}

func TestUpdateProjectionsAfterRoundEvents(t *testing.T) {
	ctx := t.Context()

	// When projection a finalized batch that includes boarding inputs, they must be retrievable
	// with the utxo repository.
	t.Run("finalized round with boarding inputs", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			t.Run("boarding utxos are recorded as cosigned", func(t *testing.T) {
				svc := newProjectionTestService(t, newProjectionTestDBs(t))
				f := newRoundWithBoardingInputs(t, svc)
				svc.(*service).txDecoder = f.decoder

				var dispatched atomic.Bool
				svc.RegisterBatchUpdateHandler(func(domain.Round) { dispatched.Store(true) })

				svc.(*service).updateProjectionsAfterRoundEvents(f.events)

				utxos, err := svc.CosignedUtxos().GetUtxos(ctx, []domain.Outpoint{
					f.vtxo.Outpoint, f.unrolledVtxo.Outpoint, f.boarding.Outpoint,
				})
				require.NoError(t, err)
				require.Len(t, utxos, 1, "only the boarding input must be recorded")
				require.Equal(t, f.boarding.Outpoint, utxos[0].Outpoint)
				require.Equal(t, f.boarding.Prevout.Amount, utxos[0].Amount)
				require.Equal(t, hex.EncodeToString(f.boarding.Prevout.PkScript[2:]), utxos[0].PubKey)
				require.Equal(t, f.commitmentTxid, utxos[0].Spend.Txid)
				require.False(t, utxos[0].Spend.IsConfirmed())
				require.Eventually(t, dispatched.Load, time.Second, 20*time.Millisecond)
			})
		})

		// These cases are all impossible to happen but we still ensure we're panic safe.
		t.Run("invalid", func(t *testing.T) {
			// A proof the decoder can't read must abort the projection: recording nothing
			// would leave the boarding utxo free to be cosigned again once the intents cache
			// releases it.
			t.Run("undecodable proof aborts the projection", func(t *testing.T) {
				svc := newProjectionTestService(t, newProjectionTestDBs(t))
				f := newRoundWithBoardingInputs(t, svc)
				f.decoder.err = errors.New("forced decode failure")
				svc.(*service).txDecoder = f.decoder

				var dispatched atomic.Bool
				svc.RegisterBatchUpdateHandler(func(domain.Round) { dispatched.Store(true) })

				svc.(*service).updateProjectionsAfterRoundEvents(f.events)

				utxos, err := svc.CosignedUtxos().GetUtxos(ctx, []domain.Outpoint{f.boarding.Outpoint})
				require.NoError(t, err)
				require.Empty(t, utxos)
				require.Never(
					t, dispatched.Load, 200*time.Millisecond, 20*time.Millisecond,
					"a failed projection must not dispatch the round update",
				)
			})

			// A boarding utxo already recorded (already cosigned) must abort the projection
			// rather than being silently overwritten.
			t.Run("already cosigned boarding utxo aborts the projection", func(t *testing.T) {
				svc := newProjectionTestService(t, newProjectionTestDBs(t))
				f := newRoundWithBoardingInputs(t, svc)
				svc.(*service).txDecoder = f.decoder

				err := svc.CosignedUtxos().AddUtxos(ctx, []domain.Utxo{{
					Outpoint:  f.boarding.Outpoint,
					Amount:    f.boarding.Prevout.Amount,
					PubKey:    hex.EncodeToString(f.boarding.Prevout.PkScript[2:]),
					Spend:     domain.UtxoSpend{Txid: randomString(t, 32)},
					CreatedAt: time.Now().Unix(),
				}}, "")
				require.NoError(t, err)

				var dispatched atomic.Bool
				svc.RegisterBatchUpdateHandler(func(domain.Round) { dispatched.Store(true) })

				svc.(*service).updateProjectionsAfterRoundEvents(f.events)

				require.Never(
					t, dispatched.Load, 200*time.Millisecond, 20*time.Millisecond,
					"a failed projection must not dispatch the round update",
				)
			})
		})
	})
}

// The events go through the real event store, so the projection is exercised the way the
// application drives it: saved, decoded, replayed and handled.
func TestUpdateProjectionsAfterOnchainTxEvents(t *testing.T) {
	ctx := t.Context()

	t.Run("cosigned onchain tx", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			t.Run("broadcast records the signed inputs, confirmation confirms them", func(t *testing.T) {
				svc := newProjectionTestService(t, newProjectionTestDBs(t))
				f := newOnchainTxFixture(t)

				require.NoError(t, svc.Events().Save(
					ctx, domain.OnchainTxTopic, f.txid, []domain.Event{f.broadcasted},
				))

				// Only the signed input is recorded, the foreign one is left alone.
				require.Eventually(t, func() bool {
					utxos, err := svc.CosignedUtxos().GetUtxos(ctx, []domain.Outpoint{f.signed})
					return err == nil && len(utxos) == 1
				}, 5*time.Second, 50*time.Millisecond)
				utxos, err := svc.CosignedUtxos().GetUtxos(
					ctx, []domain.Outpoint{f.signed, f.foreign},
				)
				require.NoError(t, err)
				require.Len(t, utxos, 1)
				require.Equal(t, f.signed, utxos[0].Outpoint)
				require.Equal(t, f.amount, utxos[0].Amount)
				require.Equal(t, hex.EncodeToString(f.pkScript[2:]), utxos[0].PubKey)
				require.Equal(t, f.broadcasted.Timestamp, utxos[0].CreatedAt)
				require.Equal(t, f.txid, utxos[0].Spend.Txid)
				require.False(t, utxos[0].Spend.IsConfirmed())

				// The tx is recorded along with its utxos.
				txs, err := svc.CosignedUtxos().GetOnchainTxs(ctx, []string{f.txid})
				require.NoError(t, err)
				require.Equal(t, []string{f.broadcasted.Tx}, txs)

				require.NoError(t, svc.Events().Save(
					ctx, domain.OnchainTxTopic, f.txid, []domain.Event{f.confirmed},
				))

				require.Eventually(t, func() bool {
					utxos, err := svc.CosignedUtxos().GetUtxos(ctx, []domain.Outpoint{f.signed})
					return err == nil && len(utxos) == 1 && utxos[0].Spend.IsConfirmed()
				}, 5*time.Second, 50*time.Millisecond)
				utxos, err = svc.CosignedUtxos().GetUtxos(ctx, []domain.Outpoint{f.signed})
				require.NoError(t, err)
				require.Equal(t, f.txid, utxos[0].Spend.Txid)
				require.Equal(t, f.confirmed.ConfirmedAtTime, utxos[0].Spend.ConfirmedAtTime)
				require.Equal(t, f.confirmed.ConfirmedAtHeight, utxos[0].Spend.ConfirmedAtHeight)

				cosigned, boarding, unrolled, err := svc.CosignedUtxos().GetUnconfirmedUtxos(ctx)
				require.NoError(t, err)
				require.Empty(t, cosigned)
				require.Empty(t, boarding)
				require.Empty(t, unrolled)
			})

			// The signed input is an unrolled vtxo: it is recorded as a pointer to the vtxo,
			// the utxo table refuses a row duplicating it, and read back with the vtxo's
			// pubkey and amount. The spending tx is stored, so the utxo counts as cosigned.
			t.Run("broadcast records an unrolled vtxo as a pointer", func(t *testing.T) {
				svc := newProjectionTestService(t, newProjectionTestDBs(t))
				f := newOnchainTxFixture(t)
				require.NoError(t, svc.Vtxos().AddVtxos(ctx, []domain.Vtxo{{
					Outpoint:  f.signed,
					PubKey:    hex.EncodeToString(f.pkScript[2:]),
					Amount:    f.amount,
					ExpiresAt: time.Now().Add(time.Hour).Unix(),
				}}))
				require.NoError(t, svc.Vtxos().UnrollVtxos(ctx, []domain.Outpoint{f.signed}))

				require.NoError(t, svc.Events().Save(
					ctx, domain.OnchainTxTopic, f.txid, []domain.Event{f.broadcasted},
				))

				require.Eventually(t, func() bool {
					utxos, err := svc.CosignedUtxos().GetUtxos(ctx, []domain.Outpoint{f.signed})
					return err == nil && len(utxos) == 1
				}, 5*time.Second, 50*time.Millisecond)
				utxos, err := svc.CosignedUtxos().GetUtxos(ctx, []domain.Outpoint{f.signed})
				require.NoError(t, err)
				require.Len(t, utxos, 1)
				require.Equal(t, f.amount, utxos[0].Amount)
				require.Equal(t, hex.EncodeToString(f.pkScript[2:]), utxos[0].PubKey)
				require.Equal(t, f.txid, utxos[0].Spend.Txid)

				cosigned, boarding, unrolled, err := svc.CosignedUtxos().GetUnconfirmedUtxos(ctx)
				require.NoError(t, err)
				require.Len(t, cosigned, 1)
				require.Equal(t, f.signed, cosigned[0].Outpoint)
				require.Empty(t, boarding)
				require.Empty(t, unrolled)
			})
		})

		// These cases are all impossible to happen but we still ensure they're harmless.
		t.Run("invalid", func(t *testing.T) {
			t.Run("undecodable tx records nothing", func(t *testing.T) {
				svc := newProjectionTestService(t, newProjectionTestDBs(t))
				f := newOnchainTxFixture(t)
				f.broadcasted.Tx = "not a psbt"

				require.NoError(t, svc.Events().Save(
					ctx, domain.OnchainTxTopic, f.txid, []domain.Event{f.broadcasted},
				))

				require.Never(t, func() bool {
					utxos, err := svc.CosignedUtxos().GetUtxos(ctx, []domain.Outpoint{f.signed})
					txs, txErr := svc.CosignedUtxos().GetOnchainTxs(ctx, []string{f.txid})
					return err != nil || txErr != nil || len(utxos) > 0 || len(txs) > 0
				}, 500*time.Millisecond, 50*time.Millisecond)
			})

			t.Run("confirmation of a tx never broadcasted records nothing", func(t *testing.T) {
				svc := newProjectionTestService(t, newProjectionTestDBs(t))
				f := newOnchainTxFixture(t)

				require.NoError(t, svc.Events().Save(
					ctx, domain.OnchainTxTopic, f.txid, []domain.Event{f.confirmed},
				))

				require.Never(t, func() bool {
					utxos, err := svc.CosignedUtxos().GetUtxos(ctx, []domain.Outpoint{f.signed})
					txs, txErr := svc.CosignedUtxos().GetOnchainTxs(ctx, []string{f.txid})
					return err != nil || txErr != nil || len(utxos) > 0 || len(txs) > 0
				}, 500*time.Millisecond, 50*time.Millisecond)
			})

			t.Run("duplicated broadcast leaves the record untouched", func(t *testing.T) {
				svc := newProjectionTestService(t, newProjectionTestDBs(t))
				f := newOnchainTxFixture(t)

				require.NoError(t, svc.Events().Save(
					ctx, domain.OnchainTxTopic, f.txid, []domain.Event{f.broadcasted},
				))
				require.Eventually(t, func() bool {
					utxos, err := svc.CosignedUtxos().GetUtxos(ctx, []domain.Outpoint{f.signed})
					return err == nil && len(utxos) == 1
				}, 5*time.Second, 50*time.Millisecond)

				// Replaying the same broadcast is a no-op for the domain, and the utxo can't be
				// inserted twice anyway.
				require.NoError(t, svc.Events().Save(
					ctx, domain.OnchainTxTopic, f.txid, []domain.Event{f.broadcasted},
				))
				require.Never(t, func() bool {
					utxos, err := svc.CosignedUtxos().GetUtxos(ctx, []domain.Outpoint{f.signed})
					return err != nil || len(utxos) != 1 || utxos[0].Spend.IsConfirmed()
				}, 500*time.Millisecond, 50*time.Millisecond)
			})
		})
	})
}

type projectionTestDBs struct {
	event string
	data  string
}

// testDatabase returns the DSN of the named database of the postgres container started by
// `make pgtest`, creating the database if it does not exist yet. The tests of this package
// reset the databases they use, and packages run in parallel, so they use databases of
// their own.
func testDatabase(t *testing.T, name string) string {
	t.Helper()
	const dsn = "postgresql://root:secret@127.0.0.1:5432/%s?sslmode=disable"
	admin, err := sql.Open("postgres", fmt.Sprintf(dsn, "event"))
	require.NoError(t, err)
	defer func() { _ = admin.Close() }()

	var exists bool
	require.NoError(t, admin.QueryRow(
		"SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", name,
	).Scan(&exists))
	if !exists {
		_, err = admin.Exec("CREATE DATABASE " + pq.QuoteIdentifier(name))
		require.NoError(t, err)
	}
	return fmt.Sprintf(dsn, name)
}

// newProjectionTestDBs empties the databases of this package and returns their DSNs.
func newProjectionTestDBs(t *testing.T) projectionTestDBs {
	t.Helper()
	dbs := projectionTestDBs{
		event: testDatabase(t, "db_events"),
		data:  testDatabase(t, "projection"),
	}
	for _, dsn := range []string{dbs.event, dbs.data} {
		conn, err := sql.Open("postgres", dsn)
		require.NoError(t, err)
		_, err = conn.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	}
	return dbs
}

func newProjectionTestService(t *testing.T, dbs projectionTestDBs) ports.RepoManager {
	t.Helper()
	svc, err := NewService(ServiceConfig{
		EventStoreType:   "postgres",
		DataStoreType:    "postgres",
		EventStoreConfig: []interface{}{dbs.event, false, pgdb.ConnectionConfig{}},
		DataStoreConfig:  []interface{}{dbs.data, false, pgdb.ConnectionConfig{}},
		Settings:         validSettings(t),
	}, bitcointxdecoder.NewService())
	require.NoError(t, err)
	require.NotNil(t, svc)
	t.Cleanup(svc.Close)
	require.NoError(t, svc.Reconcile())
	return svc
}

// finalizedSubDustEvents builds the event stream for a finalized offchain tx
// whose single output is a sub-dust OP_RETURN. Expiry is in the future so the tx
// is not considered swept: the output is swept solely because it is sub-dust,
// which isolates the dust-marker path under test.
func finalizedSubDustEvents(t *testing.T) (domain.Outpoint, []domain.Event) {
	t.Helper()

	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	subDustScript, err := script.SubDustScript(key.PubKey())
	require.NoError(t, err)

	prevoutHash, err := chainhash.NewHashFromStr(randomString(t, 32))
	require.NoError(t, err)
	ptx, err := psbt.New(
		[]*wire.OutPoint{{Hash: *prevoutHash, Index: 0}},
		[]*wire.TxOut{{Value: 100, PkScript: subDustScript}},
		3, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)
	addPrevouts(t, ptx)
	arkTx, err := ptx.B64Encode()
	require.NoError(t, err)
	arkTxid := ptx.UnsignedTx.TxID()

	checkpointTxid := randomString(t, 32)
	checkpointTx := randomTx(t)

	events := []domain.Event{
		domain.OffchainTxRequested{
			OffchainTxEvent: domain.OffchainTxEvent{
				Id: arkTxid, Type: domain.EventTypeOffchainTxRequested,
			},
			ArkTx:                 arkTx,
			UnsignedCheckpointTxs: map[string]string{checkpointTxid: checkpointTx},
			StartingTimestamp:     time.Now().Add(-time.Hour).Unix(),
		},
		domain.OffchainTxAccepted{
			OffchainTxEvent: domain.OffchainTxEvent{
				Id: arkTxid, Type: domain.EventTypeOffchainTxAccepted,
			},
			CommitmentTxids:     map[string]string{checkpointTxid: randomString(t, 32)},
			RootCommitmentTxid:  randomString(t, 32),
			FinalArkTx:          arkTx,
			SignedCheckpointTxs: map[string]string{checkpointTxid: checkpointTx},
			ExpiryTimestamp:     time.Now().Add(time.Hour).Unix(),
			Depth:               1,
		},
		domain.OffchainTxFinalized{
			OffchainTxEvent: domain.OffchainTxEvent{
				Id: arkTxid, Type: domain.EventTypeOffchainTxFinalized,
			},
			FinalCheckpointTxs: map[string]string{checkpointTxid: checkpointTx},
			Timestamp:          time.Now().Unix(),
		},
	}
	return domain.Outpoint{Txid: arkTxid, VOut: 0}, events
}

// failingBulkSweepMarkerStore delegates every marker operation to the real store
// except BulkSweepMarkers, which fails, to exercise the projection abort path.
type failingBulkSweepMarkerStore struct {
	domain.MarkerRepository
	err error
}

// boardingRoundFixture is a finalized round with one intent claiming a vtxo, an unrolled
// vtxo and a boarding utxo, and a decoder that answers the intent proof with those inputs.
// The round has no vtxo tree nor forfeit txs, so the proof is the only tx decoded.
type boardingRoundFixture struct {
	events         []domain.Event
	decoder        *mockTxDecoder
	commitmentTxid string
	vtxo           domain.Vtxo
	unrolledVtxo   domain.Vtxo
	boarding       ports.TxIn
}

func newRoundWithBoardingInputs(t *testing.T, svc ports.RepoManager) *boardingRoundFixture {
	t.Helper()
	ctx := t.Context()

	newVtxo := func() domain.Vtxo {
		commitmentTxid := randomString(t, 32)
		return domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: randomString(t, 32), VOut: 0},
			PubKey:             randomString(t, 32),
			Amount:             1000,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid},
			ExpiresAt:          time.Now().Add(time.Hour).Unix(),
			CreatedAt:          time.Now().Unix(),
		}
	}
	vtxo, unrolledVtxo := newVtxo(), newVtxo()
	require.NoError(t, svc.Vtxos().AddVtxos(ctx, []domain.Vtxo{vtxo, unrolledVtxo}))
	require.NoError(t, svc.Vtxos().UnrollVtxos(ctx, []domain.Outpoint{unrolledVtxo.Outpoint}))
	unrolledVtxo.Unrolled = true

	taprootScript := append([]byte{0x51, 0x20}, make([]byte, 32)...)
	// nolint
	rand.Read(taprootScript[2:])
	boarding := ports.TxIn{
		Outpoint: domain.Outpoint{Txid: randomString(t, 32), VOut: 1},
		Prevout:  &ports.TxOut{Amount: 5000, PkScript: taprootScript},
	}
	txIn := func(v domain.Vtxo) ports.TxIn {
		pkScript, err := hex.DecodeString("5120" + v.PubKey)
		require.NoError(t, err)
		return ports.TxIn{
			Outpoint: v.Outpoint,
			Prevout:  &ports.TxOut{Amount: v.Amount, PkScript: pkScript},
		}
	}

	// Input 0 of a proof is the BIP322 message input, it carries a zero-valued prevout.
	proof := "proof-" + randomString(t, 8)
	decoder := &mockTxDecoder{txs: map[string]decodedTx{
		proof: {
			txid: randomString(t, 32),
			ins: []ports.TxIn{
				{
					Outpoint: domain.Outpoint{Txid: randomString(t, 32), VOut: 0},
					Prevout:  &ports.TxOut{Amount: 0, PkScript: taprootScript},
				},
				txIn(vtxo), txIn(unrolledVtxo), boarding,
			},
		},
	}}

	roundId := randomString(t, 16)
	commitmentTxid := randomString(t, 32)
	now := time.Now().Unix()
	events := []domain.Event{
		domain.RoundStarted{
			RoundEvent: domain.RoundEvent{Id: roundId, Type: domain.EventTypeRoundStarted},
			Timestamp:  now,
		},
		domain.IntentsRegistered{
			RoundEvent: domain.RoundEvent{Id: roundId, Type: domain.EventTypeIntentsRegistered},
			Intents: []domain.Intent{{
				Id:        randomString(t, 16),
				Proof:     proof,
				Message:   "message",
				Txid:      randomString(t, 32),
				Inputs:    []domain.Vtxo{vtxo, unrolledVtxo},
				Receivers: []domain.Receiver{{PubKey: randomString(t, 32), Amount: 7000}},
			}},
		},
		domain.RoundFinalizationStarted{
			RoundEvent: domain.RoundEvent{
				Id: roundId, Type: domain.EventTypeRoundFinalizationStarted,
			},
			CommitmentTxid: commitmentTxid,
			CommitmentTx:   randomTx(t),
		},
		domain.RoundFinalized{
			RoundEvent:        domain.RoundEvent{Id: roundId, Type: domain.EventTypeRoundFinalized},
			FinalCommitmentTx: randomTx(t),
			Timestamp:         now + 1,
		},
	}

	return &boardingRoundFixture{
		events:         events,
		decoder:        decoder,
		commitmentTxid: commitmentTxid,
		vtxo:           vtxo,
		unrolledVtxo:   unrolledVtxo,
		boarding:       boarding,
	}
}

type decodedTx struct {
	txid string
	ins  []ports.TxIn
	outs []ports.TxOut
}

// mockTxDecoder answers the txs it knows and fails on any other, or on all of them if err
// is set.
type mockTxDecoder struct {
	txs map[string]decodedTx
	err error
}

func (m *mockTxDecoder) DecodeTx(tx string) (string, []ports.TxIn, []ports.TxOut, error) {
	if m.err != nil {
		return "", nil, nil, m.err
	}
	decoded, ok := m.txs[tx]
	if !ok {
		return "", nil, nil, errors.New("unknown tx")
	}
	return decoded.txid, decoded.ins, decoded.outs, nil
}

func (f *failingBulkSweepMarkerStore) BulkSweepMarkers(
	_ context.Context, _ []string, _ int64,
) error {
	return f.err
}

func randomString(t *testing.T, len int) string {
	t.Helper()

	buf := make([]byte, len)
	// nolint
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

func randomTx(t *testing.T) string {
	t.Helper()

	hash, _ := chainhash.NewHashFromStr(randomString(t, 32))

	ptx, _ := psbt.New(
		[]*wire.OutPoint{
			{
				Hash:  *hash,
				Index: 0,
			},
		},
		[]*wire.TxOut{
			{
				Value: 1000000,
			},
		},
		3,
		0,
		[]uint32{
			wire.MaxTxInSequenceNum,
		},
	)
	addPrevouts(t, ptx)

	b64, err := ptx.B64Encode()
	require.NoError(t, err)
	return b64
}

// addPrevouts gives every input a taproot witness utxo, as every tx decoded by the
// projections carries one in production and the decoder requires it.
// onchainTxFixture is a cosigned onchain tx spending one signed input, ours to record, and one
// foreign input, along with its lifecycle events.
type onchainTxFixture struct {
	txid        string
	signed      domain.Outpoint
	foreign     domain.Outpoint
	amount      uint64
	pkScript    []byte
	broadcasted domain.OnchainTxBroadcasted
	confirmed   domain.OnchainTxConfirmed
}

func newOnchainTxFixture(t *testing.T) *onchainTxFixture {
	t.Helper()

	signedHash, err := chainhash.NewHashFromStr(randomString(t, 32))
	require.NoError(t, err)
	foreignHash, err := chainhash.NewHashFromStr(randomString(t, 32))
	require.NoError(t, err)
	ptx, err := psbt.New(
		[]*wire.OutPoint{{Hash: *signedHash, Index: 1}, {Hash: *foreignHash, Index: 0}},
		[]*wire.TxOut{{Value: 140_000, PkScript: randomTaprootScript(t)}},
		2, 0, []uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)

	amount := uint64(100_000)
	pkScript := randomTaprootScript(t)
	updater, err := psbt.NewUpdater(ptx)
	require.NoError(t, err)
	require.NoError(t, updater.AddInWitnessUtxo(
		&wire.TxOut{Value: int64(amount), PkScript: pkScript}, 0,
	))
	require.NoError(t, updater.AddInWitnessUtxo(
		&wire.TxOut{Value: 50_000, PkScript: randomTaprootScript(t)}, 1,
	))
	tx, err := ptx.B64Encode()
	require.NoError(t, err)
	txid := ptx.UnsignedTx.TxID()

	signed := domain.Outpoint{Txid: signedHash.String(), VOut: 1}
	foreign := domain.Outpoint{Txid: foreignHash.String(), VOut: 0}
	now := time.Now().Unix()

	return &onchainTxFixture{
		txid:     txid,
		signed:   signed,
		foreign:  foreign,
		amount:   amount,
		pkScript: pkScript,
		broadcasted: domain.OnchainTxBroadcasted{
			OnchainTxEvent: domain.OnchainTxEvent{
				Id: txid, Type: domain.EventTypeOnchainTxBroadcasted,
			},
			Tx:           tx,
			SignedInputs: map[string]struct{}{signed.String(): {}},
			Timestamp:    now,
		},
		confirmed: domain.OnchainTxConfirmed{
			OnchainTxEvent: domain.OnchainTxEvent{
				Id: txid, Type: domain.EventTypeOnchainTxConfirmed,
			},
			ConfirmedAtTime:   now + 600,
			ConfirmedAtHeight: 101,
		},
	}
}

func randomTaprootScript(t *testing.T) []byte {
	t.Helper()
	pkScript := append([]byte{0x51, 0x20}, make([]byte, 32)...)
	// nolint
	rand.Read(pkScript[2:])
	return pkScript
}

func addPrevouts(t *testing.T, ptx *psbt.Packet) {
	t.Helper()

	updater, err := psbt.NewUpdater(ptx)
	require.NoError(t, err)
	for i := range ptx.Inputs {
		pkScript := append([]byte{0x51, 0x20}, make([]byte, 32)...)
		// nolint
		rand.Read(pkScript[2:])
		require.NoError(t, updater.AddInWitnessUtxo(&wire.TxOut{Value: 1000, PkScript: pkScript}, i))
	}
}

func validSettings(t *testing.T) domain.Settings {
	t.Helper()

	delay := func(v uint32) arklib.RelativeLocktime {
		lt, _ := arklib.ParseRelativeLocktime(v)
		return lt
	}
	return domain.Settings{
		FinalizationLockTTL:           5 * time.Minute,
		SessionDuration:               30 * time.Second,
		UnrolledVtxoMinExpiryMargin:   30 * time.Second,
		BanThreshold:                  3,
		BanDuration:                   3600 * time.Second,
		UnilateralExitDelay:           delay(512),
		PublicUnilateralExitDelay:     delay(512),
		CheckpointExitDelay:           delay(1024),
		BoardingExitDelay:             delay(1536),
		VtxoTreeExpiry:                delay(1024),
		RoundMinParticipantsCount:     2,
		RoundMaxParticipantsCount:     128,
		VtxoMinAmount:                 1000,
		VtxoMaxAmount:                 100000000,
		UtxoMinAmount:                 5000,
		UtxoMaxAmount:                 500000000,
		SettlementMinExpiryGap:        7200 * time.Second,
		VtxoNoCsvValidationCutoffDate: time.Unix(1700000000, 0),
		MaxTxWeight:                   400000,
		MaxOpReturnOutputs:            3,
		AssetTxMaxWeightRatio:         0.5,
		BuildVersionHeader:            "v1.0.0",
		BuildVersionHeaderRequired:    true,
		DigestHeaderRequired:          true,
		UpdatedAt:                     time.Unix(1700000000, 0),
	}
}
