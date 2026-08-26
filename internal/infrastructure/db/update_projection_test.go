package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	bitcointxdecoder "github.com/arkade-os/arkd/internal/infrastructure/tx-decoder/bitcoin"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestUpdateProjectionsAfterOffchainTxEvents(t *testing.T) {
	ctx := t.Context()

	// Covers the finalized-offchain-tx projection's swept/dust persistence. The swept state is
	// derived from swept_vtxo (non-dust outputs of a swept/expired tx) or from a dust marker
	// landing in swept_marker (sub-dust outputs).
	t.Run("finalized swept tx", func(t *testing.T) {
		// A non-dust output of a swept (here, expired) tx must land in swept_vtxo or
		// it reads back as unswept despite Swept being set on the struct.
		t.Run("non-dust output persisted as swept", func(t *testing.T) {
			svc := newProjectionTestService(t)

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
			svc := newProjectionTestService(t)

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
			svc := newProjectionTestService(t)

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

func newProjectionTestService(t *testing.T) ports.RepoManager {
	t.Helper()
	svc, err := NewService(ServiceConfig{
		EventStoreType:   "badger",
		DataStoreType:    "sqlite",
		EventStoreConfig: []interface{}{"", nil},
		DataStoreConfig:  []interface{}{t.TempDir()},
		Settings:         validSettings(t),
	}, bitcointxdecoder.NewService())
	require.NoError(t, err)
	require.NotNil(t, svc)
	t.Cleanup(svc.Close)
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

	b64, err := ptx.B64Encode()
	require.NoError(t, err)
	return b64
}

func validSettings(t *testing.T) domain.Settings {
	t.Helper()

	delay := func(v uint32) arklib.RelativeLocktime {
		lt, _ := arklib.ParseRelativeLocktime(v)
		return lt
	}
	return domain.Settings{
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
