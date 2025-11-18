package db_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/internal/infrastructure/db"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	f1        = "cHNidP8BADwBAAAAAauqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD/////AegDAAAAAAAAAAAAAAAAAAA="
	f2        = "cHNidP8BADwBAAAAAayqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD/////AegDAAAAAAAAAAAAAAAAAAA="
	f3        = "cHNidP8BADwBAAAAAa2qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD/////AegDAAAAAAAAAAAAAAAAAAA="
	f4        = "cHNidP8BADwBAAAAAa6qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD/////AegDAAAAAAAAAAAAAAAAAAA="
	emptyTx   = "0200000000000000000000"
	pubkey    = "25a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967"
	pubkey2   = "33ffb3dee353b1a9ebe4ced64b946238d0a4ac364f275d771da6ad2445d07ae0"
	txida     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	txidb     = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	arkTxid   = txida
	sweepTxid = "ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss"
	sweepTx   = "cHNidP8BADwBAAAAAauqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD/////AegDAAAAAAAAAAAAAAAAAAA="
)

var (
	vtxoTree = tree.FlatTxTree{
		{
			Txid:     randomString(32),
			Tx:       randomTx(),
			Children: nil,
		},
		{
			Txid: randomString(32),
			Tx:   randomTx(),
			Children: map[uint32]string{
				0: randomString(32),
			},
		},
		{
			Txid: randomString(32),
			Tx:   randomTx(),
			Children: map[uint32]string{
				0: randomString(32),
				1: randomString(32),
			},
		},
		{
			Txid: randomString(32),
			Tx:   randomTx(),
			Children: map[uint32]string{
				0: randomString(32),
				1: randomString(32),
			},
		},
		{
			Txid: randomString(32),
			Tx:   randomTx(),
			Children: map[uint32]string{
				0: randomString(32),
				1: randomString(32),
			},
		},
	}
	connectorsTree = tree.FlatTxTree{
		{
			Txid: randomString(32),
			Tx:   randomTx(),
			Children: map[uint32]string{
				0: randomString(32),
			},
		},
		{
			Txid: randomString(32),
			Tx:   randomTx(),
			Children: map[uint32]string{
				0: randomString(32),
			},
		},
		{
			Txid: randomString(32),
			Tx:   randomTx(),
			Children: map[uint32]string{
				0: randomString(32),
			},
		},
		{
			Txid: randomString(32),
			Tx:   randomTx(),
		},
	}

	f1Tx = func() domain.ForfeitTx {
		return domain.ForfeitTx{
			Txid: txida,
			Tx:   f1,
		}
	}
	f2Tx = func() domain.ForfeitTx {
		return domain.ForfeitTx{
			Txid: txidb,
			Tx:   f2,
		}
	}
	f3Tx = func() domain.ForfeitTx {
		return domain.ForfeitTx{
			Txid: randomString(32),
			Tx:   f3,
		}
	}
	f4Tx = func() domain.ForfeitTx {
		return domain.ForfeitTx{
			Txid: randomString(32),
			Tx:   f4,
		}
	}
	now          = time.Now()
	endTimestamp = now.Add(3 * time.Second).Unix()
)

func TestMain(m *testing.M) {
	m.Run()
	_ = os.Remove("test.db")
}

func TestService(t *testing.T) {
	dbDir := t.TempDir()
	pgDns := "postgresql://root:secret@127.0.0.1:5432/projection?sslmode=disable"
	pgEventDns := "postgresql://root:secret@127.0.0.1:5432/event?sslmode=disable"
	tests := []struct {
		name   string
		config db.ServiceConfig
	}{
		{
			name: "repo_manager_with_badger_stores",
			config: db.ServiceConfig{
				EventStoreType:   "badger",
				DataStoreType:    "badger",
				EventStoreConfig: []interface{}{"", nil},
				DataStoreConfig:  []interface{}{"", nil},
			},
		},
		{
			name: "repo_manager_with_sqlite_stores",
			config: db.ServiceConfig{
				EventStoreType:   "badger",
				DataStoreType:    "sqlite",
				EventStoreConfig: []interface{}{"", nil},
				DataStoreConfig:  []interface{}{dbDir},
			},
		},
		{
			name: "repo_manager_with_postgres_stores",
			config: db.ServiceConfig{
				EventStoreType:   "postgres",
				DataStoreType:    "postgres",
				EventStoreConfig: []interface{}{pgEventDns},
				DataStoreConfig:  []interface{}{pgDns},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := db.NewService(tt.config, nil)
			require.NoError(t, err)
			defer svc.Close()

			testEventRepository(t, svc)
			testRoundRepository(t, svc)
			testVtxoRepository(t, svc)
			testOffchainTxRepository(t, svc)
			testScheduledSessionRepository(t, svc)
			testConvictionRepository(t, svc)
		})
	}
}

func testEventRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_event_repository", func(t *testing.T) {
		fixtures := []struct {
			topic    string
			id       string
			events   []domain.Event
			handlers []func(events []domain.Event)
		}{
			{
				topic: domain.RoundTopic,
				id:    "42dd81f7-cadd-482c-bf69-8e9209aae9f3",
				events: []domain.Event{
					domain.RoundStarted{
						RoundEvent: domain.RoundEvent{
							Id:   "42dd81f7-cadd-482c-bf69-8e9209aae9f3",
							Type: domain.EventTypeRoundStarted,
						},
						Timestamp: 1701190270,
					},
				},
				handlers: []func(events []domain.Event){
					func(events []domain.Event) {
						round := domain.NewRoundFromEvents(events)

						require.NotNil(t, round)
						require.Len(t, round.Events(), 1)
						require.True(t, round.IsStarted())
						require.False(t, round.IsFailed())
						require.False(t, round.IsEnded())
					},
					func(events []domain.Event) {
						require.Len(t, events, 1)
					},
				},
			},
			{
				topic: domain.RoundTopic,
				id:    "1ea610ff-bf3e-4068-9bfd-b6c3f553467e",
				events: []domain.Event{
					domain.RoundStarted{
						RoundEvent: domain.RoundEvent{
							Id:   "1ea610ff-bf3e-4068-9bfd-b6c3f553467e",
							Type: domain.EventTypeRoundStarted,
						},
						Timestamp: 1701190270,
					},
					domain.RoundFinalizationStarted{
						RoundEvent: domain.RoundEvent{
							Id:   "1ea610ff-bf3e-4068-9bfd-b6c3f553467e",
							Type: domain.EventTypeRoundFinalizationStarted,
						},
						VtxoTree:       vtxoTree,
						Connectors:     connectorsTree,
						CommitmentTxid: "txid",
						CommitmentTx:   emptyTx,
					},
				},
				handlers: []func(events []domain.Event){
					func(events []domain.Event) {
						round := domain.NewRoundFromEvents(events)
						require.NotNil(t, round)
						require.Len(t, round.Events(), 2)
					},
				},
			},
			{
				topic: domain.RoundTopic,
				id:    "7578231e-428d-45ae-aaa4-e62c77ad5cec",
				events: []domain.Event{
					domain.RoundStarted{
						RoundEvent: domain.RoundEvent{
							Id:   "7578231e-428d-45ae-aaa4-e62c77ad5cec",
							Type: domain.EventTypeRoundStarted,
						},
						Timestamp: 1701190270,
					},
					domain.RoundFinalizationStarted{
						RoundEvent: domain.RoundEvent{
							Id:   "7578231e-428d-45ae-aaa4-e62c77ad5cec",
							Type: domain.EventTypeRoundFinalizationStarted,
						},
						VtxoTree:       vtxoTree,
						Connectors:     connectorsTree,
						CommitmentTxid: "txid",
						CommitmentTx:   emptyTx,
					},
					domain.RoundFinalized{
						RoundEvent: domain.RoundEvent{
							Id:   "7578231e-428d-45ae-aaa4-e62c77ad5cec",
							Type: domain.EventTypeRoundFinalized,
						},
						ForfeitTxs: []domain.ForfeitTx{f1Tx(), f2Tx(), f3Tx(), f4Tx()},
						Timestamp:  1701190300,
					},
				},
				handlers: []func(events []domain.Event){
					func(events []domain.Event) {
						round := domain.NewRoundFromEvents(events)

						require.NotNil(t, round)
						require.Len(t, round.Events(), 3)
						require.False(t, round.IsStarted())
						require.False(t, round.IsFailed())
						require.True(t, round.IsEnded())
						require.NotEmpty(t, round.CommitmentTxid)
					},
				},
			},
			{
				topic: domain.OffchainTxTopic,
				id:    "arkTxid",
				events: []domain.Event{
					domain.OffchainTxAccepted{
						OffchainTxEvent: domain.OffchainTxEvent{
							Id:   "arkTxid",
							Type: domain.EventTypeOffchainTxAccepted,
						},
						Id: "arkTxid",
						CommitmentTxids: map[string]string{
							"0": randomString(32),
							"1": randomString(32),
						},
						FinalArkTx: "fully signed ark tx",
						SignedCheckpointTxs: map[string]string{
							"0": "list of txs signed by the signer",
							"1": "indexed by txid",
						},
					},
				},
				handlers: []func(events []domain.Event){
					func(events []domain.Event) {
						offchainTx := domain.NewOffchainTxFromEvents(events)
						require.NotNil(t, offchainTx)
						require.Len(t, offchainTx.Events(), 1)
					},
				},
			},
			{
				topic: domain.OffchainTxTopic,
				id:    "arkTxid 2",
				events: []domain.Event{
					domain.OffchainTxAccepted{
						OffchainTxEvent: domain.OffchainTxEvent{
							Id:   "arkTxid 2",
							Type: domain.EventTypeOffchainTxAccepted,
						},
						Id: "arkTxid 2",
						CommitmentTxids: map[string]string{
							"0": randomString(32),
							"1": randomString(32),
						},
						FinalArkTx: "fully signed ark tx",
						SignedCheckpointTxs: map[string]string{
							"0": "list of txs signed by the operator",
							"1": "indexed by txid",
						},
					},
					domain.OffchainTxFinalized{
						OffchainTxEvent: domain.OffchainTxEvent{
							Id:   "arkTxid 2",
							Type: domain.EventTypeOffchainTxFinalized,
						},
						FinalCheckpointTxs: map[string]string{
							"0": "list of fully-signed txs",
							"1": "indexed by txid",
						},
					},
				},
				handlers: []func(events []domain.Event){
					func(events []domain.Event) {
						offchainTx := domain.NewOffchainTxFromEvents(events)
						require.NotNil(t, offchainTx)
						require.Len(t, offchainTx.Events(), 2)
					},
				},
			},
		}
		ctx := context.Background()

		for _, f := range fixtures {
			svc.Events().ClearRegisteredHandlers()

			wg := sync.WaitGroup{}
			wg.Add(len(f.handlers))

			for _, handler := range f.handlers {
				svc.Events().RegisterEventsHandler(f.topic, func(events []domain.Event) {
					handler(events)
					wg.Done()
				})
			}

			err := svc.Events().Save(ctx, f.topic, f.id, f.events)
			require.NoError(t, err)

			wg.Wait()
		}
	})
}

func testRoundRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_round_repository", func(t *testing.T) {
		ctx := context.Background()
		now := time.Now()

		roundId := uuid.New().String()

		round, err := svc.Rounds().GetRoundWithId(ctx, roundId)
		require.Error(t, err)
		require.Nil(t, round)

		events := []domain.Event{
			domain.RoundStarted{
				RoundEvent: domain.RoundEvent{
					Id:   roundId,
					Type: domain.EventTypeRoundStarted,
				},
				Timestamp: now.Unix(),
			},
		}
		round = domain.NewRoundFromEvents(events)
		err = svc.Rounds().AddOrUpdateRound(ctx, *round)
		require.NoError(t, err)

		roundById, err := svc.Rounds().GetRoundWithId(ctx, roundId)
		require.NoError(t, err)
		require.NotNil(t, roundById)
		roundsMatch(t, *round, *roundById)

		commitmentTxid := randomString(32)
		newEvents := []domain.Event{
			domain.IntentsRegistered{
				RoundEvent: domain.RoundEvent{
					Id:   roundId,
					Type: domain.EventTypeIntentsRegistered,
				},
				Intents: []domain.Intent{
					{
						Id:      uuid.New().String(),
						Proof:   "proof",
						Message: "message",
						Inputs: []domain.Vtxo{
							{
								Outpoint: domain.Outpoint{
									Txid: randomString(32),
									VOut: 0,
								},
								ExpiresAt: 7980322,
								PubKey:    randomString(32),
								Amount:    300,
							},
						},
						Receivers: []domain.Receiver{{
							PubKey: randomString(32),
							Amount: 300,
						}},
					},
					{
						Id:      uuid.New().String(),
						Proof:   "proof",
						Message: "message",
						Inputs: []domain.Vtxo{

							{
								Outpoint: domain.Outpoint{
									Txid: randomString(32),
									VOut: 0,
								},
								ExpiresAt: 7980322,
								PubKey:    randomString(32),
								Amount:    600,
							},
						},
						Receivers: []domain.Receiver{
							{
								PubKey: randomString(32),
								Amount: 400,
							},
							{
								PubKey: randomString(32),
								Amount: 200,
							},
						},
					},
				},
			},
			domain.RoundFinalizationStarted{
				RoundEvent: domain.RoundEvent{
					Id:   roundId,
					Type: domain.EventTypeRoundFinalizationStarted,
				},
				VtxoTree:       vtxoTree,
				Connectors:     connectorsTree,
				CommitmentTxid: commitmentTxid,
				CommitmentTx:   emptyTx,
			},
		}
		events = append(events, newEvents...)
		updatedRound := domain.NewRoundFromEvents(events)
		for _, intent := range updatedRound.Intents {
			err = svc.Vtxos().AddVtxos(ctx, intent.Inputs)
			require.NoError(t, err)
		}

		err = svc.Rounds().AddOrUpdateRound(ctx, *updatedRound)
		require.NoError(t, err)

		roundById, err = svc.Rounds().GetRoundWithId(ctx, updatedRound.Id)
		require.NoError(t, err)
		require.NotNil(t, roundById)
		roundsMatch(t, *updatedRound, *roundById)

		newEvents = []domain.Event{
			domain.RoundFinalized{
				RoundEvent: domain.RoundEvent{
					Id:   roundId,
					Type: domain.EventTypeRoundFinalized,
				},
				ForfeitTxs:        []domain.ForfeitTx{f1Tx(), f2Tx(), f3Tx(), f4Tx()},
				FinalCommitmentTx: emptyTx,
				Timestamp:         now.Unix(),
			},
		}
		events = append(events, newEvents...)
		finalizedRound := domain.NewRoundFromEvents(events)

		err = svc.Rounds().AddOrUpdateRound(ctx, *finalizedRound)
		require.NoError(t, err)

		roundById, err = svc.Rounds().GetRoundWithId(ctx, roundId)
		require.NoError(t, err)
		require.NotNil(t, roundById)
		roundsMatch(t, *finalizedRound, *roundById)

		resultTree, err := svc.Rounds().GetRoundVtxoTree(ctx, commitmentTxid)
		require.NoError(t, err)
		require.NotNil(t, resultTree)
		require.Equal(t, finalizedRound.VtxoTree, resultTree)

		roundByTxid, err := svc.Rounds().GetRoundWithCommitmentTxid(ctx, commitmentTxid)
		require.NoError(t, err)
		require.NotNil(t, roundByTxid)
		roundsMatch(t, *finalizedRound, *roundByTxid)

		txs, err := svc.Rounds().GetTxsWithTxids(ctx, []string{
			txida,                  // forfeit tx
			vtxoTree[1].Txid,       // tree tx
			connectorsTree[2].Txid, // connector tx
		})
		require.NoError(t, err)
		require.NotNil(t, txs)
		require.Equal(t, 3, len(txs))

		sweepableRounds, err := svc.Rounds().GetSweepableRounds(ctx)
		require.NoError(t, err)
		require.Len(t, sweepableRounds, 1)
		require.Equal(t, commitmentTxid, sweepableRounds[0])

		newEvents = []domain.Event{
			domain.BatchSwept{
				RoundEvent: domain.RoundEvent{
					Id:   roundId,
					Type: domain.EventTypeRoundFinalized,
				},
				Txid:       sweepTxid,
				Tx:         sweepTx,
				FullySwept: true,
			},
		}
		events = append(events, newEvents...)
		sweptRound := domain.NewRoundFromEvents(events)
		err = svc.Rounds().AddOrUpdateRound(ctx, *sweptRound)
		require.NoError(t, err)

		roundById, err = svc.Rounds().GetRoundWithId(ctx, roundId)
		require.NoError(t, err)
		require.NotNil(t, roundById)
		roundsMatch(t, *sweptRound, *roundById)

		roundsIds, err := svc.Rounds().GetRoundIds(ctx, 0, 0, false, true)
		require.NoError(t, err)
		require.Len(t, roundsIds, 1)
		require.Equal(t, roundId, roundsIds[0])

		failedRound := domain.NewRound()
		failedRound.Id = uuid.New().String()
		failedRound.Stage.Code = int(domain.RoundFinalizationStage)
		failedRound.Stage.Ended = false
		failedRound.Stage.Failed = true
		err = svc.Rounds().AddOrUpdateRound(ctx, *failedRound)
		require.NoError(t, err)

		onlyFailedIds, err := svc.Rounds().GetRoundIds(ctx, 0, 0, true, false)
		require.NoError(t, err)
		require.Len(t, onlyFailedIds, 1)
		require.Equal(t, failedRound.Id, onlyFailedIds[0])

		onlyCompletedIds, err := svc.Rounds().GetRoundIds(ctx, 0, 0, false, true)
		require.NoError(t, err)
		require.Len(t, onlyCompletedIds, 1)
		require.Equal(t, roundId, onlyCompletedIds[0])

		allRoundsIds, err := svc.Rounds().GetRoundIds(ctx, 0, 0, true, true)
		require.NoError(t, err)
		require.Len(t, allRoundsIds, 2)
		require.Contains(t, allRoundsIds, roundId)
		require.Contains(t, allRoundsIds, failedRound.Id)
		roundWithoutVtxoTree := domain.NewRound()
		roundWithoutVtxoTree.Stage.Code = int(domain.RoundFinalizationStage)
		roundWithoutVtxoTree.CommitmentTxid = randomString(32)
		roundWithoutVtxoTree.Stage.Ended = true
		err = svc.Rounds().AddOrUpdateRound(ctx, *roundWithoutVtxoTree)
		require.NoError(t, err)

		sweepableRounds, err = svc.Rounds().GetSweepableRounds(ctx)
		require.NoError(t, err)
		// check it is empty because:
		// - first round has been swept
		// - second round has no vtxo tree
		require.Empty(t, sweepableRounds)
	})
}

func testVtxoRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_vtxo_repository", func(t *testing.T) {
		ctx := context.Background()

		commitmentTxid := randomString(32)

		userVtxos := []domain.Vtxo{
			{
				Outpoint: domain.Outpoint{
					Txid: randomString(32),
					VOut: 0,
				},
				PubKey:             pubkey,
				Amount:             1000,
				RootCommitmentTxid: commitmentTxid,
				CommitmentTxids:    []string{commitmentTxid, "cmt1", "cmt2"},
				Preconfirmed:       true,
			},
			{
				Outpoint: domain.Outpoint{
					Txid: randomString(32),
					VOut: 1,
				},
				PubKey:             pubkey,
				Amount:             2000,
				RootCommitmentTxid: commitmentTxid,
				CommitmentTxids:    []string{commitmentTxid},
			},
		}
		newVtxos := append(userVtxos, domain.Vtxo{
			Outpoint: domain.Outpoint{
				Txid: randomString(32),
				VOut: 1,
			},
			PubKey:             pubkey2,
			Amount:             2000,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid},
		})
		arkTxid := randomString(32)

		commitmentTxid1 := randomString(32)

		vtxoKeys := make([]domain.Outpoint, 0, len(userVtxos))
		spentVtxoMap := make(map[domain.Outpoint]string)
		for _, v := range userVtxos {
			vtxoKeys = append(vtxoKeys, v.Outpoint)
			spentVtxoMap[v.Outpoint] = randomString(32)
		}

		vtxos, err := svc.Vtxos().GetVtxos(ctx, vtxoKeys)
		require.Nil(t, err)
		require.Empty(t, vtxos)
		spendableVtxos, spentVtxos, err := svc.Vtxos().GetAllNonUnrolledVtxos(ctx, pubkey)
		require.NoError(t, err)
		require.Empty(t, spendableVtxos)
		require.Empty(t, spentVtxos)

		spendableVtxos, spentVtxos, err = svc.Vtxos().GetAllNonUnrolledVtxos(ctx, "")
		require.NoError(t, err)

		numberOfVtxos := len(spendableVtxos) + len(spentVtxos)

		err = svc.Vtxos().AddVtxos(ctx, newVtxos)
		require.NoError(t, err)

		vtxos, err = svc.Vtxos().GetAllVtxos(ctx)
		require.NoError(t, err)
		require.Equal(t, 5, len(vtxos))

		vtxos, err = svc.Vtxos().GetVtxos(ctx, vtxoKeys)
		require.NoError(t, err)
		checkVtxos(t, userVtxos, vtxos)

		spendableVtxos, spentVtxos, err = svc.Vtxos().GetAllNonUnrolledVtxos(ctx, pubkey)
		require.NoError(t, err)

		sortedVtxos := sortVtxos(userVtxos)
		sort.Sort(sortedVtxos)

		sortedSpendableVtxos := sortVtxos(spendableVtxos)
		sort.Sort(sortedSpendableVtxos)

		checkVtxos(t, sortedSpendableVtxos, sortedVtxos)
		require.Empty(t, spentVtxos)

		spendableVtxos, spentVtxos, err = svc.Vtxos().GetAllNonUnrolledVtxos(ctx, "")
		require.NoError(t, err)
		require.Len(t, append(spendableVtxos, spentVtxos...), numberOfVtxos+len(newVtxos))

		err = svc.Vtxos().SpendVtxos(ctx, spentVtxoMap, arkTxid)
		require.NoError(t, err)

		spentVtxos, err = svc.Vtxos().GetVtxos(ctx, vtxoKeys[:1])
		require.NoError(t, err)
		require.Len(t, spentVtxos, len(vtxoKeys[:1]))
		for _, v := range spentVtxos {
			require.True(t, v.Spent)
			require.Equal(t, spentVtxoMap[v.Outpoint], v.SpentBy)
			require.Equal(t, arkTxid, v.ArkTxid)
		}

		spendableVtxos, spentVtxos, err = svc.Vtxos().GetAllNonUnrolledVtxos(ctx, pubkey)
		require.NoError(t, err)
		checkVtxos(t, vtxos[1:], spendableVtxos)
		require.Len(t, spentVtxos, len(userVtxos))

		spentVtxoMap = map[domain.Outpoint]string{
			newVtxos[len(newVtxos)-1].Outpoint: randomString(32),
		}
		vtxoKeys = []domain.Outpoint{newVtxos[len(newVtxos)-1].Outpoint}
		err = svc.Vtxos().SettleVtxos(ctx, spentVtxoMap, commitmentTxid)
		require.NoError(t, err)

		spentVtxos, err = svc.Vtxos().GetVtxos(ctx, vtxoKeys)
		require.NoError(t, err)
		require.Len(t, spentVtxos, len(vtxoKeys))
		for _, v := range spentVtxos {
			require.True(t, v.Spent)
			require.Equal(t, spentVtxoMap[v.Outpoint], v.SpentBy)
			require.Equal(t, commitmentTxid, v.SettledBy)
		}

		// Test GetAllChildrenVtxos recursive query
		// Create a chain of vtxos: vtxo1 -> vtxo2 -> vtxo3 -> vtxo4 (end with null ark_txid)
		vtxo1 := domain.Vtxo{
			Outpoint: domain.Outpoint{
				Txid: randomString(32),
				VOut: 0,
			},
			PubKey:             pubkey,
			Amount:             1000,
			RootCommitmentTxid: commitmentTxid1,
			CommitmentTxids:    []string{commitmentTxid1},
			ArkTxid:            randomString(32), // Points to vtxo2
		}

		vtxo2 := domain.Vtxo{
			Outpoint: domain.Outpoint{
				Txid: vtxo1.ArkTxid, // Same as vtxo1's ark_txid
				VOut: 0,
			},
			PubKey:             pubkey,
			Amount:             2000,
			RootCommitmentTxid: commitmentTxid1,
			CommitmentTxids:    []string{commitmentTxid1},
			ArkTxid:            randomString(32), // Points to vtxo3
		}

		vtxo3 := domain.Vtxo{
			Outpoint: domain.Outpoint{
				Txid: vtxo2.ArkTxid, // Same as vtxo2's ark_txid
				VOut: 0,
			},
			PubKey:             pubkey,
			Amount:             3000,
			RootCommitmentTxid: commitmentTxid1,
			CommitmentTxids:    []string{commitmentTxid1},
			ArkTxid:            randomString(32), // Points to vtxo4
		}

		vtxo4 := domain.Vtxo{
			Outpoint: domain.Outpoint{
				Txid: vtxo3.ArkTxid, // Same as vtxo3's ark_txid
				VOut: 0,
			},
			PubKey:             pubkey,
			Amount:             4000,
			RootCommitmentTxid: commitmentTxid1,
			CommitmentTxids:    []string{commitmentTxid1},
			ArkTxid:            "", // End of chain - null ark_txid
		}

		// Add all vtxos to the database
		chainVtxos := []domain.Vtxo{vtxo1, vtxo2, vtxo3, vtxo4}
		err = svc.Vtxos().AddVtxos(ctx, chainVtxos)
		require.NoError(t, err)

		children, err := svc.Vtxos().GetUnsweptVtxosByCommitmentTxid(ctx, vtxo1.RootCommitmentTxid)
		require.NoError(t, err)
		require.Len(t, children, 4)

		expectedOutpoints := []domain.Outpoint{
			vtxo1.Outpoint,
			vtxo2.Outpoint,
			vtxo3.Outpoint,
			vtxo4.Outpoint,
		}

		sort.Slice(children, func(i, j int) bool {
			return children[i].Txid < children[j].Txid
		})
		sort.Slice(expectedOutpoints, func(i, j int) bool {
			return expectedOutpoints[i].Txid < expectedOutpoints[j].Txid
		})

		require.Equal(t, expectedOutpoints, children)

		// Test with non-existent txid
		children, err = svc.Vtxos().GetUnsweptVtxosByCommitmentTxid(ctx, randomString(32))
		require.NoError(t, err)
		require.Empty(t, children)

		// Test GetVtxoTapKeys
		tapKeysTestVtxos := []domain.Vtxo{
			{
				Outpoint: domain.Outpoint{
					Txid: randomString(32),
					VOut: 0,
				},
				PubKey:             "tapkey1",
				Amount:             5000,
				RootCommitmentTxid: commitmentTxid,
				CommitmentTxids:    []string{commitmentTxid},
				Unrolled:           false,
				Swept:              false,
			},
			{
				Outpoint: domain.Outpoint{
					Txid: randomString(32),
					VOut: 1,
				},
				PubKey:             "tapkey2",
				Amount:             2000,
				RootCommitmentTxid: commitmentTxid,
				CommitmentTxids:    []string{commitmentTxid},
				Unrolled:           false,
				Swept:              false,
			},
			{
				Outpoint: domain.Outpoint{
					Txid: randomString(32),
					VOut: 2,
				},
				PubKey:             "tapkey3",
				Amount:             10000,
				RootCommitmentTxid: commitmentTxid,
				CommitmentTxids:    []string{commitmentTxid},
				Unrolled:           false,
				Swept:              false,
			},
		}
		err = svc.Vtxos().AddVtxos(ctx, tapKeysTestVtxos)
		require.NoError(t, err)

		tapKeysOutpoints := []domain.Outpoint{
			tapKeysTestVtxos[0].Outpoint,
			tapKeysTestVtxos[1].Outpoint,
			tapKeysTestVtxos[2].Outpoint,
		}

		tapKeys, err := svc.Vtxos().GetVtxoTapKeys(ctx, tapKeysOutpoints, 3000)
		require.NoError(t, err)
		require.Len(t, tapKeys, 2)
		require.Contains(t, tapKeys, "tapkey1")
		require.Contains(t, tapKeys, "tapkey3")
		require.NotContains(t, tapKeys, "tapkey2")

		tapKeys, err = svc.Vtxos().GetVtxoTapKeys(ctx, tapKeysOutpoints, 0)
		require.NoError(t, err)
		require.Len(t, tapKeys, 3)
		require.Contains(t, tapKeys, "tapkey1")
		require.Contains(t, tapKeys, "tapkey2")
		require.Contains(t, tapKeys, "tapkey3")

		tapKeys, err = svc.Vtxos().GetVtxoTapKeys(ctx, tapKeysOutpoints, 20000)
		require.NoError(t, err)
		require.Empty(t, tapKeys)

		tapKeys, err = svc.Vtxos().GetVtxoTapKeys(ctx, []domain.Outpoint{}, 0)
		require.NoError(t, err)
		require.Empty(t, tapKeys)

		nonExistentOutpoint := domain.Outpoint{
			Txid: randomString(32),
			VOut: 999,
		}
		tapKeys, err = svc.Vtxos().GetVtxoTapKeys(ctx, []domain.Outpoint{nonExistentOutpoint}, 0)
		require.NoError(t, err)
		require.Empty(t, tapKeys)

		// Test GetAllSweepableVtxoTapKeys
		sweepableTestVtxos := []domain.Vtxo{
			{
				Outpoint: domain.Outpoint{
					Txid: randomString(32),
					VOut: 0,
				},
				PubKey:             "sweepable1",
				Amount:             1000,
				RootCommitmentTxid: commitmentTxid,
				CommitmentTxids:    []string{commitmentTxid},
				Unrolled:           false,
				Swept:              false,
			},
			{
				Outpoint: domain.Outpoint{
					Txid: randomString(32),
					VOut: 1,
				},
				PubKey:             "sweepable2",
				Amount:             2000,
				RootCommitmentTxid: commitmentTxid,
				CommitmentTxids:    []string{commitmentTxid},
				Unrolled:           false,
				Swept:              false,
			},
			{
				Outpoint: domain.Outpoint{
					Txid: randomString(32),
					VOut: 2,
				},
				PubKey:             "notsweepable1",
				Amount:             3000,
				RootCommitmentTxid: commitmentTxid,
				CommitmentTxids:    []string{commitmentTxid},
				Unrolled:           true,
				Swept:              false,
			},
			{
				Outpoint: domain.Outpoint{
					Txid: randomString(32),
					VOut: 3,
				},
				PubKey:             "notsweepable2",
				Amount:             4000,
				RootCommitmentTxid: commitmentTxid,
				CommitmentTxids:    []string{commitmentTxid},
				Unrolled:           false,
				Swept:              true,
			},
		}
		err = svc.Vtxos().AddVtxos(ctx, sweepableTestVtxos)
		require.NoError(t, err)

		allSweepableTapKeys, err := svc.Vtxos().GetAllSweepableVtxoTapKeys(ctx)
		require.NoError(t, err)
		require.Contains(t, allSweepableTapKeys, "sweepable1")
		require.Contains(t, allSweepableTapKeys, "sweepable2")
		require.NotContains(t, allSweepableTapKeys, "notsweepable1")
		require.NotContains(t, allSweepableTapKeys, "notsweepable2")

		pubkeyCount := make(map[string]int)
		for _, key := range allSweepableTapKeys {
			pubkeyCount[key]++
		}
		for key, count := range pubkeyCount {
			require.Equal(t, 1, count, "pubkey %s should appear only once", key)
		}
	})
}

func testScheduledSessionRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_scheduled_session_repository", func(t *testing.T) {
		ctx := context.Background()
		repo := svc.ScheduledSession()

		scheduledSession, err := repo.Get(ctx)
		require.NoError(t, err)
		require.Nil(t, scheduledSession)

		now := time.Now().Truncate(time.Second)
		expected := domain.ScheduledSession{
			StartTime: now,
			Period:    time.Duration(3) * time.Hour,
			Duration:  time.Duration(20) * time.Second,
			UpdatedAt: now,
		}

		err = repo.Upsert(ctx, expected)
		require.NoError(t, err)

		got, err := repo.Get(ctx)
		require.NoError(t, err)
		require.NotNil(t, got)
		assertScheduledSessionEqual(t, expected, *got)

		expected.Period = time.Duration(4) * time.Hour
		expected.Duration = time.Duration(40) * time.Second
		expected.UpdatedAt = now.Add(100 * time.Second)

		err = repo.Upsert(ctx, expected)
		require.NoError(t, err)

		got, err = repo.Get(ctx)
		require.NoError(t, err)
		require.NotNil(t, got)
		assertScheduledSessionEqual(t, expected, *got)

		err = repo.Clear(ctx)
		require.NoError(t, err)

		scheduledSession, err = repo.Get(ctx)
		require.NoError(t, err)
		require.Nil(t, scheduledSession)

		// No error if trying to clear already cleared scheduled session
		err = repo.Clear(ctx)
		require.NoError(t, err)
	})
}

func testOffchainTxRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_offchain_tx_repository", func(t *testing.T) {
		ctx := context.Background()
		repo := svc.OffchainTxs()

		offchainTx, err := repo.GetOffchainTx(ctx, arkTxid)
		require.Nil(t, offchainTx)
		require.Error(t, err)

		checkpointTxid1 := "0000000000000000000000000000000000000000000000000000000000000001"
		signedCheckpointPtx1 := "cHNldP8BAgQCAAAAAQQBAAEFAQABBgEDAfsEAgAAAAA=signed"
		checkpointTxid2 := "0000000000000000000000000000000000000000000000000000000000000002"
		signedCheckpointPtx2 := "cHNldP8BAgQCAAAAAQQBAAEFAQABBgEDAfsEAgAAAAB=signed"
		rootCommitmentTxid := "0000000000000000000000000000000000000000000000000000000000000003"
		commitmentTxid := "0000000000000000000000000000000000000000000000000000000000000004"
		events := []domain.Event{
			domain.OffchainTxRequested{
				OffchainTxEvent: domain.OffchainTxEvent{
					Id:   arkTxid,
					Type: domain.EventTypeOffchainTxRequested,
				},
				ArkTx:                 "",
				UnsignedCheckpointTxs: nil,
				StartingTimestamp:     now.Unix(),
			},
			domain.OffchainTxAccepted{
				OffchainTxEvent: domain.OffchainTxEvent{
					Id:   arkTxid,
					Type: domain.EventTypeOffchainTxAccepted,
				},
				Id: arkTxid,
				CommitmentTxids: map[string]string{
					checkpointTxid1: rootCommitmentTxid,
					checkpointTxid2: commitmentTxid,
				},
				FinalArkTx: "",
				SignedCheckpointTxs: map[string]string{
					checkpointTxid1: signedCheckpointPtx1,
					checkpointTxid2: signedCheckpointPtx2,
				},
				RootCommitmentTxid: rootCommitmentTxid,
			},
		}
		offchainTx = domain.NewOffchainTxFromEvents(events)
		err = repo.AddOrUpdateOffchainTx(ctx, offchainTx)
		require.NoError(t, err)

		gotOffchainTx, err := repo.GetOffchainTx(ctx, arkTxid)
		require.NoError(t, err)
		require.NotNil(t, offchainTx)
		require.True(t, gotOffchainTx.IsAccepted())
		require.Equal(t, rootCommitmentTxid, gotOffchainTx.RootCommitmentTxId)
		require.Condition(t, offchainTxMatch(*offchainTx, *gotOffchainTx))

		newEvents := []domain.Event{
			domain.OffchainTxFinalized{
				OffchainTxEvent: domain.OffchainTxEvent{
					Id:   arkTxid,
					Type: domain.EventTypeOffchainTxFinalized,
				},
				FinalCheckpointTxs: nil,
				Timestamp:          endTimestamp,
			},
		}
		events = append(events, newEvents...)
		offchainTx = domain.NewOffchainTxFromEvents(events)
		err = repo.AddOrUpdateOffchainTx(ctx, offchainTx)
		require.NoError(t, err)

		gotOffchainTx, err = repo.GetOffchainTx(ctx, arkTxid)
		require.NoError(t, err)
		require.NotNil(t, offchainTx)
		require.True(t, gotOffchainTx.IsFinalized())
		require.Condition(t, offchainTxMatch(*offchainTx, *gotOffchainTx))
	})
}

func testConvictionRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_conviction_repository", func(t *testing.T) {
		ctx := context.Background()
		repo := svc.Convictions()

		conviction, err := repo.Get(ctx, "non-existent-id")
		require.Error(t, err)
		require.Nil(t, conviction)

		scriptConviction, err := repo.GetActiveScriptConvictions(ctx, "non-existent-script")
		require.NoError(t, err)
		require.Empty(t, scriptConviction)

		convictions, err := repo.GetAll(ctx, time.Now().Add(-time.Hour), time.Now())
		require.NoError(t, err)
		require.Empty(t, convictions)

		roundConvictions, err := repo.GetByRoundID(ctx, "non-existent-round")
		require.NoError(t, err)
		require.Empty(t, roundConvictions)

		roundID1 := uuid.New().String()
		roundID2 := uuid.New().String()
		script1 := randomString(32)
		script2 := randomString(32)
		banDuration := time.Duration(1) * time.Hour

		crime1 := domain.Crime{
			Type:    domain.CrimeTypeMusig2NonceSubmission,
			RoundID: roundID1,
			Reason:  "Test crime 1",
		}
		crime2 := domain.Crime{
			Type:    domain.CrimeTypeMusig2SignatureSubmission,
			RoundID: roundID2,
			Reason:  "Test crime 2",
		}

		conviction1 := domain.NewScriptConviction(script1, crime1, &banDuration)
		conviction2 := domain.NewScriptConviction(script2, crime2, nil) // Permanent ban

		err = repo.Add(ctx, conviction1, conviction2)
		require.NoError(t, err)

		retrievedConviction1, err := repo.Get(ctx, conviction1.GetID())
		require.NoError(t, err)
		require.NotNil(t, retrievedConviction1)
		assertConvictionEqual(t, conviction1, retrievedConviction1)

		retrievedConviction2, err := repo.Get(ctx, conviction2.GetID())
		require.NoError(t, err)
		require.NotNil(t, retrievedConviction2)
		assertConvictionEqual(t, conviction2, retrievedConviction2)

		activeConviction1, err := repo.GetActiveScriptConvictions(ctx, script1)
		require.NoError(t, err)
		require.NotNil(t, activeConviction1)
		require.Len(t, activeConviction1, 1)
		require.Equal(t, script1, activeConviction1[0].Script)
		require.False(t, activeConviction1[0].IsPardoned())

		activeConviction2, err := repo.GetActiveScriptConvictions(ctx, script2)
		require.NoError(t, err)
		require.NotNil(t, activeConviction2)
		require.Len(t, activeConviction2, 1)
		require.Equal(t, script2, activeConviction2[0].Script)
		require.False(t, activeConviction2[0].IsPardoned())

		round1Convictions, err := repo.GetByRoundID(ctx, roundID1)
		require.NoError(t, err)
		require.Len(t, round1Convictions, 1)
		assertConvictionEqual(t, conviction1, round1Convictions[0])

		round2Convictions, err := repo.GetByRoundID(ctx, roundID2)
		require.NoError(t, err)
		require.Len(t, round2Convictions, 1)
		assertConvictionEqual(t, conviction2, round2Convictions[0])

		allConvictions, err := repo.GetAll(
			ctx,
			time.Now().Add(-time.Hour),
			time.Now().Add(time.Hour),
		)
		require.NoError(t, err)
		require.Len(t, allConvictions, 2)

		err = repo.Pardon(ctx, conviction1.GetID())
		require.NoError(t, err)

		pardonedConviction, err := repo.Get(ctx, conviction1.GetID())
		require.NoError(t, err)
		require.NotNil(t, pardonedConviction)
		require.True(t, pardonedConviction.IsPardoned())

		activeConvictionAfterPardon, err := repo.GetActiveScriptConvictions(ctx, script1)
		require.NoError(t, err)
		require.Empty(t, activeConvictionAfterPardon)

		shortDuration := time.Duration(1) * time.Millisecond
		crime3 := domain.Crime{
			Type:    domain.CrimeTypeMusig2InvalidSignature,
			RoundID: roundID1,
			Reason:  "Test expired crime",
		}
		expiredConviction := domain.NewScriptConviction(script1, crime3, &shortDuration)
		err = repo.Add(ctx, expiredConviction)
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		_, err = repo.GetActiveScriptConvictions(ctx, script1)
		require.NoError(t, err)
	})
}

func assertScheduledSessionEqual(t *testing.T, expected, actual domain.ScheduledSession) {
	assert.True(t, expected.StartTime.Equal(actual.StartTime), "StartTime not equal")
	assert.Equal(t, expected.Period, actual.Period, "Period not equal")
	assert.Equal(t, expected.Duration, actual.Duration, "Duration not equal")
	assert.True(t, expected.UpdatedAt.Equal(actual.UpdatedAt), "UpdatedAt not equal")
	assert.True(t, expected.EndTime.Equal(actual.EndTime), "EndTime not equal")
}

func assertConvictionEqual(t *testing.T, expected, actual domain.Conviction) {
	require.Equal(t, expected.GetID(), actual.GetID())
	require.Equal(t, expected.GetType(), actual.GetType())
	require.Equal(t, expected.GetCrime(), actual.GetCrime())
	require.Equal(t, expected.IsPardoned(), actual.IsPardoned())

	require.WithinDuration(t, expected.GetCreatedAt(), actual.GetCreatedAt(), time.Second)

	if expected.GetExpiresAt() == nil {
		require.Nil(t, actual.GetExpiresAt())
	} else {
		require.NotNil(t, actual.GetExpiresAt())
		require.WithinDuration(t, *expected.GetExpiresAt(), *actual.GetExpiresAt(), time.Second)
	}

	if expectedConv, ok := expected.(domain.ScriptConviction); ok {
		if actualConv, ok := actual.(domain.ScriptConviction); ok {
			require.Equal(t, expectedConv.Script, actualConv.Script)
		}
	}
}

func roundsMatch(t *testing.T, expected, got domain.Round) {
	require.Equal(t, expected.Id, got.Id)
	require.Equal(t, expected.StartingTimestamp, got.StartingTimestamp)
	require.Equal(t, expected.EndingTimestamp, got.EndingTimestamp)
	require.Equal(t, expected.Stage, got.Stage)
	require.Equal(t, expected.CommitmentTxid, got.CommitmentTxid)
	require.Equal(t, expected.CommitmentTx, got.CommitmentTx)
	require.Exactly(t, expected.VtxoTree, got.VtxoTree)

	for k, v := range expected.Intents {
		gotValue, ok := got.Intents[k]
		require.True(t, ok)

		expectedVtxos := sortVtxos(v.Inputs)
		gotVtxos := sortVtxos(gotValue.Inputs)

		sort.Sort(expectedVtxos)
		sort.Sort(gotVtxos)

		expectedReceivers := sortReceivers(v.Receivers)
		gotReceivers := sortReceivers(gotValue.Receivers)

		sort.Sort(expectedReceivers)
		sort.Sort(gotReceivers)

		require.Exactly(t, expectedReceivers, gotReceivers)
		require.Exactly(t, expectedVtxos, gotVtxos)
		require.Equal(t, v.Proof, gotValue.Proof)
		require.Equal(t, v.Message, gotValue.Message)
	}

	if len(expected.ForfeitTxs) > 0 {
		sort.SliceStable(expected.ForfeitTxs, func(i, j int) bool {
			return expected.ForfeitTxs[i].Txid < expected.ForfeitTxs[j].Txid
		})
		sort.SliceStable(got.ForfeitTxs, func(i, j int) bool {
			return got.ForfeitTxs[i].Txid < got.ForfeitTxs[j].Txid
		})

		require.Exactly(t, expected.ForfeitTxs, got.ForfeitTxs)
	}

	if len(expected.Connectors) > 0 {
		require.Exactly(t, expected.Connectors, got.Connectors)
	}

	if len(expected.VtxoTree) > 0 {
		require.Exactly(t, expected.VtxoTree, got.VtxoTree)
	}

	require.Equal(t, expected.Swept, got.Swept)
	for k, v := range expected.SweepTxs {
		gotValue, ok := got.SweepTxs[k]
		require.True(t, ok)
		require.Equal(t, v, gotValue)
	}
}

func offchainTxMatch(expected, got domain.OffchainTx) assert.Comparison {
	return func() bool {
		if expected.Stage != got.Stage {
			return false
		}
		if expected.StartingTimestamp != got.StartingTimestamp {
			return false
		}
		if expected.EndingTimestamp != got.EndingTimestamp {
			return false
		}
		if expected.ArkTxid != got.ArkTxid {
			return false
		}
		if expected.ArkTx != got.ArkTx {
			return false
		}
		for k, v := range expected.CheckpointTxs {
			gotValue, ok := got.CheckpointTxs[k]
			if !ok {
				return false
			}
			if v != gotValue {
				return false
			}
		}
		if len(expected.CommitmentTxids) > 0 {
			if !reflect.DeepEqual(expected.CommitmentTxids, got.CommitmentTxids) {
				return false
			}
		}
		if expected.ExpiryTimestamp != got.ExpiryTimestamp {
			return false
		}
		if expected.FailReason != got.FailReason {
			return false
		}
		return true
	}
}

func randomString(len int) string {
	buf := make([]byte, len)
	// nolint
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

func randomTx() string {
	hash, _ := chainhash.NewHashFromStr(randomString(32))

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

	b64, _ := ptx.B64Encode()
	return b64
}

type sortVtxos []domain.Vtxo

func (a sortVtxos) String() string {
	buf, _ := json.Marshal(a)
	return string(buf)
}

func (a sortVtxos) Len() int           { return len(a) }
func (a sortVtxos) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a sortVtxos) Less(i, j int) bool { return a[i].Txid < a[j].Txid }

type sortReceivers []domain.Receiver

func (a sortReceivers) Len() int           { return len(a) }
func (a sortReceivers) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a sortReceivers) Less(i, j int) bool { return a[i].Amount < a[j].Amount }

func checkVtxos(t *testing.T, expectedVtxos sortVtxos, gotVtxos sortVtxos) {
	for i, v := range gotVtxos {
		expected := expectedVtxos[i]
		require.Exactly(t, expected.Outpoint, v.Outpoint)
		require.Exactly(t, expected.Amount, v.Amount)
		require.Exactly(t, expected.CreatedAt, v.CreatedAt)
		require.Exactly(t, expected.ExpiresAt, v.ExpiresAt)
		require.Exactly(t, expected.PubKey, v.PubKey)
		require.Exactly(t, expected.Preconfirmed, v.Preconfirmed)
		require.Exactly(t, expected.Unrolled, v.Unrolled)
		require.Exactly(t, expected.RootCommitmentTxid, v.RootCommitmentTxid)
		require.Exactly(t, expected.Spent, v.Spent)
		require.Exactly(t, expected.SpentBy, v.SpentBy)
		require.Exactly(t, expected.Swept, v.Swept)
		require.ElementsMatch(t, expected.CommitmentTxids, v.CommitmentTxids)
	}
}
