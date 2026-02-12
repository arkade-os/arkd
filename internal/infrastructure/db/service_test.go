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
	txidc     = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
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
				EventStoreConfig: []interface{}{pgEventDns, false},
				DataStoreConfig:  []interface{}{pgDns, false},
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
			testMarkerBasicOperations(t, svc)
			testMarkerSweep(t, svc)
			testVtxoMarkerAssociation(t, svc)
			testSweepVtxosByMarker(t, svc)
			testMarkerDepthRangeQueries(t, svc)
			testMarkerChainTraversal(t, svc)
			testGetVtxoChainWithMarkerOptimization(t, svc)
			testOffchainTxRepository(t, svc)
			testScheduledSessionRepository(t, svc)
			testConvictionRepository(t, svc)
			testFeeRepository(t, svc)
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
						Txid:    txida,
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
						Txid:    txidb,
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

		// get intents by txid
		intent, err := svc.Rounds().GetIntentByTxid(ctx, txida)
		require.NoError(t, err)
		require.Equal(t, "proof", intent.Proof)
		require.Equal(t, "message", intent.Message)
		require.NotEqual(t, "", intent.Id)
		require.NotEqual(t, "", intent.Txid)

		intent, err = svc.Rounds().GetIntentByTxid(ctx, txidb)
		require.NoError(t, err)
		require.Equal(t, "proof", intent.Proof)
		require.Equal(t, "message", intent.Message)
		require.NotEqual(t, "", intent.Id)
		require.NotEqual(t, "", intent.Txid)

		// non existing intent by txid
		intent, err = svc.Rounds().GetIntentByTxid(ctx, txidc)
		require.NoError(t, err)
		require.Nil(t, intent)

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
				Depth:              2, // chained vtxo at depth 2
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
				Depth:              0, // batch vtxo at depth 0
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
			Depth:              1, // chained vtxo at depth 1
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
		require.Equal(t, numberOfVtxos+len(newVtxos), len(vtxos))

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

		children, err := svc.Vtxos().
			GetSweepableVtxosByCommitmentTxid(ctx, vtxo1.RootCommitmentTxid)
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
		children, err = svc.Vtxos().GetSweepableVtxosByCommitmentTxid(ctx, randomString(32))
		require.NoError(t, err)
		require.Empty(t, children)

		// Test recursive query starting from vtxo1
		children, err = svc.Vtxos().GetAllChildrenVtxos(ctx, vtxo1.Txid)
		require.NoError(t, err)
		require.Len(t, children, 4) // Should return all 4 vtxos in the chain

		sort.Slice(children, func(i, j int) bool {
			return children[i].Txid < children[j].Txid
		})

		require.Equal(t, expectedOutpoints, children)

		// Test starting from middle of chain (vtxo2)
		children, err = svc.Vtxos().GetAllChildrenVtxos(ctx, vtxo2.Txid)
		require.NoError(t, err)
		require.Len(t, children, 3) // Should return vtxo2, vtxo3, vtxo4

		// Test starting from end of chain (vtxo4)
		children, err = svc.Vtxos().GetAllChildrenVtxos(ctx, vtxo4.Txid)
		require.NoError(t, err)
		require.Len(t, children, 1) // Should return only vtxo4

		// Test with non-existent txid
		children, err = svc.Vtxos().GetAllChildrenVtxos(ctx, randomString(32))
		require.NoError(t, err)
		require.Empty(t, children)

		otherCommitmentTxid := randomString(32)

		// Test GetVtxoPubKeysByCommitmentTxid
		tapKeysTestVtxos := []domain.Vtxo{
			{
				Outpoint: domain.Outpoint{
					Txid: randomString(32),
					VOut: 0,
				},
				PubKey:             "tapkey1",
				Amount:             5000,
				RootCommitmentTxid: otherCommitmentTxid,
				CommitmentTxids:    []string{otherCommitmentTxid},
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
				RootCommitmentTxid: otherCommitmentTxid,
				CommitmentTxids:    []string{otherCommitmentTxid},
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
				RootCommitmentTxid: otherCommitmentTxid,
				CommitmentTxids:    []string{otherCommitmentTxid},
				Unrolled:           false,
				Swept:              false,
			},
		}
		err = svc.Vtxos().AddVtxos(ctx, tapKeysTestVtxos)
		require.NoError(t, err)

		tapKeys, err := svc.Vtxos().GetVtxoPubKeysByCommitmentTxid(ctx, otherCommitmentTxid, 3000)
		require.NoError(t, err)
		require.Len(t, tapKeys, 2)
		require.Contains(t, tapKeys, "tapkey1")
		require.Contains(t, tapKeys, "tapkey3")
		require.NotContains(t, tapKeys, "tapkey2")

		tapKeys, err = svc.Vtxos().GetVtxoPubKeysByCommitmentTxid(ctx, otherCommitmentTxid, 0)
		require.NoError(t, err)
		require.Len(t, tapKeys, 3)
		require.Contains(t, tapKeys, "tapkey1")
		require.Contains(t, tapKeys, "tapkey2")
		require.Contains(t, tapKeys, "tapkey3")

		tapKeys, err = svc.Vtxos().GetVtxoPubKeysByCommitmentTxid(ctx, otherCommitmentTxid, 20000)
		require.NoError(t, err)
		require.Empty(t, tapKeys)

		tapKeys, err = svc.Vtxos().GetVtxoPubKeysByCommitmentTxid(ctx, "", 0)
		require.NoError(t, err)
		require.Empty(t, tapKeys)

		nonExistentCommitmentTxid := randomString(32)
		tapKeys, err = svc.Vtxos().GetVtxoPubKeysByCommitmentTxid(ctx, nonExistentCommitmentTxid, 0)
		require.NoError(t, err)
		require.Empty(t, tapKeys)

		t.Run("test_get_pending_spent_vtxos", func(t *testing.T) {
			ctx := t.Context()

			vtxos := []domain.Vtxo{
				{
					Outpoint: domain.Outpoint{
						Txid: randomString(32),
						VOut: 2,
					},
					PubKey:  "aaaa",
					Amount:  10000,
					Spent:   true,
					ArkTxid: "test",
					SpentBy: "checkpoint_test",
				},
				{
					Outpoint: domain.Outpoint{
						Txid: randomString(32),
						VOut: 2,
					},
					PubKey:  "aaaa",
					Amount:  10000,
					Spent:   true,
					ArkTxid: "test",
					SpentBy: "checkpoint_test",
				},
				{
					Outpoint: domain.Outpoint{
						Txid: randomString(32),
						VOut: 2,
					},
					PubKey:  "bbbb",
					Amount:  10000,
					Spent:   true,
					ArkTxid: "test2",
					SpentBy: "checkpoint_test",
				},
			}
			outpoints := make([]domain.Outpoint, 0, len(vtxos))
			for _, vtxo := range vtxos {
				outpoints = append(outpoints, vtxo.Outpoint)
			}

			pendingSpentVtxos, err := svc.Vtxos().GetPendingSpentVtxosWithOutpoints(ctx, outpoints)
			require.NoError(t, err)
			require.Empty(t, pendingSpentVtxos)

			pendingSpentVtxosByPubkey, err := svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"aaaa"}, 0, 0,
			)
			require.NoError(t, err)
			require.Empty(t, pendingSpentVtxosByPubkey)

			err = svc.Vtxos().AddVtxos(ctx, vtxos)
			require.NoError(t, err)

			pendingSpentVtxos, err = svc.Vtxos().GetPendingSpentVtxosWithOutpoints(ctx, outpoints)
			require.NoError(t, err)
			require.Len(t, pendingSpentVtxos, 3)

			pendingSpentVtxosByPubkey, err = svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"aaaa"}, 0, 0,
			)
			require.NoError(t, err)
			require.Len(t, pendingSpentVtxosByPubkey, 2)

			pendingSpentVtxosByPubkey, err = svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"bbbb"}, 0, 0,
			)
			require.NoError(t, err)
			require.Len(t, pendingSpentVtxosByPubkey, 1)

			// Simulate finalization of a send by adding a change vtxo to the "user" set
			spendingVtxos := []domain.Vtxo{
				{
					Outpoint: domain.Outpoint{
						Txid: "test",
						VOut: 0,
					},
					PubKey: "aaaa",
					Amount: 3000,
				},
			}
			err = svc.Vtxos().AddVtxos(ctx, spendingVtxos)
			require.NoError(t, err)

			pendingSpentVtxos, err = svc.Vtxos().GetPendingSpentVtxosWithOutpoints(ctx, outpoints)
			require.NoError(t, err)
			require.Len(t, pendingSpentVtxos, 1)
			require.Equal(t, "bbbb", pendingSpentVtxos[0].PubKey)

			pendingSpentVtxosByPubkey, err = svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"aaaa"}, 0, 0,
			)
			require.NoError(t, err)
			require.Empty(t, pendingSpentVtxosByPubkey)

			pendingSpentVtxosByPubkey, err = svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"bbbb"}, 0, 0,
			)
			require.NoError(t, err)
			require.Len(t, pendingSpentVtxosByPubkey, 1)

			// Test with time range that includes the vtxo
			currTime := time.Now()
			pendingSpentVtxosByPubkey, err = svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"bbbb"}, currTime.Add(-1*time.Hour).UnixMilli(), currTime.Add(1*time.Hour).UnixMilli(),
			)
			require.NoError(t, err)
			require.Len(t, pendingSpentVtxosByPubkey, 1)

			// Test with unbounded after time
			pendingSpentVtxosByPubkey, err = svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"bbbb"}, 0, currTime.Add(1*time.Hour).UnixMilli(),
			)
			require.NoError(t, err)
			require.Len(t, pendingSpentVtxosByPubkey, 1)

			// Test with unbounded before time
			pendingSpentVtxosByPubkey, err = svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"bbbb"}, currTime.Add(-1*time.Hour).UnixMilli(), 0,
			)
			require.NoError(t, err)
			require.Len(t, pendingSpentVtxosByPubkey, 1)

			// Test with time range that excludes the vtxo
			pendingSpentVtxosByPubkey, err = svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"bbbb"}, currTime.Add(-2*time.Hour).UnixMilli(), currTime.Add(-1*time.Hour).UnixMilli(),
			)
			require.NoError(t, err)
			require.Empty(t, pendingSpentVtxosByPubkey)

			// TODO: move to "invalid" sub-test
			// Test with invalid time range where after is greater than before
			pendingSpentVtxosByPubkey, err = svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"bbbb"}, now.UnixMilli()+1000, now.UnixMilli(),
			)
			require.Error(t, err)
			require.Equal(t, "before must be greater than after", err.Error())
			require.Empty(t, pendingSpentVtxosByPubkey)

			// Test with invalid time range where after is equal to before
			pendingSpentVtxosByPubkey, err = svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"bbbb"}, now.UnixMilli(), now.UnixMilli(),
			)
			require.Error(t, err)
			require.Equal(t, "before must be greater than after", err.Error())
			require.Empty(t, pendingSpentVtxosByPubkey)

			// Test with negative time after value
			pendingSpentVtxosByPubkey, err = svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"bbbb"}, -1000, 0,
			)
			require.Error(t, err)
			require.Equal(t, "after and before must be greater than or equal to 0", err.Error())
			require.Empty(t, pendingSpentVtxosByPubkey)

			// Test with negative time before value
			pendingSpentVtxosByPubkey, err = svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"bbbb"}, 0, -1000,
			)
			require.Error(t, err)
			require.Equal(t, "after and before must be greater than or equal to 0", err.Error())
			require.Empty(t, pendingSpentVtxosByPubkey)

			// Test with future time range
			futureStart := time.Now().Add(24 * time.Hour).UnixMilli()
			futureEnd := time.Now().Add(25 * time.Hour).UnixMilli()
			pendingSpentVtxosByPubkey, err = svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"bbbb"}, futureStart, futureEnd,
			)
			require.NoError(t, err)
			require.Empty(t, pendingSpentVtxosByPubkey)

			// Simulate finalization of a send-all by adding a new vtxo spending the pending one
			// with same amount and different pubkey
			spendingVtxos = []domain.Vtxo{
				{
					Outpoint: domain.Outpoint{
						Txid: "test2",
						VOut: 0,
					},
					PubKey: "cccc",
					Amount: 10000,
				},
			}
			err = svc.Vtxos().AddVtxos(ctx, spendingVtxos)
			require.NoError(t, err)

			pendingSpentVtxos, err = svc.Vtxos().GetPendingSpentVtxosWithOutpoints(ctx, outpoints)
			require.NoError(t, err)
			require.Empty(t, pendingSpentVtxos)

			pendingSpentVtxosByPubkey, err = svc.Vtxos().GetPendingSpentVtxosWithPubKeys(
				ctx, []string{"bbbb"}, 0, 0,
			)
			require.NoError(t, err)
			require.Empty(t, pendingSpentVtxosByPubkey)
		})

		liquidityNow := time.Now().Unix()
		after := liquidityNow + 1
		before := liquidityNow + 45

		liquidityCommitmentTxid := randomString(32)
		expiringVtxoToSweep := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 1},
			PubKey:             pubkey,
			Amount:             200,
			RootCommitmentTxid: liquidityCommitmentTxid,
			CommitmentTxids:    []string{liquidityCommitmentTxid},
			ExpiresAt:          liquidityNow + 20,
			Swept:              false, // Will be marked as swept via markers
			Spent:              false,
			Unrolled:           false,
		}
		expiringVtxos := []domain.Vtxo{
			{
				Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 9},
				PubKey:             pubkey,
				Amount:             700,
				RootCommitmentTxid: liquidityCommitmentTxid,
				CommitmentTxids:    []string{liquidityCommitmentTxid},
				ExpiresAt:          liquidityNow - 10,
				Swept:              false,
				Spent:              false,
				Unrolled:           false,
			},
			{
				Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 0},
				PubKey:             pubkey,
				Amount:             100,
				RootCommitmentTxid: liquidityCommitmentTxid,
				CommitmentTxids:    []string{liquidityCommitmentTxid},
				ExpiresAt:          liquidityNow + 10,
				Swept:              false,
				Spent:              false,
				Unrolled:           false,
			},
			expiringVtxoToSweep,
			{
				Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 2},
				PubKey:             pubkey,
				Amount:             300,
				RootCommitmentTxid: liquidityCommitmentTxid,
				CommitmentTxids:    []string{liquidityCommitmentTxid},
				ExpiresAt:          liquidityNow + 30,
				Swept:              false,
				Spent:              true,
				Unrolled:           false,
			},
			{
				Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 3},
				PubKey:             pubkey,
				Amount:             400,
				RootCommitmentTxid: liquidityCommitmentTxid,
				CommitmentTxids:    []string{liquidityCommitmentTxid},
				ExpiresAt:          liquidityNow + 40,
				Swept:              false,
				Spent:              false,
				Unrolled:           true,
			},
			{
				Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 4},
				PubKey:             pubkey,
				Amount:             500,
				RootCommitmentTxid: liquidityCommitmentTxid,
				CommitmentTxids:    []string{liquidityCommitmentTxid},
				ExpiresAt:          liquidityNow + 50,
				Swept:              false,
				Spent:              false,
				Unrolled:           false,
			},
		}
		err = svc.Vtxos().AddVtxos(ctx, expiringVtxos)
		require.NoError(t, err)

		// Mark the swept vtxo via markers (if marker store is available)
		if svc.Markers() != nil {
			sweptAt := time.Now().Unix()
			err = svc.Markers().MarkDustVtxoSwept(ctx, expiringVtxoToSweep.Outpoint, sweptAt)
			require.NoError(t, err)
		}

		amount, err := svc.Vtxos().GetExpiringLiquidity(ctx, after, before)
		require.NoError(t, err)
		// Only vtxo at VOut=0 with Amount=100 is in range (after < expiresAt < before)
		require.Equal(t, uint64(100), amount)

		// before=0 means no upper bound.
		// Without marker support: 100 + 200 + 500 = 800 (swept vtxo not excluded)
		// With marker support: 100 + 500 = 600 (swept vtxo excluded)
		amount, err = svc.Vtxos().GetExpiringLiquidity(ctx, liquidityNow, 0)
		require.NoError(t, err)
		if svc.Markers() != nil {
			require.Equal(t, uint64(600), amount)
		} else {
			require.Equal(t, uint64(800), amount)
		}

		recoverableBefore, err := svc.Vtxos().GetRecoverableLiquidity(ctx)
		require.NoError(t, err)

		recoverableCommitmentTxid := randomString(32)
		recoverableVtxo1 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 10},
			PubKey:             pubkey,
			Amount:             111,
			RootCommitmentTxid: recoverableCommitmentTxid,
			CommitmentTxids:    []string{recoverableCommitmentTxid},
			Swept:              false, // Will be marked as swept via markers
			Spent:              false,
		}
		recoverableVtxo2 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 11},
			PubKey:             pubkey,
			Amount:             222,
			RootCommitmentTxid: recoverableCommitmentTxid,
			CommitmentTxids:    []string{recoverableCommitmentTxid},
			Swept:              false, // Will be marked as swept via markers
			Spent:              true,
		}
		recoverableVtxo3 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 12},
			PubKey:             pubkey,
			Amount:             333,
			RootCommitmentTxid: recoverableCommitmentTxid,
			CommitmentTxids:    []string{recoverableCommitmentTxid},
			Swept:              false,
			Spent:              false,
		}
		recoverableVtxos := []domain.Vtxo{recoverableVtxo1, recoverableVtxo2, recoverableVtxo3}
		err = svc.Vtxos().AddVtxos(ctx, recoverableVtxos)
		require.NoError(t, err)

		// Mark first two vtxos as swept via markers (if marker store is available)
		if svc.Markers() != nil {
			sweptAt := time.Now().Unix()
			err = svc.Markers().MarkDustVtxoSwept(ctx, recoverableVtxo1.Outpoint, sweptAt)
			require.NoError(t, err)
			err = svc.Markers().MarkDustVtxoSwept(ctx, recoverableVtxo2.Outpoint, sweptAt)
			require.NoError(t, err)
		}

		recoverableAfter, err := svc.Vtxos().GetRecoverableLiquidity(ctx)
		require.NoError(t, err)
		// Only recoverableVtxo1 is swept and not spent, so it contributes 111
		if svc.Markers() != nil {
			require.Equal(t, recoverableBefore+uint64(111), recoverableAfter)
		}
	})

	t.Run("test_vtxo_depth", func(t *testing.T) {
		ctx := context.Background()
		commitmentTxid := randomString(32)

		// Create vtxos with different depths to simulate a chain
		// Batch vtxo at depth 0
		batchVtxo := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 0},
			PubKey:             pubkey,
			Amount:             1000,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid},
			Depth:              0,
		}

		// First chain at depth 1
		chainedVtxo1 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 0},
			PubKey:             pubkey,
			Amount:             900,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid, randomString(32)},
			Depth:              1,
		}

		// Second chain at depth 2
		chainedVtxo2 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 0},
			PubKey:             pubkey,
			Amount:             800,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid, randomString(32), randomString(32)},
			Depth:              2,
		}

		// Deep chain at depth 100
		deepVtxo := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 0},
			PubKey:             pubkey,
			Amount:             500,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid},
			Depth:              100,
		}

		vtxosToAdd := []domain.Vtxo{batchVtxo, chainedVtxo1, chainedVtxo2, deepVtxo}
		err := svc.Vtxos().AddVtxos(ctx, vtxosToAdd)
		require.NoError(t, err)

		// Retrieve and verify depths are preserved
		outpoints := []domain.Outpoint{
			batchVtxo.Outpoint,
			chainedVtxo1.Outpoint,
			chainedVtxo2.Outpoint,
			deepVtxo.Outpoint,
		}
		retrievedVtxos, err := svc.Vtxos().GetVtxos(ctx, outpoints)
		require.NoError(t, err)
		require.Len(t, retrievedVtxos, 4)

		// Create a map for easier lookup
		vtxoByOutpoint := make(map[string]domain.Vtxo)
		for _, v := range retrievedVtxos {
			vtxoByOutpoint[v.Outpoint.String()] = v
		}

		// Verify each vtxo has correct depth
		require.Equal(t, uint32(0), vtxoByOutpoint[batchVtxo.Outpoint.String()].Depth)
		require.Equal(t, uint32(1), vtxoByOutpoint[chainedVtxo1.Outpoint.String()].Depth)
		require.Equal(t, uint32(2), vtxoByOutpoint[chainedVtxo2.Outpoint.String()].Depth)
		require.Equal(t, uint32(100), vtxoByOutpoint[deepVtxo.Outpoint.String()].Depth)
	})
}

func testMarkerBasicOperations(t *testing.T, svc ports.RepoManager) {
	t.Run("test_marker_basic_operations", func(t *testing.T) {
		if svc.Markers() == nil {
			t.Skip("marker repository not available for this data store")
		}
		ctx := context.Background()

		// Create markers with AddMarker
		marker1 := domain.Marker{
			ID:              randomString(32),
			Depth:           0,
			ParentMarkerIDs: nil,
		}
		marker2 := domain.Marker{
			ID:              randomString(32),
			Depth:           100,
			ParentMarkerIDs: []string{marker1.ID},
		}
		marker3 := domain.Marker{
			ID:              randomString(32),
			Depth:           100,
			ParentMarkerIDs: []string{marker1.ID},
		}
		marker4 := domain.Marker{
			ID:              randomString(32),
			Depth:           200,
			ParentMarkerIDs: []string{marker2.ID, marker3.ID},
		}

		err := svc.Markers().AddMarker(ctx, marker1)
		require.NoError(t, err)
		err = svc.Markers().AddMarker(ctx, marker2)
		require.NoError(t, err)
		err = svc.Markers().AddMarker(ctx, marker3)
		require.NoError(t, err)
		err = svc.Markers().AddMarker(ctx, marker4)
		require.NoError(t, err)

		// Test GetMarker - retrieve single marker and verify all fields
		retrievedMarker1, err := svc.Markers().GetMarker(ctx, marker1.ID)
		require.NoError(t, err)
		require.NotNil(t, retrievedMarker1)
		require.Equal(t, marker1.ID, retrievedMarker1.ID)
		require.Equal(t, marker1.Depth, retrievedMarker1.Depth)
		require.Empty(t, retrievedMarker1.ParentMarkerIDs)

		retrievedMarker2, err := svc.Markers().GetMarker(ctx, marker2.ID)
		require.NoError(t, err)
		require.NotNil(t, retrievedMarker2)
		require.Equal(t, marker2.ID, retrievedMarker2.ID)
		require.Equal(t, marker2.Depth, retrievedMarker2.Depth)
		require.ElementsMatch(t, marker2.ParentMarkerIDs, retrievedMarker2.ParentMarkerIDs)

		retrievedMarker4, err := svc.Markers().GetMarker(ctx, marker4.ID)
		require.NoError(t, err)
		require.NotNil(t, retrievedMarker4)
		require.Equal(t, marker4.ID, retrievedMarker4.ID)
		require.Equal(t, marker4.Depth, retrievedMarker4.Depth)
		require.ElementsMatch(t, marker4.ParentMarkerIDs, retrievedMarker4.ParentMarkerIDs)

		// Test GetMarker with non-existent ID
		nonExistent, err := svc.Markers().GetMarker(ctx, "nonexistent")
		require.NoError(t, err)
		require.Nil(t, nonExistent)

		// Test GetMarkersByDepth - markers at same depth
		markersAtDepth100, err := svc.Markers().GetMarkersByDepth(ctx, 100)
		require.NoError(t, err)
		require.Len(t, markersAtDepth100, 2)
		markerIdsAtDepth100 := []string{markersAtDepth100[0].ID, markersAtDepth100[1].ID}
		require.ElementsMatch(t, []string{marker2.ID, marker3.ID}, markerIdsAtDepth100)

		markersAtDepth0, err := svc.Markers().GetMarkersByDepth(ctx, 0)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(markersAtDepth0), 1)
		var foundMarker1 bool
		for _, m := range markersAtDepth0 {
			if m.ID == marker1.ID {
				foundMarker1 = true
				break
			}
		}
		require.True(t, foundMarker1)

		markersAtDepth200, err := svc.Markers().GetMarkersByDepth(ctx, 200)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(markersAtDepth200), 1)
		var foundMarker4 bool
		for _, m := range markersAtDepth200 {
			if m.ID == marker4.ID {
				foundMarker4 = true
				break
			}
		}
		require.True(t, foundMarker4)

		// Test GetMarkersByIds - batch retrieve
		markersById, err := svc.Markers().
			GetMarkersByIds(ctx, []string{marker1.ID, marker3.ID, marker4.ID})
		require.NoError(t, err)
		require.Len(t, markersById, 3)
		retrievedIds := make([]string, len(markersById))
		for i, m := range markersById {
			retrievedIds[i] = m.ID
		}
		require.ElementsMatch(t, []string{marker1.ID, marker3.ID, marker4.ID}, retrievedIds)

		// Test GetMarkersByIds with empty slice
		emptyMarkers, err := svc.Markers().GetMarkersByIds(ctx, []string{})
		require.NoError(t, err)
		require.Nil(t, emptyMarkers)

		// Test GetMarkersByIds with non-existent IDs mixed with valid
		mixedMarkers, err := svc.Markers().GetMarkersByIds(ctx, []string{marker1.ID, "nonexistent"})
		require.NoError(t, err)
		require.Len(t, mixedMarkers, 1)
		require.Equal(t, marker1.ID, mixedMarkers[0].ID)
	})
}

func testMarkerSweep(t *testing.T, svc ports.RepoManager) {
	t.Run("test_marker_sweep", func(t *testing.T) {
		if svc.Markers() == nil {
			t.Skip("marker repository not available for this data store")
		}
		ctx := context.Background()

		// Create a marker
		marker := domain.Marker{
			ID:              randomString(32),
			Depth:           0,
			ParentMarkerIDs: nil,
		}
		err := svc.Markers().AddMarker(ctx, marker)
		require.NoError(t, err)

		// Verify marker is not swept initially
		isSwept, err := svc.Markers().IsMarkerSwept(ctx, marker.ID)
		require.NoError(t, err)
		require.False(t, isSwept)

		// Sweep the marker
		sweptAt := time.Now().UnixMilli()
		err = svc.Markers().SweepMarker(ctx, marker.ID, sweptAt)
		require.NoError(t, err)

		// Verify IsMarkerSwept returns true
		isSwept, err = svc.Markers().IsMarkerSwept(ctx, marker.ID)
		require.NoError(t, err)
		require.True(t, isSwept)

		// Verify GetSweptMarkers returns correct record
		sweptMarkers, err := svc.Markers().GetSweptMarkers(ctx, []string{marker.ID})
		require.NoError(t, err)
		require.Len(t, sweptMarkers, 1)
		require.Equal(t, marker.ID, sweptMarkers[0].MarkerID)
		require.Equal(t, sweptAt, sweptMarkers[0].SweptAt)

		// Test idempotency - sweeping again should not error (ON CONFLICT DO NOTHING)
		err = svc.Markers().SweepMarker(ctx, marker.ID, sweptAt+1000)
		require.NoError(t, err)

		// Verify the original swept_at is preserved (not updated)
		sweptMarkers, err = svc.Markers().GetSweptMarkers(ctx, []string{marker.ID})
		require.NoError(t, err)
		require.Len(t, sweptMarkers, 1)
		require.Equal(t, sweptAt, sweptMarkers[0].SweptAt)

		// Test GetSweptMarkers with multiple markers
		marker2 := domain.Marker{
			ID:              randomString(32),
			Depth:           100,
			ParentMarkerIDs: []string{marker.ID},
		}
		err = svc.Markers().AddMarker(ctx, marker2)
		require.NoError(t, err)

		sweptAt2 := time.Now().UnixMilli()
		err = svc.Markers().SweepMarker(ctx, marker2.ID, sweptAt2)
		require.NoError(t, err)

		sweptMarkers, err = svc.Markers().GetSweptMarkers(ctx, []string{marker.ID, marker2.ID})
		require.NoError(t, err)
		require.Len(t, sweptMarkers, 2)

		// Test GetSweptMarkers with empty slice
		emptySwept, err := svc.Markers().GetSweptMarkers(ctx, []string{})
		require.NoError(t, err)
		require.Nil(t, emptySwept)

		// Test IsMarkerSwept for non-existent marker
		isSwept, err = svc.Markers().IsMarkerSwept(ctx, "nonexistent")
		require.NoError(t, err)
		require.False(t, isSwept)
	})

	t.Run("test_sweep_marker_with_descendants", func(t *testing.T) {
		if svc.Markers() == nil {
			t.Skip("marker repository not available for this data store")
		}
		ctx := context.Background()

		// Create a marker hierarchy:
		// root -> child1 -> grandchild1
		//      -> child2
		root := domain.Marker{
			ID:              "sweep_desc_root_" + randomString(16),
			Depth:           0,
			ParentMarkerIDs: nil,
		}
		child1 := domain.Marker{
			ID:              "sweep_desc_child1_" + randomString(16),
			Depth:           100,
			ParentMarkerIDs: []string{root.ID},
		}
		child2 := domain.Marker{
			ID:              "sweep_desc_child2_" + randomString(16),
			Depth:           100,
			ParentMarkerIDs: []string{root.ID},
		}
		grandchild1 := domain.Marker{
			ID:              "sweep_desc_grandchild1_" + randomString(16),
			Depth:           200,
			ParentMarkerIDs: []string{child1.ID},
		}

		err := svc.Markers().AddMarker(ctx, root)
		require.NoError(t, err)
		err = svc.Markers().AddMarker(ctx, child1)
		require.NoError(t, err)
		err = svc.Markers().AddMarker(ctx, child2)
		require.NoError(t, err)
		err = svc.Markers().AddMarker(ctx, grandchild1)
		require.NoError(t, err)

		// Verify none are swept initially
		isSwept, err := svc.Markers().IsMarkerSwept(ctx, root.ID)
		require.NoError(t, err)
		require.False(t, isSwept)

		// Sweep root with descendants
		sweptAt := time.Now().UnixMilli()
		count, err := svc.Markers().SweepMarkerWithDescendants(ctx, root.ID, sweptAt)
		require.NoError(t, err)
		require.Equal(t, int64(4), count) // root + child1 + child2 + grandchild1

		// Verify all markers are now swept
		for _, m := range []domain.Marker{root, child1, child2, grandchild1} {
			isSwept, err := svc.Markers().IsMarkerSwept(ctx, m.ID)
			require.NoError(t, err)
			require.True(t, isSwept, "Marker %s should be swept", m.ID)
		}

		// Test idempotency - calling again should return 0
		count, err = svc.Markers().SweepMarkerWithDescendants(ctx, root.ID, sweptAt+1000)
		require.NoError(t, err)
		require.Equal(t, int64(0), count)

		// Test sweeping a leaf node (no descendants)
		leaf := domain.Marker{
			ID:              "sweep_desc_leaf_" + randomString(16),
			Depth:           300,
			ParentMarkerIDs: []string{grandchild1.ID},
		}
		err = svc.Markers().AddMarker(ctx, leaf)
		require.NoError(t, err)

		count, err = svc.Markers().SweepMarkerWithDescendants(ctx, leaf.ID, sweptAt)
		require.NoError(t, err)
		require.Equal(t, int64(1), count) // Just the leaf itself

		// Test with non-existent marker (should return 0)
		count, err = svc.Markers().SweepMarkerWithDescendants(ctx, "nonexistent", sweptAt)
		require.NoError(t, err)
		require.Equal(t, int64(0), count)
	})
}

func testVtxoMarkerAssociation(t *testing.T, svc ports.RepoManager) {
	t.Run("test_vtxo_marker_association", func(t *testing.T) {
		if svc.Markers() == nil {
			t.Skip("marker repository not available for this data store")
		}
		ctx := context.Background()
		commitmentTxid := randomString(32)

		// Create a marker
		markerID := randomString(32)
		marker := domain.Marker{
			ID:              markerID,
			Depth:           0,
			ParentMarkerIDs: nil,
		}
		err := svc.Markers().AddMarker(ctx, marker)
		require.NoError(t, err)

		// Add VTXOs without marker_id
		vtxo1 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 0},
			PubKey:             pubkey,
			Amount:             1000,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid},
			Depth:              0,
		}
		vtxo2 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 0},
			PubKey:             pubkey,
			Amount:             2000,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid},
			Depth:              50,
		}
		vtxo3 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 0},
			PubKey:             pubkey2,
			Amount:             3000,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid},
			Depth:              75,
		}

		err = svc.Vtxos().AddVtxos(ctx, []domain.Vtxo{vtxo1, vtxo2, vtxo3})
		require.NoError(t, err)

		// Verify VTXOs initially have no markers
		retrievedVtxos, err := svc.Vtxos().GetVtxos(ctx, []domain.Outpoint{vtxo1.Outpoint})
		require.NoError(t, err)
		require.Len(t, retrievedVtxos, 1)
		require.Empty(t, retrievedVtxos[0].MarkerIDs)

		// Call UpdateVtxoMarkers to associate VTXOs with marker
		err = svc.Markers().UpdateVtxoMarkers(ctx, vtxo1.Outpoint, []string{markerID})
		require.NoError(t, err)
		err = svc.Markers().UpdateVtxoMarkers(ctx, vtxo2.Outpoint, []string{markerID})
		require.NoError(t, err)

		// Verify GetVtxosByMarker returns the associated VTXOs
		vtxosByMarker, err := svc.Markers().GetVtxosByMarker(ctx, markerID)
		require.NoError(t, err)
		require.Len(t, vtxosByMarker, 2)
		outpoints := []string{
			vtxosByMarker[0].Outpoint.String(),
			vtxosByMarker[1].Outpoint.String(),
		}
		require.ElementsMatch(
			t,
			[]string{vtxo1.Outpoint.String(), vtxo2.Outpoint.String()},
			outpoints,
		)

		// Verify VTXO.MarkerIDs field is populated when retrieved via GetVtxos
		retrievedVtxos, err = svc.Vtxos().
			GetVtxos(ctx, []domain.Outpoint{vtxo1.Outpoint, vtxo2.Outpoint})
		require.NoError(t, err)
		require.Len(t, retrievedVtxos, 2)
		for _, v := range retrievedVtxos {
			require.Contains(t, v.MarkerIDs, markerID)
		}

		// Verify vtxo3 still has no markers
		retrievedVtxos, err = svc.Vtxos().GetVtxos(ctx, []domain.Outpoint{vtxo3.Outpoint})
		require.NoError(t, err)
		require.Len(t, retrievedVtxos, 1)
		require.Empty(t, retrievedVtxos[0].MarkerIDs)

		// Test GetVtxosByMarker with non-existent marker
		vtxosByNonExistent, err := svc.Markers().GetVtxosByMarker(ctx, "nonexistent")
		require.NoError(t, err)
		require.Empty(t, vtxosByNonExistent)
	})
}

func testSweepVtxosByMarker(t *testing.T, svc ports.RepoManager) {
	t.Run("test_sweep_vtxos_by_marker", func(t *testing.T) {
		if svc.Markers() == nil {
			t.Skip("marker repository not available for this data store")
		}
		ctx := context.Background()
		commitmentTxid := randomString(32)

		// Create a marker
		markerID := randomString(32)
		marker := domain.Marker{
			ID:              markerID,
			Depth:           0,
			ParentMarkerIDs: nil,
		}
		err := svc.Markers().AddMarker(ctx, marker)
		require.NoError(t, err)

		// Add 5 VTXOs - all start as unswept
		vtxos := make([]domain.Vtxo, 5)
		for i := 0; i < 5; i++ {
			vtxos[i] = domain.Vtxo{
				Outpoint:           domain.Outpoint{Txid: randomString(32), VOut: 0},
				PubKey:             pubkey,
				Amount:             uint64(1000 * (i + 1)),
				RootCommitmentTxid: commitmentTxid,
				CommitmentTxids:    []string{commitmentTxid},
				Depth:              uint32(i * 10),
				Swept:              false,
			}
		}

		err = svc.Vtxos().AddVtxos(ctx, vtxos)
		require.NoError(t, err)

		// Associate all VTXOs with the marker
		for _, v := range vtxos {
			err = svc.Markers().UpdateVtxoMarkers(ctx, v.Outpoint, []string{markerID})
			require.NoError(t, err)
		}

		// Mark vtxos[3] and vtxos[4] as swept via MarkDustVtxoSwept
		sweptAt := time.Now().Unix()
		err = svc.Markers().MarkDustVtxoSwept(ctx, vtxos[3].Outpoint, sweptAt)
		require.NoError(t, err)
		err = svc.Markers().MarkDustVtxoSwept(ctx, vtxos[4].Outpoint, sweptAt)
		require.NoError(t, err)

		// Verify initial state - vtxos[3] and vtxos[4] should be swept
		vtxosByMarker, err := svc.Markers().GetVtxosByMarker(ctx, markerID)
		require.NoError(t, err)
		require.Len(t, vtxosByMarker, 5)

		sweptCount := 0
		for _, v := range vtxosByMarker {
			if v.Swept {
				sweptCount++
			}
		}
		require.Equal(t, 2, sweptCount)

		// Call SweepVtxosByMarker - this sweeps by marking the marker itself as swept
		count, err := svc.Markers().SweepVtxosByMarker(ctx, markerID)
		require.NoError(t, err)
		require.Equal(t, int64(3), count) // Only 3 were newly swept

		// Verify all 5 VTXOs now have swept=true
		vtxosByMarker, err = svc.Markers().GetVtxosByMarker(ctx, markerID)
		require.NoError(t, err)
		require.Len(t, vtxosByMarker, 5)
		for _, v := range vtxosByMarker {
			require.True(t, v.Swept, "VTXO %s should be swept", v.Outpoint.String())
		}

		// Call SweepVtxosByMarker again - should return 0 (all already swept)
		count, err = svc.Markers().SweepVtxosByMarker(ctx, markerID)
		require.NoError(t, err)
		require.Equal(t, int64(0), count)

		// Test with non-existent marker
		count, err = svc.Markers().SweepVtxosByMarker(ctx, "nonexistent")
		require.NoError(t, err)
		require.Equal(t, int64(0), count)
	})
}

func testMarkerDepthRangeQueries(t *testing.T, svc ports.RepoManager) {
	t.Run("test_marker_depth_range_queries", func(t *testing.T) {
		if svc.Markers() == nil {
			t.Skip("marker repository not available for this data store")
		}
		ctx := context.Background()
		commitmentTxid := randomString(32)

		// Add markers at depths 0, 100, 200, 300 with unique IDs
		markerDepth0 := domain.Marker{
			ID:              "range_test_" + randomString(16),
			Depth:           0,
			ParentMarkerIDs: nil,
		}
		markerDepth100 := domain.Marker{
			ID:              "range_test_" + randomString(16),
			Depth:           100,
			ParentMarkerIDs: []string{markerDepth0.ID},
		}
		markerDepth200 := domain.Marker{
			ID:              "range_test_" + randomString(16),
			Depth:           200,
			ParentMarkerIDs: []string{markerDepth100.ID},
		}
		markerDepth300 := domain.Marker{
			ID:              "range_test_" + randomString(16),
			Depth:           300,
			ParentMarkerIDs: []string{markerDepth200.ID},
		}

		err := svc.Markers().AddMarker(ctx, markerDepth0)
		require.NoError(t, err)
		err = svc.Markers().AddMarker(ctx, markerDepth100)
		require.NoError(t, err)
		err = svc.Markers().AddMarker(ctx, markerDepth200)
		require.NoError(t, err)
		err = svc.Markers().AddMarker(ctx, markerDepth300)
		require.NoError(t, err)

		// Test GetMarkersByDepthRange(50, 250) - should return markers at 100 and 200
		markersInRange, err := svc.Markers().GetMarkersByDepthRange(ctx, 50, 250)
		require.NoError(t, err)

		// Filter to only our test markers
		var ourMarkers []domain.Marker
		testMarkerIDs := map[string]bool{
			markerDepth0.ID:   true,
			markerDepth100.ID: true,
			markerDepth200.ID: true,
			markerDepth300.ID: true,
		}
		for _, m := range markersInRange {
			if testMarkerIDs[m.ID] {
				ourMarkers = append(ourMarkers, m)
			}
		}
		require.Len(t, ourMarkers, 2)
		foundDepths := []uint32{ourMarkers[0].Depth, ourMarkers[1].Depth}
		require.ElementsMatch(t, []uint32{100, 200}, foundDepths)

		// Test range that includes all
		markersInRange, err = svc.Markers().GetMarkersByDepthRange(ctx, 0, 300)
		require.NoError(t, err)
		ourMarkers = nil
		for _, m := range markersInRange {
			if testMarkerIDs[m.ID] {
				ourMarkers = append(ourMarkers, m)
			}
		}
		require.Len(t, ourMarkers, 4)

		// Test range that includes none of our test markers
		markersInRange, err = svc.Markers().GetMarkersByDepthRange(ctx, 350, 400)
		require.NoError(t, err)
		ourMarkers = nil
		for _, m := range markersInRange {
			if testMarkerIDs[m.ID] {
				ourMarkers = append(ourMarkers, m)
			}
		}
		require.Empty(t, ourMarkers)

		// Add VTXOs at depths 0, 50, 100, 150 with unique IDs
		vtxoDepth0 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: "vtxo_range_" + randomString(24), VOut: 0},
			PubKey:             pubkey,
			Amount:             1000,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid},
			Depth:              0,
		}
		vtxoDepth50 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: "vtxo_range_" + randomString(24), VOut: 0},
			PubKey:             pubkey,
			Amount:             2000,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid},
			Depth:              50,
		}
		vtxoDepth100 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: "vtxo_range_" + randomString(24), VOut: 0},
			PubKey:             pubkey,
			Amount:             3000,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid},
			Depth:              100,
		}
		vtxoDepth150 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: "vtxo_range_" + randomString(24), VOut: 0},
			PubKey:             pubkey,
			Amount:             4000,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid},
			Depth:              150,
		}

		err = svc.Vtxos().
			AddVtxos(ctx, []domain.Vtxo{vtxoDepth0, vtxoDepth50, vtxoDepth100, vtxoDepth150})
		require.NoError(t, err)

		// Test GetVtxosByDepthRange(25, 125) - should return VTXOs at 50 and 100
		vtxosInRange, err := svc.Markers().GetVtxosByDepthRange(ctx, 25, 125)
		require.NoError(t, err)

		// Filter to only our test vtxos
		testVtxoTxids := map[string]bool{
			vtxoDepth0.Txid:   true,
			vtxoDepth50.Txid:  true,
			vtxoDepth100.Txid: true,
			vtxoDepth150.Txid: true,
		}
		var ourVtxos []domain.Vtxo
		for _, v := range vtxosInRange {
			if testVtxoTxids[v.Txid] {
				ourVtxos = append(ourVtxos, v)
			}
		}
		require.Len(t, ourVtxos, 2)
		foundVtxoDepths := []uint32{ourVtxos[0].Depth, ourVtxos[1].Depth}
		require.ElementsMatch(t, []uint32{50, 100}, foundVtxoDepths)

		// Test range that includes all test vtxos
		vtxosInRange, err = svc.Markers().GetVtxosByDepthRange(ctx, 0, 150)
		require.NoError(t, err)
		ourVtxos = nil
		for _, v := range vtxosInRange {
			if testVtxoTxids[v.Txid] {
				ourVtxos = append(ourVtxos, v)
			}
		}
		require.Len(t, ourVtxos, 4)

		// Test range that includes none
		vtxosInRange, err = svc.Markers().GetVtxosByDepthRange(ctx, 200, 300)
		require.NoError(t, err)
		ourVtxos = nil
		for _, v := range vtxosInRange {
			if testVtxoTxids[v.Txid] {
				ourVtxos = append(ourVtxos, v)
			}
		}
		require.Empty(t, ourVtxos)
	})
}

func testMarkerChainTraversal(t *testing.T, svc ports.RepoManager) {
	t.Run("test_marker_chain_traversal", func(t *testing.T) {
		if svc.Markers() == nil {
			t.Skip("marker repository not available for this data store")
		}
		ctx := context.Background()
		commitmentTxid := randomString(32)

		// Create markers for the chain
		marker1 := domain.Marker{
			ID:              "chain_marker_" + randomString(16),
			Depth:           0,
			ParentMarkerIDs: nil,
		}
		marker2 := domain.Marker{
			ID:              "chain_marker_" + randomString(16),
			Depth:           100,
			ParentMarkerIDs: []string{marker1.ID},
		}

		err := svc.Markers().AddMarker(ctx, marker1)
		require.NoError(t, err)
		err = svc.Markers().AddMarker(ctx, marker2)
		require.NoError(t, err)

		// Create an ark_txid that links vtxos together
		arkTxid := "ark_chain_" + randomString(24)

		// Add VTXOs with ark_txid (marker_ids will be set via UpdateVtxoMarker)
		vtxo1 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: "chain_vtxo_" + randomString(20), VOut: 0},
			PubKey:             pubkey,
			Amount:             1000,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid},
			Depth:              0,
			ArkTxid:            arkTxid,
		}
		vtxo2 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: arkTxid, VOut: 0}, // Created by arkTxid
			PubKey:             pubkey,
			Amount:             900,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid},
			Depth:              1,
		}
		vtxo3 := domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: "chain_vtxo_" + randomString(20), VOut: 0},
			PubKey:             pubkey,
			Amount:             800,
			RootCommitmentTxid: commitmentTxid,
			CommitmentTxids:    []string{commitmentTxid},
			Depth:              100,
		}

		err = svc.Vtxos().AddVtxos(ctx, []domain.Vtxo{vtxo1, vtxo2, vtxo3})
		require.NoError(t, err)

		// Associate VTXOs with their markers using UpdateVtxoMarkers
		err = svc.Markers().UpdateVtxoMarkers(ctx, vtxo1.Outpoint, []string{marker1.ID})
		require.NoError(t, err)
		err = svc.Markers().UpdateVtxoMarkers(ctx, vtxo2.Outpoint, []string{marker1.ID})
		require.NoError(t, err)
		err = svc.Markers().UpdateVtxoMarkers(ctx, vtxo3.Outpoint, []string{marker2.ID})
		require.NoError(t, err)

		// Test GetVtxoChainByMarkers - returns VTXOs for given marker list
		vtxosByMarkers, err := svc.Markers().GetVtxoChainByMarkers(ctx, []string{marker1.ID})
		require.NoError(t, err)
		require.Len(t, vtxosByMarkers, 2) // vtxo1 and vtxo2 have marker1.ID
		foundTxids := make(map[string]bool)
		for _, v := range vtxosByMarkers {
			foundTxids[v.Txid] = true
		}
		require.True(t, foundTxids[vtxo1.Txid])
		require.True(t, foundTxids[vtxo2.Txid])

		// Test with both markers
		vtxosByMarkers, err = svc.Markers().
			GetVtxoChainByMarkers(ctx, []string{marker1.ID, marker2.ID})
		require.NoError(t, err)
		require.Len(t, vtxosByMarkers, 3)

		// Test with empty marker list
		vtxosByMarkers, err = svc.Markers().GetVtxoChainByMarkers(ctx, []string{})
		require.NoError(t, err)
		require.Nil(t, vtxosByMarkers)

		// Test with non-existent marker
		vtxosByMarkers, err = svc.Markers().GetVtxoChainByMarkers(ctx, []string{"nonexistent"})
		require.NoError(t, err)
		require.Empty(t, vtxosByMarkers)

		// Test GetVtxosByArkTxid - returns VTXOs created by specific ark tx
		vtxosByArkTxid, err := svc.Markers().GetVtxosByArkTxid(ctx, arkTxid)
		require.NoError(t, err)
		require.Len(t, vtxosByArkTxid, 1) // Only vtxo2 has Txid == arkTxid
		require.Equal(t, vtxo2.Txid, vtxosByArkTxid[0].Txid)

		// Test GetVtxosByArkTxid with non-existent ark txid
		vtxosByArkTxid, err = svc.Markers().GetVtxosByArkTxid(ctx, "nonexistent")
		require.NoError(t, err)
		require.Empty(t, vtxosByArkTxid)
	})
}

// testGetVtxoChainWithMarkerOptimization tests that GetVtxoChain correctly
// traverses a deep VTXO chain and uses marker-based prefetching.
// This verifies:
// 1. Markers are correctly created at depth boundaries (0, 100, 200)
// 2. VTXOs have correct marker assignments
// 3. GetVtxoChainByMarkers returns all VTXOs for the marker chain
func testGetVtxoChainWithMarkerOptimization(t *testing.T, svc ports.RepoManager) {
	t.Run("test_get_vtxo_chain_with_marker_optimization", func(t *testing.T) {
		if svc.Markers() == nil {
			t.Skip("marker repository not available for this data store")
		}
		ctx := context.Background()
		commitmentTxid := randomString(32)

		// Create markers at depths 0, 100, 200 (simulating a chain spanning 250 depths)
		marker0 := domain.Marker{
			ID:              "opt_marker_0_" + randomString(16),
			Depth:           0,
			ParentMarkerIDs: nil,
		}
		marker100 := domain.Marker{
			ID:              "opt_marker_100_" + randomString(16),
			Depth:           100,
			ParentMarkerIDs: []string{marker0.ID},
		}
		marker200 := domain.Marker{
			ID:              "opt_marker_200_" + randomString(16),
			Depth:           200,
			ParentMarkerIDs: []string{marker100.ID},
		}

		err := svc.Markers().AddMarker(ctx, marker0)
		require.NoError(t, err)
		err = svc.Markers().AddMarker(ctx, marker100)
		require.NoError(t, err)
		err = svc.Markers().AddMarker(ctx, marker200)
		require.NoError(t, err)

		// Create VTXOs at various depths across the marker boundaries:
		// - VTXOs at depth 0-99 should have marker0.ID
		// - VTXOs at depth 100-199 should have marker100.ID
		// - VTXOs at depth 200-250 should have marker200.ID
		vtxos := make([]domain.Vtxo, 0)
		vtxoMarkerMap := make(map[string]string) // outpoint -> markerID

		// Helper to determine which marker a VTXO should have based on depth
		getMarkerForDepth := func(depth uint32) string {
			if depth >= 200 {
				return marker200.ID
			} else if depth >= 100 {
				return marker100.ID
			}
			return marker0.ID
		}

		// Create VTXOs at sample depths: 0, 50, 99, 100, 150, 199, 200, 225, 250
		sampleDepths := []uint32{0, 50, 99, 100, 150, 199, 200, 225, 250}
		for i, depth := range sampleDepths {
			vtxo := domain.Vtxo{
				Outpoint: domain.Outpoint{
					Txid: "opt_chain_vtxo_" + randomString(16),
					VOut: uint32(i),
				},
				PubKey:             pubkey,
				Amount:             uint64(1000 * (i + 1)),
				RootCommitmentTxid: commitmentTxid,
				CommitmentTxids:    []string{commitmentTxid},
				Depth:              depth,
			}
			vtxos = append(vtxos, vtxo)
			vtxoMarkerMap[vtxo.Outpoint.String()] = getMarkerForDepth(depth)
		}

		// Add all VTXOs
		err = svc.Vtxos().AddVtxos(ctx, vtxos)
		require.NoError(t, err)

		// Associate VTXOs with their markers
		for _, v := range vtxos {
			markerID := vtxoMarkerMap[v.Outpoint.String()]
			err = svc.Markers().UpdateVtxoMarkers(ctx, v.Outpoint, []string{markerID})
			require.NoError(t, err)
		}

		// Verify each VTXO has the correct marker assigned
		for _, v := range vtxos {
			retrievedVtxos, err := svc.Vtxos().GetVtxos(ctx, []domain.Outpoint{v.Outpoint})
			require.NoError(t, err)
			require.Len(t, retrievedVtxos, 1)
			expectedMarker := vtxoMarkerMap[v.Outpoint.String()]
			require.Contains(t, retrievedVtxos[0].MarkerIDs, expectedMarker,
				"VTXO at depth %d should have marker %s", v.Depth, expectedMarker)
		}

		// Test 1: Query VTXOs using the full marker chain (marker200 -> marker100 -> marker0)
		// This simulates what prefetchVtxosByMarkers does
		fullMarkerChain := []string{marker200.ID, marker100.ID, marker0.ID}
		allChainVtxos, err := svc.Markers().GetVtxoChainByMarkers(ctx, fullMarkerChain)
		require.NoError(t, err)
		require.Len(t, allChainVtxos, len(vtxos), "Should return all VTXOs in the chain")

		// Verify all our VTXOs are in the result
		resultOutpoints := make(map[string]bool)
		for _, v := range allChainVtxos {
			resultOutpoints[v.Outpoint.String()] = true
		}
		for _, v := range vtxos {
			require.True(t, resultOutpoints[v.Outpoint.String()],
				"VTXO %s at depth %d should be in result", v.Outpoint.String(), v.Depth)
		}

		// Test 2: Query with just marker0 - should return only depth 0-99 VTXOs
		marker0Vtxos, err := svc.Markers().GetVtxoChainByMarkers(ctx, []string{marker0.ID})
		require.NoError(t, err)
		for _, v := range marker0Vtxos {
			// Only check our test VTXOs (filter by prefix)
			if len(v.Txid) > 0 && v.Txid[:13] == "opt_chain_vtx" {
				require.True(t, v.Depth < 100,
					"VTXOs with marker0 should have depth < 100, got depth %d", v.Depth)
			}
		}

		// Test 3: Query with marker200 only - should return only depth 200+ VTXOs
		marker200Vtxos, err := svc.Markers().GetVtxoChainByMarkers(ctx, []string{marker200.ID})
		require.NoError(t, err)
		for _, v := range marker200Vtxos {
			if len(v.Txid) > 0 && v.Txid[:13] == "opt_chain_vtx" {
				require.True(t, v.Depth >= 200,
					"VTXOs with marker200 should have depth >= 200, got depth %d", v.Depth)
			}
		}

		// Test 4: Verify marker chain can be followed via ParentMarkerIDs
		// Starting from marker200, should be able to traverse to marker0
		currentMarker, err := svc.Markers().GetMarker(ctx, marker200.ID)
		require.NoError(t, err)
		require.NotNil(t, currentMarker)
		require.Equal(t, uint32(200), currentMarker.Depth)
		require.Len(t, currentMarker.ParentMarkerIDs, 1)
		require.Equal(t, marker100.ID, currentMarker.ParentMarkerIDs[0])

		currentMarker, err = svc.Markers().GetMarker(ctx, currentMarker.ParentMarkerIDs[0])
		require.NoError(t, err)
		require.NotNil(t, currentMarker)
		require.Equal(t, uint32(100), currentMarker.Depth)
		require.Len(t, currentMarker.ParentMarkerIDs, 1)
		require.Equal(t, marker0.ID, currentMarker.ParentMarkerIDs[0])

		currentMarker, err = svc.Markers().GetMarker(ctx, currentMarker.ParentMarkerIDs[0])
		require.NoError(t, err)
		require.NotNil(t, currentMarker)
		require.Equal(t, uint32(0), currentMarker.Depth)
		require.Nil(t, currentMarker.ParentMarkerIDs) // Root marker has no parents

		// Test 5: Test GetMarkersByIds with the full chain
		markers, err := svc.Markers().GetMarkersByIds(ctx, fullMarkerChain)
		require.NoError(t, err)
		require.Len(t, markers, 3)
		markerDepths := make(map[uint32]bool)
		for _, m := range markers {
			markerDepths[m.Depth] = true
		}
		require.True(t, markerDepths[0])
		require.True(t, markerDepths[100])
		require.True(t, markerDepths[200])

		// Test 6: Verify VTXOs can be retrieved by depth range
		vtxosDepth50to150, err := svc.Markers().GetVtxosByDepthRange(ctx, 50, 150)
		require.NoError(t, err)
		// Filter to our test VTXOs
		ourVtxosInRange := 0
		for _, v := range vtxosDepth50to150 {
			if len(v.Txid) > 13 && v.Txid[:13] == "opt_chain_vtx" {
				ourVtxosInRange++
				require.True(t, v.Depth >= 50 && v.Depth <= 150,
					"VTXO depth %d should be in range [50, 150]", v.Depth)
			}
		}
		// We expect VTXOs at depths 50, 99, 100, 150 to be in range
		require.Equal(t, 4, ourVtxosInRange, "Expected 4 VTXOs in depth range 50-150")
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

func testFeeRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_fee_repository", func(t *testing.T) {
		ctx := context.Background()
		repo := svc.Fees()

		// fees should be initialized to empty strings
		currentFees, err := repo.GetIntentFees(ctx)
		require.NoError(t, err)
		require.NotNil(t, currentFees)
		require.Equal(t, "", currentFees.OnchainInputFee)
		require.Equal(t, "", currentFees.OffchainInputFee)
		require.Equal(t, "", currentFees.OnchainOutputFee)
		require.Equal(t, "", currentFees.OffchainOutputFee)

		newFees := domain.IntentFees{
			OnchainInputFee:   "0.25",
			OffchainInputFee:  "0.30",
			OnchainOutputFee:  "0.35",
			OffchainOutputFee: "0.40",
		}

		// sqlite and postgres use millisecond precision for created_at so we need to
		// wait to ensure the updated_at is different.
		// set the new fees
		time.Sleep(10 * time.Millisecond)
		err = repo.UpdateIntentFees(ctx, newFees)
		require.NoError(t, err)

		updatedFees, err := repo.GetIntentFees(ctx)
		require.NoError(t, err)
		require.NotNil(t, updatedFees)
		require.Equal(t, newFees.OnchainInputFee, updatedFees.OnchainInputFee)
		require.Equal(t, newFees.OffchainInputFee, updatedFees.OffchainInputFee)
		require.Equal(t, newFees.OnchainOutputFee, updatedFees.OnchainOutputFee)
		require.Equal(t, newFees.OffchainOutputFee, updatedFees.OffchainOutputFee)
		time.Sleep(10 * time.Millisecond)
		// zero out the fees
		err = repo.ClearIntentFees(ctx)
		require.NoError(t, err)

		clearedFees, err := repo.GetIntentFees(ctx)
		require.NoError(t, err)
		require.NotNil(t, clearedFees)
		require.Equal(t, "", clearedFees.OnchainInputFee)
		require.Equal(t, "", clearedFees.OffchainInputFee)
		require.Equal(t, "", clearedFees.OnchainOutputFee)
		require.Equal(t, "", clearedFees.OffchainOutputFee)

		// set the fees back to newFees
		time.Sleep(10 * time.Millisecond)
		err = repo.UpdateIntentFees(ctx, newFees)
		require.NoError(t, err)

		updatedFees, err = repo.GetIntentFees(ctx)
		require.NoError(t, err)
		require.NotNil(t, updatedFees)
		require.Equal(t, newFees.OnchainInputFee, updatedFees.OnchainInputFee)
		require.Equal(t, newFees.OffchainInputFee, updatedFees.OffchainInputFee)
		require.Equal(t, newFees.OnchainOutputFee, updatedFees.OnchainOutputFee)
		require.Equal(t, newFees.OffchainOutputFee, updatedFees.OffchainOutputFee)

		// only change 2 of the fees, the others should remain the same (testing partial updates)
		newFees = domain.IntentFees{
			OnchainInputFee:   "0.25",
			OffchainOutputFee: "0.40",
		}
		time.Sleep(10 * time.Millisecond)
		err = repo.UpdateIntentFees(ctx, newFees)
		require.NoError(t, err)

		updatedFees, err = repo.GetIntentFees(ctx)
		require.NoError(t, err)
		require.NotNil(t, updatedFees)
		require.Equal(t, newFees.OnchainInputFee, updatedFees.OnchainInputFee)
		require.Equal(t, "0.30", updatedFees.OffchainInputFee)
		require.Equal(t, "0.35", updatedFees.OnchainOutputFee)
		require.Equal(t, newFees.OffchainOutputFee, updatedFees.OffchainOutputFee)

		// test that updating with no fees yields an error and does not change existing fees
		newFees = domain.IntentFees{}
		time.Sleep(10 * time.Millisecond)
		err = repo.UpdateIntentFees(ctx, newFees)
		require.Error(t, err)

		updatedFees, err = repo.GetIntentFees(ctx)
		require.NoError(t, err)
		require.NotNil(t, updatedFees)
		require.Equal(t, "0.25", updatedFees.OnchainInputFee)
		require.Equal(t, "0.30", updatedFees.OffchainInputFee)
		require.Equal(t, "0.35", updatedFees.OnchainOutputFee)
		require.Equal(t, "0.40", updatedFees.OffchainOutputFee)

		// zero out the fees
		err = repo.ClearIntentFees(ctx)
		require.NoError(t, err)

		// do partial update after clearing to ensure fees are set correctly from zero state
		newFees = domain.IntentFees{
			OnchainInputFee:  "0.15",
			OffchainInputFee: "0.20",
		}
		time.Sleep(10 * time.Millisecond)
		err = repo.UpdateIntentFees(ctx, newFees)
		require.NoError(t, err)

		updatedFees, err = repo.GetIntentFees(ctx)
		require.NoError(t, err)
		require.NotNil(t, updatedFees)
		require.Equal(t, newFees.OnchainInputFee, updatedFees.OnchainInputFee)
		require.Equal(t, newFees.OffchainInputFee, updatedFees.OffchainInputFee)
		require.Equal(t, "", updatedFees.OnchainOutputFee)
		require.Equal(t, "", updatedFees.OffchainOutputFee)
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
		require.Exactly(t, expected.Depth, v.Depth)
		require.ElementsMatch(t, expected.CommitmentTxids, v.CommitmentTxids)
	}
}
