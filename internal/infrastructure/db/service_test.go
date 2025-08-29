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
			testMarketHourRepository(t, svc)
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
				Timestamp:         now.Add(60 * time.Second).Unix(),
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
	})
}

func testVtxoRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_vtxo_repository", func(t *testing.T) {
		ctx := context.Background()

		userVtxos := []domain.Vtxo{
			{
				Outpoint: domain.Outpoint{
					Txid: randomString(32),
					VOut: 0,
				},
				PubKey:             pubkey,
				Amount:             1000,
				RootCommitmentTxid: "root",
				CommitmentTxids:    []string{"root", "cmt1", "cmt2"},
				Preconfirmed:       true,
			},
			{
				Outpoint: domain.Outpoint{
					Txid: randomString(32),
					VOut: 1,
				},
				PubKey:             pubkey,
				Amount:             2000,
				RootCommitmentTxid: "root",
				CommitmentTxids:    []string{"root"},
			},
		}
		newVtxos := append(userVtxos, domain.Vtxo{
			Outpoint: domain.Outpoint{
				Txid: randomString(32),
				VOut: 1,
			},
			PubKey:             pubkey2,
			Amount:             2000,
			RootCommitmentTxid: "root",
			CommitmentTxids:    []string{"root"},
		})
		arkTxid := randomString(32)
		commitmentTxid := randomString(32)

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
	})
}

func testMarketHourRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_market_hour_repository", func(t *testing.T) {
		ctx := context.Background()
		repo := svc.MarketHourRepo()

		marketHour, err := repo.Get(ctx)
		require.NoError(t, err)
		require.Nil(t, marketHour)

		now := time.Now().Truncate(time.Second)
		expected := domain.MarketHour{
			StartTime:     now,
			Period:        time.Duration(3) * time.Hour,
			RoundInterval: time.Duration(20) * time.Second,
			UpdatedAt:     now,
		}

		err = repo.Upsert(ctx, expected)
		require.NoError(t, err)

		got, err := repo.Get(ctx)
		require.NoError(t, err)
		require.NotNil(t, got)
		assertMarketHourEqual(t, expected, *got)

		expected.Period = time.Duration(4) * time.Hour
		expected.RoundInterval = time.Duration(40) * time.Second
		expected.UpdatedAt = now.Add(100 * time.Second)

		err = repo.Upsert(ctx, expected)
		require.NoError(t, err)

		got, err = repo.Get(ctx)
		require.NoError(t, err)
		require.NotNil(t, got)
		assertMarketHourEqual(t, expected, *got)
	})
}

func testOffchainTxRepository(t *testing.T, svc ports.RepoManager) {
	t.Run("test_offchain_tx_repository", func(t *testing.T) {
		ctx := context.Background()
		repo := svc.OffchainTxs()

		offchainTx, err := repo.GetOffchainTx(ctx, arkTxid)
		require.Error(t, err)
		require.Nil(t, offchainTx)

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

func assertMarketHourEqual(t *testing.T, expected, actual domain.MarketHour) {
	assert.True(t, expected.StartTime.Equal(actual.StartTime), "StartTime not equal")
	assert.Equal(t, expected.Period, actual.Period, "Period not equal")
	assert.Equal(t, expected.RoundInterval, actual.RoundInterval, "RoundInterval not equal")
	assert.True(t, expected.UpdatedAt.Equal(actual.UpdatedAt), "UpdatedAt not equal")
	assert.True(t, expected.EndTime.Equal(actual.EndTime), "EndTime not equal")
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
