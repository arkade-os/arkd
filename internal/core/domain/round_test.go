package domain_test

import (
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/stretchr/testify/require"
)

var (
	intents = []domain.Intent{
		{
			Id:      "0",
			Proof:   "proof",
			Message: "message",
			Inputs: []domain.Vtxo{
				{
					Outpoint: domain.Outpoint{
						Txid: txid,
						VOut: 0,
					},
					PubKey:             pubkey,
					Amount:             2000,
					CommitmentTxids:    []string{txid},
					RootCommitmentTxid: txid,
				},
			},
			Receivers: []domain.Receiver{
				{
					PubKey: pubkey,
					Amount: 700,
				},
				{
					PubKey: pubkey,
					Amount: 700,
				},
				{
					PubKey: pubkey,
					Amount: 600,
				},
			},
		},
		{
			Id:      "1",
			Proof:   "proof",
			Message: "message",
			Inputs: []domain.Vtxo{
				{
					Outpoint: domain.Outpoint{
						Txid: txid,
						VOut: 0,
					},
					PubKey:             pubkey,
					Amount:             1000,
					CommitmentTxids:    []string{txid},
					RootCommitmentTxid: txid,
				},
				{
					Outpoint: domain.Outpoint{
						Txid: txid,
						VOut: 0,
					},
					PubKey:             pubkey,
					Amount:             1000,
					CommitmentTxids:    []string{txid},
					RootCommitmentTxid: txid,
				},
			},
			Receivers: []domain.Receiver{{
				PubKey: pubkey,
				Amount: 2000,
			}},
		},
	}
	emptyPtx       = "cHNldP8BAgQCAAAAAQQBAAEFAQABBgEDAfsEAgAAAAA="
	emptyTx        = "0200000000000000000000"
	txid           = "0000000000000000000000000000000000000000000000000000000000000000"
	emptyForfeitTx = domain.ForfeitTx{
		Txid: txid,
		Tx:   emptyPtx,
	}
	vtxoTree = tree.FlatTxTree{
		{
			Txid: txid,
			Tx:   emptyPtx,
			Children: map[uint32]string{
				0: txid,
			},
		},
		{
			Txid: txid,
			Tx:   emptyPtx,
			Children: map[uint32]string{
				0: txid,
				1: txid,
			},
		},
		{
			Txid:     txid,
			Tx:       emptyPtx,
			Children: nil,
		},
		{
			Txid:     txid,
			Tx:       emptyPtx,
			Children: nil,
		},
	}
	connectors = tree.FlatTxTree{
		{
			Txid: txid,
			Tx:   emptyPtx,
			Children: map[uint32]string{
				0: txid,
			},
		},
		{
			Txid: txid,
			Tx:   emptyPtx,
			Children: map[uint32]string{
				0: txid,
			},
		},
		{
			Txid:     txid,
			Tx:       emptyPtx,
			Children: nil,
		},
	}
	forfeitTxs = []domain.ForfeitTx{
		emptyForfeitTx, emptyForfeitTx, emptyForfeitTx, emptyForfeitTx, emptyForfeitTx,
		emptyForfeitTx, emptyForfeitTx, emptyForfeitTx, emptyForfeitTx,
	}
	commitmentTx      = emptyTx
	finalCommitmentTx = emptyTx
	expiration        = int64(600) // seconds
)

func TestRound(t *testing.T) {
	testStartRegistration(t)

	testRegisterIntents(t)

	testStartFinalization(t)

	testEndFinalization(t)

	testSweep(t)

	testFail(t)
}

func testStartRegistration(t *testing.T) {
	t.Run("start_registration", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			round := domain.NewRound()
			require.NotNil(t, round)
			require.NotEmpty(t, round.Id)
			require.Empty(t, round.Events())
			require.False(t, round.IsStarted())
			require.False(t, round.IsEnded())
			require.False(t, round.IsFailed())

			events, err := round.StartRegistration()
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.True(t, round.IsStarted())
			require.False(t, round.IsEnded())
			require.False(t, round.IsFailed())

			event, ok := events[0].(domain.RoundStarted)
			require.True(t, ok)
			require.Equal(t, domain.EventTypeRoundStarted, event.Type)
			require.Equal(t, round.Id, event.Id)
			require.Equal(t, round.StartingTimestamp, event.Timestamp)
		})

		t.Run("invalid", func(t *testing.T) {
			fixtures := []struct {
				round       *domain.Round
				expectedErr string
			}{
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code:   int(domain.RoundUndefinedStage),
							Failed: true,
						},
					},
					expectedErr: "not in a valid stage to start intents registration",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: int(domain.RoundRegistrationStage),
						},
					},
					expectedErr: "not in a valid stage to start intents registration",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: int(domain.RoundFinalizationStage),
						},
					},
					expectedErr: "not in a valid stage to start intents registration",
				},
			}

			for _, f := range fixtures {
				events, err := f.round.StartRegistration()
				require.EqualError(t, err, f.expectedErr)
				require.Empty(t, events)
			}
		})
	})
}

func testRegisterIntents(t *testing.T) {
	t.Run("register_intents", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			round := domain.NewRound()
			events, err := round.StartRegistration()
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.RegisterIntents(intents)
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.Condition(t, func() bool {
				for _, intent := range intents {
					_, ok := round.Intents[intent.Id]
					if !ok {
						return false
					}
				}
				return true
			})

			event, ok := events[0].(domain.IntentsRegistered)
			require.True(t, ok)
			require.Equal(t, domain.EventTypeIntentsRegistered, event.Type)
			require.Equal(t, round.Id, event.Id)
			require.Equal(t, intents, event.Intents)
		})

		t.Run("invalid", func(t *testing.T) {
			fixtures := []struct {
				round       *domain.Round
				intents     []domain.Intent
				expectedErr string
			}{
				{
					round: &domain.Round{
						Id:    "id",
						Stage: domain.Stage{},
					},
					intents:     intents,
					expectedErr: "not in a valid stage to register intents",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code:   int(domain.RoundRegistrationStage),
							Failed: true,
						},
					},
					intents:     intents,
					expectedErr: "not in a valid stage to register intents",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: int(domain.RoundFinalizationStage),
						},
					},
					intents:     intents,
					expectedErr: "not in a valid stage to register intents",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: int(domain.RoundRegistrationStage),
						},
					},
					intents:     nil,
					expectedErr: "missing intents to register",
				},
			}

			for _, f := range fixtures {
				events, err := f.round.RegisterIntents(f.intents)
				require.EqualError(t, err, f.expectedErr)
				require.Empty(t, events)
			}
		})
	})
}

func testStartFinalization(t *testing.T) {
	t.Run("start_finalization", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			round := domain.NewRound()
			events, err := round.StartRegistration()
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.RegisterIntents(intents)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.StartFinalization(
				"", connectors, vtxoTree, "txid", commitmentTx, expiration,
			)
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.True(t, round.IsStarted())
			require.False(t, round.IsEnded())
			require.False(t, round.IsFailed())

			event, ok := events[0].(domain.RoundFinalizationStarted)
			require.True(t, ok)
			require.Equal(t, domain.EventTypeRoundFinalizationStarted, event.Type)
			require.Equal(t, round.Id, event.Id)
			require.Exactly(t, connectors, event.Connectors)
			require.Exactly(t, vtxoTree, event.VtxoTree)
			require.Exactly(t, commitmentTx, event.CommitmentTx)
		})

		t.Run("invalid", func(t *testing.T) {
			intentsById := map[string]domain.Intent{}
			for _, p := range intents {
				intentsById[p.Id] = p
			}
			fixtures := []struct {
				round        *domain.Round
				connectors   tree.FlatTxTree
				tree         tree.FlatTxTree
				txid         string
				commitmentTx string
				expiration   int64
				expectedErr  string
			}{
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: int(domain.RoundRegistrationStage),
						},
						Intents: intentsById,
					},
					connectors:   connectors,
					tree:         vtxoTree,
					expiration:   expiration,
					commitmentTx: "",
					expectedErr:  "missing unsigned commitment tx",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: int(domain.RoundRegistrationStage),
						},
						Intents: intentsById,
					},
					connectors:   connectors,
					tree:         vtxoTree,
					commitmentTx: commitmentTx,
					expectedErr:  "missing vtxo tree expiration",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: int(domain.RoundRegistrationStage),
						},
						Intents: nil,
					},
					connectors:   connectors,
					tree:         vtxoTree,
					expiration:   expiration,
					commitmentTx: commitmentTx,
					expectedErr:  "no intents registered",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: int(domain.RoundUndefinedStage),
						},
						Intents: intentsById,
					},
					connectors:   connectors,
					tree:         vtxoTree,
					expiration:   expiration,
					commitmentTx: commitmentTx,
					expectedErr:  "not in a valid stage to start finalization",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code:   int(domain.RoundRegistrationStage),
							Failed: true,
						},
						Intents: intentsById,
					},
					connectors:   connectors,
					tree:         vtxoTree,
					expiration:   expiration,
					commitmentTx: commitmentTx,
					expectedErr:  "not in a valid stage to start finalization",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: int(domain.RoundFinalizationStage),
						},
						Intents: intentsById,
					},
					connectors:   connectors,
					tree:         vtxoTree,
					expiration:   expiration,
					txid:         "txid",
					commitmentTx: commitmentTx,
					expectedErr:  "not in a valid stage to start finalization",
				},
			}

			for _, f := range fixtures {
				events, err := f.round.StartFinalization(
					"", f.connectors, f.tree, f.txid, f.commitmentTx, f.expiration,
				)
				require.EqualError(t, err, f.expectedErr)
				require.Empty(t, events)
			}
		})
	})
}

func testEndFinalization(t *testing.T) {
	t.Run("end_finalization", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			round := domain.NewRound()
			events, err := round.StartRegistration()
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.RegisterIntents(intents)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.StartFinalization(
				"",
				connectors,
				vtxoTree,
				"txid",
				commitmentTx,
				expiration,
			)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.EndFinalization(forfeitTxs, finalCommitmentTx)
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.False(t, round.IsStarted())
			require.True(t, round.IsEnded())
			require.False(t, round.IsFailed())

			event, ok := events[0].(domain.RoundFinalized)
			require.True(t, ok)
			require.Equal(t, domain.EventTypeRoundFinalized, event.Type)
			require.Equal(t, round.Id, event.Id)
			require.Exactly(t, forfeitTxs, event.ForfeitTxs)
			require.Exactly(t, round.EndingTimestamp, event.Timestamp)
		})

		t.Run("invalid", func(t *testing.T) {
			intentsById := map[string]domain.Intent{}
			for _, p := range intents {
				intentsById[p.Id] = p
			}
			fixtures := []struct {
				round       *domain.Round
				forfeitTxs  []domain.ForfeitTx
				expectedErr string
			}{
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: int(domain.RoundFinalizationStage),
						},
						Intents: intentsById,
					},
					forfeitTxs:  nil,
					expectedErr: "missing list of signed forfeit txs",
				},
				{
					round: &domain.Round{
						Id: "0",
					},
					forfeitTxs:  forfeitTxs,
					expectedErr: "not in a valid stage to end finalization",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: int(domain.RoundRegistrationStage),
						},
					},
					forfeitTxs:  forfeitTxs,
					expectedErr: "not in a valid stage to end finalization",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code:   int(domain.RoundFinalizationStage),
							Failed: true,
						},
					},
					forfeitTxs: []domain.ForfeitTx{
						emptyForfeitTx,
						emptyForfeitTx,
						emptyForfeitTx,
						emptyForfeitTx,
					},
					expectedErr: "not in a valid stage to end finalization",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code:  int(domain.RoundFinalizationStage),
							Ended: true,
						},
					},
					forfeitTxs: []domain.ForfeitTx{
						emptyForfeitTx,
						emptyForfeitTx,
						emptyForfeitTx,
						emptyForfeitTx,
					},
					expectedErr: "round already finalized",
				},
			}

			for _, f := range fixtures {
				events, err := f.round.EndFinalization(f.forfeitTxs, finalCommitmentTx)
				require.EqualError(t, err, f.expectedErr)
				require.Empty(t, events)
			}
		})
	})
}

func testSweep(t *testing.T) {
	t.Run("sweep", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			round := domain.NewRound()
			events, err := round.StartRegistration()
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.RegisterIntents(intents)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.StartFinalization(
				"",
				connectors,
				vtxoTree,
				"txid",
				commitmentTx,
				expiration,
			)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.EndFinalization(forfeitTxs, finalCommitmentTx)
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.False(t, round.IsStarted())
			require.True(t, round.IsEnded())
			require.False(t, round.IsFailed())

			vtxos := leavesToVtxos(tree.FlatTxTree(vtxoTree).Leaves())
			events, err = round.Sweep(vtxos, "sweepTxid", emptyPtx)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			event, ok := events[0].(domain.BatchSwept)
			require.True(t, ok)
			require.Equal(t, domain.EventTypeBatchSwept, event.Type)
			require.Equal(t, round.Id, event.Id)
			require.Exactly(t, vtxos, event.Vtxos)
			require.Equal(t, "sweepTxid", event.Txid)
			require.Equal(t, emptyPtx, event.Tx)
			require.True(t, event.FullySwept)
			require.True(t, round.Swept)
			require.Equal(t, round.SweepTxs["sweepTxid"], emptyPtx)
		})
	})
}

func testFail(t *testing.T) {
	t.Run("fail", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			round := domain.NewRound()
			events, err := round.StartRegistration()
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.RegisterIntents(intents)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			reason := fmt.Errorf("some valid reason")
			events = round.Fail(reason)
			require.Len(t, events, 1)
			require.False(t, round.IsStarted())
			require.False(t, round.IsEnded())
			require.True(t, round.IsFailed())

			event, ok := events[0].(domain.RoundFailed)
			require.True(t, ok)
			require.Equal(t, domain.EventTypeRoundFailed, event.Type)
			require.Exactly(t, round.Id, event.Id)
			require.Exactly(t, round.EndingTimestamp, event.Timestamp)
			require.EqualError(t, reason, event.Reason)

			events = round.Fail(reason)
			require.Empty(t, events)
		})
	})
}

func leavesToVtxos(leaves tree.FlatTxTree) []domain.Outpoint {
	var vtxos []domain.Outpoint
	for _, leaf := range leaves {
		vtxos = append(vtxos, domain.Outpoint{
			Txid: leaf.Txid,
			VOut: 0,
		})
	}
	return vtxos
}
