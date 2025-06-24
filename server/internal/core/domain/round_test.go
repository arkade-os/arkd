package domain_test

import (
	"fmt"
	"testing"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/stretchr/testify/require"
)

var (
	requests = []domain.TxRequest{
		{
			Id: "0",
			Inputs: []domain.Vtxo{
				{
					VtxoKey: domain.VtxoKey{
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
			Id: "1",
			Inputs: []domain.Vtxo{
				{
					VtxoKey: domain.VtxoKey{
						Txid: txid,
						VOut: 0,
					},
					PubKey:             pubkey,
					Amount:             1000,
					CommitmentTxids:    []string{txid},
					RootCommitmentTxid: txid,
				},
				{
					VtxoKey: domain.VtxoKey{
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
	vtxoTree = []tree.TxGraphChunk{
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
			Children: map[uint32]string{},
		},
		{
			Txid:     txid,
			Tx:       emptyPtx,
			Children: map[uint32]string{},
		},
	}
	connectors = []tree.TxGraphChunk{
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
			Children: map[uint32]string{},
		},
	}
	forfeitTxs = []domain.ForfeitTx{
		emptyForfeitTx, emptyForfeitTx, emptyForfeitTx, emptyForfeitTx, emptyForfeitTx,
		emptyForfeitTx, emptyForfeitTx, emptyForfeitTx, emptyForfeitTx,
	}
	roundTx      = emptyTx
	finalRoundTx = emptyTx
	expiration   = int64(600) // seconds
)

func TestRound(t *testing.T) {
	testStartRegistration(t)

	testRegisterTxRequests(t)

	testStartFinalization(t)

	testEndFinalization(t)

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
					expectedErr: "not in a valid stage to start tx requests registration",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: int(domain.RoundRegistrationStage),
						},
					},
					expectedErr: "not in a valid stage to start tx requests registration",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: int(domain.RoundFinalizationStage),
						},
					},
					expectedErr: "not in a valid stage to start tx requests registration",
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

func testRegisterTxRequests(t *testing.T) {
	t.Run("register_tx_requests", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			round := domain.NewRound()
			events, err := round.StartRegistration()
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.RegisterTxRequests(requests)
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.Condition(t, func() bool {
				for _, request := range requests {
					_, ok := round.TxRequests[request.Id]
					if !ok {
						return false
					}
				}
				return true
			})

			event, ok := events[0].(domain.TxRequestsRegistered)
			require.True(t, ok)
			require.Equal(t, domain.EventTypeTxRequestsRegistered, event.Type)
			require.Equal(t, round.Id, event.Id)
			require.Equal(t, requests, event.TxRequests)
		})

		t.Run("invalid", func(t *testing.T) {
			fixtures := []struct {
				round       *domain.Round
				requests    []domain.TxRequest
				expectedErr string
			}{
				{
					round: &domain.Round{
						Id:    "id",
						Stage: domain.Stage{},
					},
					requests:    requests,
					expectedErr: "not in a valid stage to register tx requests",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code:   int(domain.RoundRegistrationStage),
							Failed: true,
						},
					},
					requests:    requests,
					expectedErr: "not in a valid stage to register tx requests",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: int(domain.RoundFinalizationStage),
						},
					},
					requests:    requests,
					expectedErr: "not in a valid stage to register tx requests",
				},
				{
					round: &domain.Round{
						Id: "id",
						Stage: domain.Stage{
							Code: int(domain.RoundRegistrationStage),
						},
					},
					requests:    nil,
					expectedErr: "missing tx requests to register",
				},
			}

			for _, f := range fixtures {
				events, err := f.round.RegisterTxRequests(f.requests)
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

			events, err = round.RegisterTxRequests(requests)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.StartFinalization("", connectors, vtxoTree, "txid", roundTx, map[string]domain.Outpoint{
				txid: {
					Txid: txid,
					VOut: 0,
				},
			}, expiration)
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
			require.Exactly(t, roundTx, event.RoundTx)
		})

		t.Run("invalid", func(t *testing.T) {
			requestsById := map[string]domain.TxRequest{}
			for _, p := range requests {
				requestsById[p.Id] = p
			}
			fixtures := []struct {
				round       *domain.Round
				connectors  []tree.TxGraphChunk
				tree        []tree.TxGraphChunk
				txid        string
				roundTx     string
				expiration  int64
				expectedErr string
			}{
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: int(domain.RoundRegistrationStage),
						},
						TxRequests: requestsById,
					},
					connectors:  connectors,
					tree:        vtxoTree,
					expiration:  expiration,
					roundTx:     "",
					expectedErr: "missing unsigned round tx",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: int(domain.RoundRegistrationStage),
						},
						TxRequests: requestsById,
					},
					connectors:  connectors,
					tree:        vtxoTree,
					roundTx:     roundTx,
					expectedErr: "missing vtxo tree expiration",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: int(domain.RoundRegistrationStage),
						},
						TxRequests: nil,
					},
					connectors:  connectors,
					tree:        vtxoTree,
					expiration:  expiration,
					roundTx:     roundTx,
					expectedErr: "no tx requests registered",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: int(domain.RoundUndefinedStage),
						},
						TxRequests: requestsById,
					},
					connectors:  connectors,
					tree:        vtxoTree,
					expiration:  expiration,
					roundTx:     roundTx,
					expectedErr: "not in a valid stage to start finalization",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code:   int(domain.RoundRegistrationStage),
							Failed: true,
						},
						TxRequests: requestsById,
					},
					connectors:  connectors,
					tree:        vtxoTree,
					expiration:  expiration,
					roundTx:     roundTx,
					expectedErr: "not in a valid stage to start finalization",
				},
				{
					round: &domain.Round{
						Id: "0",
						Stage: domain.Stage{
							Code: int(domain.RoundFinalizationStage),
						},
						TxRequests: requestsById,
					},
					connectors:  connectors,
					tree:        vtxoTree,
					expiration:  expiration,
					txid:        "txid",
					roundTx:     roundTx,
					expectedErr: "not in a valid stage to start finalization",
				},
			}

			for _, f := range fixtures {
				events, err := f.round.StartFinalization("", f.connectors, f.tree, f.txid, f.roundTx, map[string]domain.Outpoint{
					txid: {
						Txid: txid,
						VOut: 0,
					},
				}, f.expiration)
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

			events, err = round.RegisterTxRequests(requests)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.StartFinalization("", connectors, vtxoTree, "txid", roundTx, map[string]domain.Outpoint{
				txid: {
					Txid: txid,
					VOut: 0,
				},
			}, expiration)
			require.NoError(t, err)
			require.NotEmpty(t, events)

			events, err = round.EndFinalization(forfeitTxs, finalRoundTx)
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
			requestsById := map[string]domain.TxRequest{}
			for _, p := range requests {
				requestsById[p.Id] = p
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
						TxRequests: requestsById,
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
					forfeitTxs:  []domain.ForfeitTx{emptyForfeitTx, emptyForfeitTx, emptyForfeitTx, emptyForfeitTx},
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
					forfeitTxs:  []domain.ForfeitTx{emptyForfeitTx, emptyForfeitTx, emptyForfeitTx, emptyForfeitTx},
					expectedErr: "round already finalized",
				},
			}

			for _, f := range fixtures {
				events, err := f.round.EndFinalization(f.forfeitTxs, finalRoundTx)
				require.EqualError(t, err, f.expectedErr)
				require.Empty(t, events)
			}
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

			events, err = round.RegisterTxRequests(requests)
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
			require.EqualError(t, reason, event.Err)

			events = round.Fail(reason)
			require.Empty(t, events)
		})
	})
}
