package domain_test

import (
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

var (
	onchainTx       = signedPtx
	onchainTxInputs = []domain.Outpoint{
		{
			Txid: "0000000000000000000000000000000000000000000000000000000000000000",
			VOut: 0,
		},
		{
			Txid: "0000000000000000000000000000000000000000000000000000000000000001",
			VOut: 1,
		},
	}
	onchainConfirmedAtTime   = int64(1700000000)
	onchainConfirmedAtHeight = uint64(100)
	// The signed inputs as the aggregate and its events index them.
	onchainTxSignedInputs = map[string]struct{}{
		onchainTxInputs[0].String(): {},
		onchainTxInputs[1].String(): {},
	}
)

func TestOnchainTx(t *testing.T) {
	testBroadcastOnchainTx(t)

	testConfirmOnchainTx(t)

	testReplayOnchainTxEvents(t)
}

func testBroadcastOnchainTx(t *testing.T) {
	t.Run("broadcast", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			tx := domain.NewOnchainTx()
			require.NotNil(t, tx)
			require.Empty(t, tx.Events())
			require.False(t, tx.IsBroadcasted())
			require.False(t, tx.IsConfirmed())

			event, err := tx.Broadcast(txid, onchainTx, onchainTxInputs)
			require.NoError(t, err)
			require.NotNil(t, event)
			require.Equal(t, domain.EventTypeOnchainTxBroadcasted, event.GetType())
			require.Equal(t, domain.OnchainTxTopic, event.GetTopic())
			require.True(t, tx.IsBroadcasted())
			require.False(t, tx.IsConfirmed())
			require.False(t, tx.Stage.Ended)
			require.Equal(t, txid, tx.Txid)
			require.Equal(t, onchainTx, tx.Tx)
			require.Equal(t, onchainTxSignedInputs, tx.SignedInputs)
			require.NotEmpty(t, tx.BroadcastedAt)
			require.Zero(t, tx.ConfirmedAtTime)
			require.Zero(t, tx.ConfirmedAtHeight)

			events := tx.Events()
			require.Len(t, events, 1)
			require.Equal(t, event, events[0])
			require.Equal(
				t, onchainTxSignedInputs, events[0].(domain.OnchainTxBroadcasted).SignedInputs,
			)

			// The aggregate doesn't share the map with the event in its history.
			tx.SignedInputs["tampered"] = struct{}{}
			require.NotContains(
				t, events[0].(domain.OnchainTxBroadcasted).SignedInputs, "tampered",
			)
		})

		t.Run("invalid", func(t *testing.T) {
			fixtures := []struct {
				onchainTx   *domain.OnchainTx
				txid        string
				tx          string
				inputs      []domain.Outpoint
				expectedErr string
			}{
				{
					onchainTx:   domain.NewOnchainTx(),
					tx:          onchainTx,
					inputs:      onchainTxInputs,
					expectedErr: "missing onchain txid",
				},
				{
					onchainTx:   domain.NewOnchainTx(),
					inputs:      onchainTxInputs,
					txid:        txid,
					expectedErr: "missing onchain tx",
				},
				{
					onchainTx:   domain.NewOnchainTx(),
					tx:          onchainTx,
					txid:        txid,
					expectedErr: "missing signed inputs",
				},
				{
					onchainTx: &domain.OnchainTx{
						Stage: domain.Stage{Code: int(domain.OnchainTxBroadcastedStage)},
					},
					txid:        txid,
					tx:          onchainTx,
					inputs:      onchainTxInputs,
					expectedErr: "not in a valid stage to sign and broadcast an onchain tx",
				},
				{
					onchainTx: &domain.OnchainTx{
						Stage: domain.Stage{Code: int(domain.OnchainTxConfirmedStage), Ended: true},
					},
					txid:        txid,
					tx:          onchainTx,
					inputs:      onchainTxInputs,
					expectedErr: "not in a valid stage to sign and broadcast an onchain tx",
				},
			}

			for _, f := range fixtures {
				event, err := f.onchainTx.Broadcast(f.txid, f.tx, f.inputs)
				require.EqualError(t, err, f.expectedErr)
				require.Nil(t, event)
				require.Empty(t, f.onchainTx.Events())
			}
		})
	})
}

func testConfirmOnchainTx(t *testing.T) {
	t.Run("confirm", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			tx := domain.NewOnchainTx()
			event, err := tx.Broadcast(txid, onchainTx, onchainTxInputs)
			require.NoError(t, err)
			require.NotNil(t, event)

			event, err = tx.Confirm(onchainConfirmedAtTime, onchainConfirmedAtHeight)
			require.NoError(t, err)
			require.NotNil(t, event)
			require.Equal(t, domain.EventTypeOnchainTxConfirmed, event.GetType())
			require.Equal(t, domain.OnchainTxTopic, event.GetTopic())
			require.False(t, tx.IsBroadcasted())
			require.True(t, tx.IsConfirmed())
			require.True(t, tx.Stage.Ended)
			require.Equal(t, txid, tx.Txid)
			require.Equal(t, onchainTx, tx.Tx)
			require.Equal(t, onchainTxSignedInputs, tx.SignedInputs)
			require.Equal(t, onchainConfirmedAtTime, tx.ConfirmedAtTime)
			require.Equal(t, onchainConfirmedAtHeight, tx.ConfirmedAtHeight)

			events := tx.Events()
			require.Len(t, events, 2)
			require.Equal(t, event, events[1])
			// The event is keyed by the txid of the broadcast tx.
			require.Equal(t, txid, events[1].(domain.OnchainTxConfirmed).Id)
		})

		t.Run("invalid", func(t *testing.T) {
			broadcasted := func() *domain.OnchainTx {
				tx := domain.NewOnchainTx()
				_, err := tx.Broadcast(txid, onchainTx, onchainTxInputs)
				require.NoError(t, err)
				return tx
			}
			confirmed := func() *domain.OnchainTx {
				tx := broadcasted()
				_, err := tx.Confirm(onchainConfirmedAtTime, onchainConfirmedAtHeight)
				require.NoError(t, err)
				return tx
			}

			fixtures := []struct {
				name        string
				onchainTx   *domain.OnchainTx
				time        int64
				height      uint64
				expectedErr string
			}{
				{
					name:        "not broadcasted yet",
					onchainTx:   domain.NewOnchainTx(),
					time:        onchainConfirmedAtTime,
					height:      onchainConfirmedAtHeight,
					expectedErr: "not in a valid stage to confirm an onchain tx",
				},
				{
					name:        "already confirmed",
					onchainTx:   confirmed(),
					time:        onchainConfirmedAtTime + 600,
					height:      onchainConfirmedAtHeight + 1,
					expectedErr: "not in a valid stage to confirm an onchain tx",
				},
				{
					name:        "missing time",
					onchainTx:   broadcasted(),
					height:      onchainConfirmedAtHeight,
					expectedErr: "missing confirmation time",
				},
				{
					name:        "negative time",
					onchainTx:   broadcasted(),
					time:        -1,
					height:      onchainConfirmedAtHeight,
					expectedErr: "missing confirmation time",
				},
				{
					name:        "missing height",
					onchainTx:   broadcasted(),
					time:        onchainConfirmedAtTime,
					expectedErr: "missing confirmation height",
				},
			}

			for _, f := range fixtures {
				t.Run(f.name, func(t *testing.T) {
					eventsBefore := len(f.onchainTx.Events())
					stageBefore := f.onchainTx.Stage

					event, err := f.onchainTx.Confirm(f.time, f.height)
					require.EqualError(t, err, f.expectedErr)
					require.Nil(t, event)
					// Nothing is raised and the tx is left as it was.
					require.Len(t, f.onchainTx.Events(), eventsBefore)
					require.Equal(t, stageBefore, f.onchainTx.Stage)
				})
			}
		})
	})
}

func testReplayOnchainTxEvents(t *testing.T) {
	t.Run("replay", func(t *testing.T) {
		broadcasted := domain.OnchainTxBroadcasted{
			OnchainTxEvent: domain.OnchainTxEvent{
				Id:   txid,
				Type: domain.EventTypeOnchainTxBroadcasted,
			},
			Tx:           onchainTx,
			SignedInputs: onchainTxSignedInputs,
			Timestamp:    onchainConfirmedAtTime - 600,
		}
		confirmed := domain.OnchainTxConfirmed{
			OnchainTxEvent: domain.OnchainTxEvent{
				Id:   txid,
				Type: domain.EventTypeOnchainTxConfirmed,
			},
			ConfirmedAtTime:   onchainConfirmedAtTime,
			ConfirmedAtHeight: onchainConfirmedAtHeight,
		}

		fixtures := []struct {
			name            string
			events          []domain.Event
			expectedVersion uint
			expectedStage   domain.Stage
			expectedTxid    string
			expectedTime    int64
			expectedHeight  uint64
		}{
			{
				name:            "broadcasted",
				events:          []domain.Event{broadcasted},
				expectedVersion: 1,
				expectedStage:   domain.Stage{Code: int(domain.OnchainTxBroadcastedStage)},
				expectedTxid:    txid,
			},
			{
				name:            "broadcasted and confirmed",
				events:          []domain.Event{broadcasted, confirmed},
				expectedVersion: 2,
				expectedStage: domain.Stage{
					Code: int(domain.OnchainTxConfirmedStage), Ended: true,
				},
				expectedTxid:   txid,
				expectedTime:   onchainConfirmedAtTime,
				expectedHeight: onchainConfirmedAtHeight,
			},
			{
				// A duplicated event is ignored and doesn't bump the version.
				name:            "duplicated broadcasted event",
				events:          []domain.Event{broadcasted, broadcasted},
				expectedVersion: 1,
				expectedStage:   domain.Stage{Code: int(domain.OnchainTxBroadcastedStage)},
				expectedTxid:    txid,
			},
			{
				name:            "duplicated confirmed event",
				events:          []domain.Event{broadcasted, confirmed, confirmed},
				expectedVersion: 2,
				expectedStage: domain.Stage{
					Code: int(domain.OnchainTxConfirmedStage), Ended: true,
				},
				expectedTxid:   txid,
				expectedTime:   onchainConfirmedAtTime,
				expectedHeight: onchainConfirmedAtHeight,
			},
			{
				// A confirmation for a tx never broadcasted is ignored.
				name:            "confirmed before broadcasted",
				events:          []domain.Event{confirmed},
				expectedVersion: 0,
				expectedStage:   domain.Stage{Code: int(domain.OnchainTxUndefinedStage)},
			},
			{
				// Out of order, the broadcast is applied and the confirmation is lost.
				name:            "confirmed then broadcasted",
				events:          []domain.Event{confirmed, broadcasted},
				expectedVersion: 1,
				expectedStage:   domain.Stage{Code: int(domain.OnchainTxBroadcastedStage)},
				expectedTxid:    txid,
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				tx := domain.NewOnchainTxFromEvents(f.events)
				require.NotNil(t, tx)
				require.Equal(t, f.expectedVersion, tx.Version)
				require.Equal(t, f.expectedStage, tx.Stage)
				require.Equal(t, f.expectedTxid, tx.Txid)
				// The signed inputs come with the broadcast, none without it.
				if f.expectedTxid != "" {
					require.Equal(t, onchainTxSignedInputs, tx.SignedInputs)
				} else {
					require.Empty(t, tx.SignedInputs)
				}
				require.Equal(t, f.expectedTime, tx.ConfirmedAtTime)
				require.Equal(t, f.expectedHeight, tx.ConfirmedAtHeight)
				// Replayed events are kept as the history of the tx.
				require.Equal(t, f.events, tx.Events())
			})
		}
	})
}
