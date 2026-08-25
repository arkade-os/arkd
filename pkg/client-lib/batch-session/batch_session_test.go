package batchsession_test

import (
	"context"
	"errors"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsession "github.com/arkade-os/arkd/pkg/client-lib/batch-session"
	"github.com/stretchr/testify/require"
)

func TestJoinBatch(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*batchsession.JoinBatchArgs)
			errSubstr string
		}{
			{
				name:      "missing client",
				mutate:    func(a *batchsession.JoinBatchArgs) { a.Client = nil },
				errSubstr: "missing client",
			},
			{
				name: "missing funds",
				mutate: func(a *batchsession.JoinBatchArgs) {
					a.Vtxos = nil
					a.BoardingUtxos = nil
					a.Notes = nil
				},
				errSubstr: "missing funds to join a batch",
			},
			{
				name:      "missing outputs",
				mutate:    func(a *batchsession.JoinBatchArgs) { a.Outputs = nil },
				errSubstr: "missing outputs",
			},
			{
				name:      "missing intent id",
				mutate:    func(a *batchsession.JoinBatchArgs) { a.IntentId = "" },
				errSubstr: "missing intent id",
			},
			{
				name:      "missing tree signers",
				mutate:    func(a *batchsession.JoinBatchArgs) { a.TreeSigners = nil },
				errSubstr: "missing tree signer(s)",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestJoinBatchArgs(t)
				tc.mutate(&args)

				_, err := batchsession.JoinBatch(t.Context(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})

	t.Run("valid", func(t *testing.T) {
		// This test ensures JoinBatch sends all events to the replay channel before this
		// gets closed by the listener/owner.
		t.Run("event channel close safe", func(t *testing.T) {
			const (
				iterations = 50
				burst      = 256
			)

			errStop := errors.New("stop the session")

			for i := 0; i < iterations; i++ {
				// Buffer everything up front so JoinBatch races through the
				// whole burst in a tight loop, then returns — maximising the
				// number of replay forwards in flight when the caller closes
				// below.
				eventsCh := make(chan clientlib.BatchEventChannel, burst+1)
				replayCh := make(chan any, burst)

				// At the initial step, a TreeTxEvent makes the handler loop
				// forward to the replay channel and then `continue` without
				// invoking the handler. An Err event then returns from JoinBatch.
				for j := 0; j < burst; j++ {
					eventsCh <- clientlib.BatchEventChannel{Event: clientlib.TreeTxEvent{}}
				}
				eventsCh <- clientlib.BatchEventChannel{Err: errStop}

				// The source event stream is injected via a mock client whose
				// GetEventStream returns the pre-loaded channel.
				args := newTestJoinBatchArgs(t)
				args.Client = mockEventStreamClient{events: eventsCh}

				errCh := make(chan error, 1)
				go func() {
					_, err := batchsession.JoinBatch(
						t.Context(), args,
						batchsession.WithEventsCh(replayCh),
						batchsession.WithHandler(noopBatchHandler{}),
					)
					errCh <- err
				}()

				require.ErrorIs(t, <-errCh, errStop)

				// The caller closes the replay channel it owns once the session
				// has returned. This must be safe: no forwarder may still be
				// running.
				close(replayCh)
			}
		})
	})
}

// newTestJoinBatchArgs returns a valid baseline JoinBatchArgs. Tests in this
// file mutate a single field on the returned value to exercise the
// corresponding validation error.
func newTestJoinBatchArgs(t *testing.T) batchsession.JoinBatchArgs {
	t.Helper()
	signer, err := tree.NewVtxoTreeSigner()
	require.NoError(t, err)
	return batchsession.JoinBatchArgs{
		BaseArgs: batchsession.BaseArgs{
			Vtxos: []clientlib.Vtxo{{
				Outpoint: clientlib.Outpoint{Txid: "deadbeef", VOut: 0},
				Amount:   10000,
			}},
			Outputs: []clientlib.Receiver{{To: "tark1qexample", Amount: 10000}},
			SignTx:  clientlib.SignFn(mockSignTx),
		},
		Client:       mockClient{},
		ServerParams: clientlib.ServerParams{Network: arklib.BitcoinRegTest, Dust: 1000},
		IntentId:     "test-intent-id",
		TreeSigners:  []tree.SignerSession{signer},
	}
}

// mockEventStreamClient injects a caller-controlled batch event stream. Only
// GetEventStream is exercised; every other Client method comes from the nil
// embedded interface and must not be called.
type mockEventStreamClient struct {
	clientlib.Client
	events <-chan clientlib.BatchEventChannel
}

func (m mockEventStreamClient) GetEventStream(
	context.Context, []string,
) (<-chan clientlib.BatchEventChannel, func(), error) {
	return m.events, func() {}, nil
}

// noopBatchHandler satisfies the batch-session Handler so JoinBatch can be
// driven directly in tests. Its methods are never reached by the "event
// channel close safe" test (the events used there either continue before the
// handler call or terminate the loop via an error).
type noopBatchHandler struct{}

func (noopBatchHandler) OnBatchStarted(
	context.Context, clientlib.BatchStartedEvent,
) (bool, time.Duration, error) {
	return false, 0, nil
}
func (noopBatchHandler) OnBatchFinalized(
	context.Context, clientlib.BatchFinalizedEvent,
) error {
	return nil
}
func (noopBatchHandler) OnBatchFailed(
	context.Context, clientlib.BatchFailedEvent,
) error {
	return nil
}
func (noopBatchHandler) OnTreeTxEvent(
	context.Context, clientlib.TreeTxEvent,
) error {
	return nil
}
func (noopBatchHandler) OnTreeSignatureEvent(
	context.Context, clientlib.TreeSignatureEvent,
) error {
	return nil
}
func (noopBatchHandler) OnTreeSigningStarted(
	context.Context, clientlib.TreeSigningStartedEvent, *tree.TxTree,
) (bool, error) {
	return false, nil
}
func (noopBatchHandler) OnTreeNoncesAggregated(
	context.Context, clientlib.TreeNoncesAggregatedEvent,
) (bool, error) {
	return false, nil
}
func (noopBatchHandler) OnTreeNonces(
	context.Context, clientlib.TreeNoncesEvent,
) (bool, error) {
	return false, nil
}
func (noopBatchHandler) OnBatchFinalization(
	context.Context, clientlib.BatchFinalizationEvent, *tree.TxTree,
	*tree.TxTree,
) ([]string, error) {
	return nil, nil
}
func (noopBatchHandler) OnStreamStarted(
	context.Context, clientlib.StreamStartedEvent,
) error {
	return nil
}
