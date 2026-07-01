package wallet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/stretchr/testify/require"
)

// TestJoinBatchSessionReplayCloseSafe is a regression test for the
// "panic: send on closed channel" fix during a collaborative exit.
//
// JoinBatchSession forwards every batch event to the caller-supplied
// WithReplay channel. The caller owns that channel and closes it once
// JoinBatchSession returns. If the forwarding runs in detached goroutines that
// can outlive the return, the caller's close() races an in-flight send and the
// process panics.
//
// The test drives a burst of forwarded events, terminates the session, then
// closes the replay channel exactly as a caller would. It must never panic:
// all forwards have to happen-before JoinBatchSession returns.
func TestJoinBatchSessionReplayCloseSafe(t *testing.T) {
	const (
		iterations = 50
		burst      = 256
	)

	errStop := errors.New("stop the session")

	for i := 0; i < iterations; i++ {
		// Buffer everything up front so JoinBatchSession races through the
		// whole burst in a tight loop, then returns — maximising the number
		// of replay forwards in flight when the caller closes below.
		eventsCh := make(chan client.BatchEventChannel, burst+1)
		replayCh := make(chan any, burst)

		// At the initial step, a TreeTxEvent makes the loop forward to the
		// replay channel and then `continue` without invoking the handler.
		// An Err event then returns from JoinBatchSession.
		for j := 0; j < burst; j++ {
			eventsCh <- client.BatchEventChannel{Event: client.TreeTxEvent{}}
		}
		eventsCh <- client.BatchEventChannel{Err: errStop}

		errCh := make(chan error, 1)
		go func() {
			_, _, _, _, _, err := JoinBatchSession(
				t.Context(), eventsCh, noopBatchHandler{}, WithReplay(replayCh),
			)
			errCh <- err
		}()

		require.ErrorIs(t, <-errCh, errStop)

		// The caller closes the replay channel it owns once the session has
		// returned. This must be safe: no forwarder may still be running.
		close(replayCh)
	}
}

// noopBatchHandler satisfies BatchEventsHandler so JoinBatchSession can be
// driven directly in tests. Its methods are never reached by
// TestJoinBatchSessionReplayCloseSafe (the events used there either continue
// before the handler call or terminate the loop via an error).
type noopBatchHandler struct{}

func (noopBatchHandler) OnBatchStarted(
	context.Context, client.BatchStartedEvent,
) (bool, time.Duration, error) {
	return false, 0, nil
}
func (noopBatchHandler) OnBatchFinalized(
	context.Context, client.BatchFinalizedEvent,
) error {
	return nil
}
func (noopBatchHandler) OnBatchFailed(
	context.Context, client.BatchFailedEvent,
) error {
	return nil
}
func (noopBatchHandler) OnTreeTxEvent(
	context.Context, client.TreeTxEvent,
) error {
	return nil
}
func (noopBatchHandler) OnTreeSignatureEvent(
	context.Context, client.TreeSignatureEvent,
) error {
	return nil
}
func (noopBatchHandler) OnTreeSigningStarted(
	context.Context, client.TreeSigningStartedEvent, *tree.TxTree,
) (bool, error) {
	return false, nil
}
func (noopBatchHandler) OnTreeNoncesAggregated(
	context.Context, client.TreeNoncesAggregatedEvent,
) (bool, error) {
	return false, nil
}
func (noopBatchHandler) OnTreeNonces(
	context.Context, client.TreeNoncesEvent,
) (bool, error) {
	return false, nil
}
func (noopBatchHandler) OnBatchFinalization(
	context.Context, client.BatchFinalizationEvent, *tree.TxTree,
	*tree.TxTree,
) ([]string, error) {
	return nil, nil
}
func (noopBatchHandler) OnStreamStarted(
	context.Context, client.StreamStartedEvent,
) error {
	return nil
}
