package utils

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestStartReconnectingStream(t *testing.T) {
	// Verifies that READY is emitted when the initial recv returns a message immediately
	// (GetEventStream style).
	t.Run("quick stream emits READY", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		msg := "hello"
		var n atomic.Int32

		cfg := makeConfig(
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ms *mockStream) (*string, error) {
				if n.Add(1) == 1 {
					return &msg, nil
				}
				<-ctx.Done()
				return nil, ctx.Err()
			},
		)

		ch, closeFn, err := StartReconnectingStream(ctx, cfg)
		require.NoError(t, err)
		defer closeFn()

		evs := collectEvents(t, ctx, ch, 1)
		require.Equal(t, ReconnectingStreamStateReady, evs[0].state)
	})

	// Verifies that READY is emitted after the 2-second timedOutRecv timeout when the stream
	// never sends a first message (GetTransactionsStream style).
	t.Run("quiet stream emits READY", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cfg := makeConfig(
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ms *mockStream) (*string, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		)

		ch, closeFn, err := StartReconnectingStream(ctx, cfg)
		require.NoError(t, err)
		defer closeFn()

		start := time.Now()
		evs := collectEvents(t, ctx, ch, 1)

		require.Equal(t, ReconnectingStreamStateReady, evs[0].state)
		require.GreaterOrEqual(t, time.Since(start), 2*time.Second,
			"READY for a quiet stream should arrive after the ~2s timedOutRecv timeout")
	})

	// Verifies that DISCONNECTED is emitted and OnDisconnect is called when Recv returns a
	// retryable error after READY.
	t.Run("emits DISCONNECTED and triggers OnDisconnect", func(t *testing.T) {
		saved := GrpcReconnectConfig
		GrpcReconnectConfig.InitialDelay = 0
		defer func() { GrpcReconnectConfig = saved }()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		msg := "hello"
		var n atomic.Int32
		disconnectCh := make(chan error, 1)

		cfg := makeConfig(
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ms *mockStream) (*string, error) {
				switch n.Add(1) {
				case 1:
					return &msg, nil
				case 2:
					return nil, unavailErr()
				default:
					<-ctx.Done()
					return nil, ctx.Err()
				}
			},
		)
		cfg.OnDisconnect = func(err error) { disconnectCh <- err }

		ch, closeFn, err := StartReconnectingStream(ctx, cfg)
		require.NoError(t, err)
		defer closeFn()

		evs := collectEvents(t, ctx, ch, 2)
		require.Equal(t, ReconnectingStreamStateReady, evs[0].state, "event[0]")
		require.Equal(t, ReconnectingStreamStateDisconnected, evs[1].state, "event[1]")

		select {
		case callErr := <-disconnectCh:
			require.NotNil(t, callErr, "OnDisconnect called with nil error")
		case <-time.After(time.Second):
			t.Error("OnDisconnect was not called")
		}
	})

	// Verifies that DISCONNECTED and OnDisconnect are NOT emitted when the error contains
	// "service not ready".
	t.Run("suppresses DISCONNECTED for notReady error", func(t *testing.T) {
		saved := GrpcReconnectConfig
		GrpcReconnectConfig.InitialDelay = 0
		defer func() { GrpcReconnectConfig = saved }()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		msg := "hello"
		var n atomic.Int32
		disconnectCalled := make(chan struct{}, 1)

		cfg := makeConfig(
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ms *mockStream) (*string, error) {
				switch n.Add(1) {
				case 1:
					return &msg, nil
				case 2:
					return nil, notReadyErr()
				default:
					<-ctx.Done()
					return nil, ctx.Err()
				}
			},
		)
		cfg.OnDisconnect = func(err error) { disconnectCalled <- struct{}{} }

		ch, closeFn, err := StartReconnectingStream(ctx, cfg)
		require.NoError(t, err)
		defer closeFn()

		evs := collectEvents(t, ctx, ch, 1)
		require.Equal(t, ReconnectingStreamStateReady, evs[0].state)

		select {
		case ev := <-ch:
			require.NotEqual(t, ReconnectingStreamStateDisconnected, ev.state,
				"DISCONNECTED must not be emitted for 'service not ready'")
		case <-disconnectCalled:
			t.Error("OnDisconnect must not be called for 'service not ready'")
		case <-time.After(500 * time.Millisecond):
			// correct: no spurious disconnect events
		}
	})

	// Verifies that after a disconnect the events arrive in the correct order:
	// READY → DISCONNECTED → RECONNECTED → READY.
	//
	// RED: currently fails because L267 calls timedOutRecv with currentStream
	// (the old broken stream) instead of newStream, producing a spurious extra
	// READY between DISCONNECTED and RECONNECTED.
	t.Run("emits correct Connection event sequence after reconnection", func(t *testing.T) {
		saved := GrpcReconnectConfig
		GrpcReconnectConfig.InitialDelay = 0
		defer func() { GrpcReconnectConfig = saved }()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		msg := "hello"
		reconnectMsg := "reconnect-hello"
		var initialStreamID atomic.Int32
		var n atomic.Int32

		cfg := makeConfig(
			func(ctx context.Context) (*mockStream, error) {
				s := newMockStream()
				initialStreamID.Store(s.id)
				return s, nil
			},
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ms *mockStream) (*string, error) {
				if ms.id == initialStreamID.Load() {
					switch n.Add(1) {
					case 1:
						return &msg, nil
					default:
						return nil, unavailErr()
					}
				}
				// Reconnect stream always responds immediately.
				return &reconnectMsg, nil
			},
		)

		ch, closeFn, err := StartReconnectingStream(ctx, cfg)
		require.NoError(t, err)
		defer closeFn()

		evs := collectEvents(t, ctx, ch, 4)
		require.Equal(t, ReconnectingStreamStateReady, evs[0].state, "event[0]")
		require.Equal(t, ReconnectingStreamStateDisconnected, evs[1].state, "event[1]")
		require.Equal(t, ReconnectingStreamStateReconnected, evs[2].state, "event[2]")
		require.Equal(t, ReconnectingStreamStateReady, evs[3].state, "event[3]")
	})

	// Verifies that OnReconnectSuccess is called with the first message from the new
	// stream after a successful reconnect.
	t.Run("triggers OnReconnectSuccess after reconnection", func(t *testing.T) {
		saved := GrpcReconnectConfig
		GrpcReconnectConfig.InitialDelay = 0
		defer func() { GrpcReconnectConfig = saved }()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		msg := "hello"
		reconnectMsg := "reconnect-hello"
		var initialStreamID atomic.Int32
		var n atomic.Int32
		reconnectSuccessCh := make(chan string, 1)

		cfg := makeConfig(
			func(ctx context.Context) (*mockStream, error) {
				s := newMockStream()
				initialStreamID.Store(s.id)
				return s, nil
			},
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ms *mockStream) (*string, error) {
				if ms.id == initialStreamID.Load() {
					switch n.Add(1) {
					case 1:
						return &msg, nil
					default:
						return nil, unavailErr()
					}
				}
				return &reconnectMsg, nil
			},
		)
		cfg.OnReconnectSuccess = func(r string) { reconnectSuccessCh <- r }

		ch, closeFn, err := StartReconnectingStream(ctx, cfg)
		require.NoError(t, err)
		defer closeFn()

		// Drain events in the background: the goroutine emits RECONNECTED and
		// READY(probe) before calling OnReconnectSuccess, so without a reader
		// those sends block and the callback is never reached.
		go func() {
			for range ch {
			}
		}()

		select {
		case got := <-reconnectSuccessCh:
			require.Equal(t, reconnectMsg, got)
		case <-time.After(5 * time.Second):
			t.Error("OnReconnectSuccess was not called after reconnect")
		}
	})

	// Verifies that when the reconnect probe (timedOutRecv) times out with a nil response, the
	// code does not panic dereferencing it before calling OnReconnectSuccess.
	//
	// RED: currently panics at L276 — cfg.OnReconnectSuccess(*recvResp) with
	// recvResp == nil when timedOutRecv returns (nil, nil) on timeout.
	t.Run("no panic when probe timeout", func(t *testing.T) {
		saved := GrpcReconnectConfig
		GrpcReconnectConfig.InitialDelay = 0
		defer func() { GrpcReconnectConfig = saved }()

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		msg := "hello"
		var n atomic.Int32

		// Both streams are quiet: Recv blocks indefinitely after the disconnect.
		// The reconnect probe will time out after 2s returning (nil, nil).
		cfg := makeConfig(
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ms *mockStream) (*string, error) {
				switch n.Add(1) {
				case 1:
					return &msg, nil
				case 2:
					return nil, unavailErr()
				default:
					<-ctx.Done()
					return nil, ctx.Err()
				}
			},
		)
		cfg.OnReconnectSuccess = func(r string) {}

		ch, closeFn, err := StartReconnectingStream(ctx, cfg)
		require.NoError(t, err)
		defer closeFn()

		// Drain events in the background so the goroutine can proceed past
		// RECONNECTED and into the probe timeout path. Without a reader it would
		// block on the RECONNECTED send and never reach OnReconnectSuccess.
		// A panic here means the nil guard is missing.
		go func() {
			for range ch {
			}
		}()

		time.Sleep(5 * time.Second) // enough for 1s sleep + 2s probe timeout + margin
	})

	// terminatesOnNonRetryableError verifies that a non-retryable error emits
	// an error event and closes the event channel.
	t.Run("terminates on non retryable error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		msg := "hello"
		var n atomic.Int32

		cfg := makeConfig(
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ms *mockStream) (*string, error) {
				if n.Add(1) == 1 {
					return &msg, nil
				}
				return nil, fatalErr()
			},
		)

		ch, closeFn, err := StartReconnectingStream(ctx, cfg)
		require.NoError(t, err)
		defer closeFn()

		collectEvents(t, ctx, ch, 1) // drain READY

		select {
		case ev, ok := <-ch:
			if ok {
				require.NotNil(t, ev.err, "expected terminal error event, got %+v", ev)
			}
		case <-ctx.Done():
			t.Fatal("timeout waiting for terminal error event")
		}

		select {
		case _, ok := <-ch:
			require.False(t, ok, "channel must be closed after terminal error")
		case <-time.After(time.Second):
			t.Error("channel not closed after terminal error")
		}
	})

	// Verifies that calling closeFn closes the event channel.
	t.Run("closes channel OnClose", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Connect stores the stream's derived context so Recv can unblock when
		// closeFn() cancels it, not when the outer test context expires.
		connectFn := func(sCtx context.Context) (*mockStream, error) {
			return &mockStream{id: streamIDSeq.Add(1), ctx: sCtx}, nil
		}
		cfg := makeConfig(
			connectFn,
			connectFn,
			func(ms *mockStream) (*string, error) {
				<-ms.ctx.Done()
				return nil, ms.ctx.Err()
			},
		)

		ch, closeFn, err := StartReconnectingStream(ctx, cfg)
		require.NoError(t, err)

		collectEvents(t, ctx, ch, 1) // wait for READY (after 2s timedOutRecv timeout)

		closeFn()

		// Drain until closed: the goroutine may send one final event (e.g.
		// DISCONNECTED) before it notices ctx is done, so a single receive
		// is not enough — we must keep draining until ok==false.
		deadline := time.After(time.Second)
		for {
			select {
			case _, ok := <-ch:
				if !ok {
					return // channel closed — test passes
				}
			case <-deadline:
				t.Error("channel not closed after closeFn()")
				return
			}
		}
	})

	// Verifies that RECONNECTED and READY are still emitted when Reconnect fails
	// several times before eventually succeeding. This exercises the inner
	// reconnect loop: a failed Reconnect must not return to the outer loop with
	// a dead recvCh.
	t.Run("reconnects after repeated Reconnect failures", func(t *testing.T) {
		saved := GrpcReconnectConfig
		GrpcReconnectConfig.InitialDelay = 0
		defer func() { GrpcReconnectConfig = saved }()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		msg := "hello"
		reconnectMsg := "reconnect-hello"
		var n atomic.Int32
		var reconnectAttempts atomic.Int32
		var initialStreamID atomic.Int32

		cfg := makeConfig(
			func(ctx context.Context) (*mockStream, error) {
				s := newMockStream()
				initialStreamID.Store(s.id)
				return s, nil
			},
			func(ctx context.Context) (*mockStream, error) {
				if reconnectAttempts.Add(1) < 3 {
					return nil, unavailErr() // first two attempts fail
				}
				return newMockStream(), nil
			},
			func(ms *mockStream) (*string, error) {
				if ms.id == initialStreamID.Load() {
					switch n.Add(1) {
					case 1:
						return &msg, nil
					default:
						return nil, unavailErr()
					}
				}
				return &reconnectMsg, nil
			},
		)

		ch, closeFn, err := StartReconnectingStream(ctx, cfg)
		require.NoError(t, err)
		defer closeFn()

		evs := collectEvents(t, ctx, ch, 4)
		require.Equal(t, ReconnectingStreamStateReady, evs[0].state, "event[0]")
		require.Equal(t, ReconnectingStreamStateDisconnected, evs[1].state, "event[1]")
		require.Equal(t, ReconnectingStreamStateReconnected, evs[2].state, "event[2]")
		require.Equal(t, ReconnectingStreamStateReady, evs[3].state, "event[3]")
		require.GreaterOrEqual(t, reconnectAttempts.Load(), int32(3),
			"Reconnect must have been retried at least 3 times")
	})

	// Verifies that a non-retryable error from Reconnect emits a terminal error
	// event and closes the channel.
	t.Run("terminates on non-retryable Reconnect error", func(t *testing.T) {
		saved := GrpcReconnectConfig
		GrpcReconnectConfig.InitialDelay = 0
		defer func() { GrpcReconnectConfig = saved }()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		msg := "hello"
		var n atomic.Int32

		cfg := makeConfig(
			func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			func(ctx context.Context) (*mockStream, error) { return nil, fatalErr() },
			func(ms *mockStream) (*string, error) {
				if n.Add(1) == 1 {
					return &msg, nil
				}
				return nil, unavailErr()
			},
		)

		ch, closeFn, err := StartReconnectingStream(ctx, cfg)
		require.NoError(t, err)
		defer closeFn()

		collectEvents(t, ctx, ch, 2) // drain READY + DISCONNECTED

		select {
		case ev, ok := <-ch:
			if ok {
				require.NotNil(t, ev.err, "expected terminal error event, got %+v", ev)
			}
		case <-ctx.Done():
			t.Fatal("timeout waiting for terminal error")
		}

		select {
		case _, ok := <-ch:
			require.False(t, ok, "channel must be closed after non-retryable Reconnect error")
		case <-time.After(time.Second):
			t.Error("channel not closed after non-retryable Reconnect error")
		}
	})

	// Verifies that an error returned by HandleResp emits a terminal error event
	// and closes the channel.
	t.Run("terminates when HandleResp returns error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		msg := "hello"

		cfg := ReconnectingStreamConfig[*mockStream, string, testEvent]{
			Connect:   func(ctx context.Context) (*mockStream, error) { return newMockStream(), nil },
			Reconnect: func(ctx context.Context) (string, *mockStream, error) { return "", newMockStream(), nil },
			Recv:      func(ms *mockStream) (*string, error) { return &msg, nil },
			HandleResp: func(_ context.Context, _ chan<- testEvent, _ string) error {
				return fatalErr()
			},
			ErrorEvent: func(err error) testEvent { return testEvent{err: err} },
			ConnectionEvent: func(e ReconnectingStreamStateEvent) testEvent {
				return testEvent{state: e.State}
			},
		}

		ch, closeFn, err := StartReconnectingStream(ctx, cfg)
		require.NoError(t, err)
		defer closeFn()

		collectEvents(t, ctx, ch, 1) // drain READY

		select {
		case ev, ok := <-ch:
			if ok {
				require.NotNil(t, ev.err, "expected terminal error from HandleResp, got %+v", ev)
			}
		case <-ctx.Done():
			t.Fatal("timeout waiting for terminal error from HandleResp")
		}

		select {
		case _, ok := <-ch:
			require.False(t, ok, "channel must be closed after HandleResp error")
		case <-time.After(time.Second):
			t.Error("channel not closed after HandleResp error")
		}
	})
}

// mockStream satisfies grpcClientStream.
// ctx is optionally set by Connect so that Recv can unblock when the stream's
// context is cancelled (e.g. by closeFn), independently of the test's context.
type mockStream struct {
	id  int32
	ctx context.Context
}

func (m *mockStream) CloseSend() error { return nil }

var streamIDSeq atomic.Int32

func newMockStream() *mockStream {
	return &mockStream{id: streamIDSeq.Add(1)}
}

// testEvent is the concrete domain event type used in tests.
type testEvent struct {
	state ReconnectingStreamState
	err   error
}

func unavailErr() error  { return status.Error(codes.Unavailable, "connection lost") }
func notReadyErr() error { return status.Error(codes.Unavailable, "service not ready") }
func fatalErr() error    { return status.Error(codes.PermissionDenied, "unauthorized") }

// collectEvents drains exactly n events from ch, failing if ctx expires first.
func collectEvents(t *testing.T, ctx context.Context, ch <-chan testEvent, n int) []testEvent {
	t.Helper()
	evs := make([]testEvent, 0, n)
	for range n {
		select {
		case ev, ok := <-ch:
			require.True(t, ok, "channel closed after %d/%d events", len(evs), n)
			evs = append(evs, ev)
		case <-ctx.Done():
			t.Fatalf("timeout after collecting %d/%d events: %v", len(evs), n, evs)
		}
	}
	return evs
}

// makeConfig builds a minimal ReconnectingStreamConfig for tests.
func makeConfig(
	connect func(context.Context) (*mockStream, error),
	reconnect func(context.Context) (*mockStream, error),
	recv func(*mockStream) (*string, error),
) ReconnectingStreamConfig[*mockStream, string, testEvent] {
	return ReconnectingStreamConfig[*mockStream, string, testEvent]{
		Connect: connect,
		Reconnect: func(ctx context.Context) (string, *mockStream, error) {
			stream, err := reconnect(ctx)
			return "", stream, err
		},
		Recv:       recv,
		HandleResp: func(_ context.Context, _ chan<- testEvent, _ string) error { return nil },
		ErrorEvent: func(err error) testEvent { return testEvent{err: err} },
		ConnectionEvent: func(e ReconnectingStreamStateEvent) testEvent {
			return testEvent{state: e.State}
		},
	}
}
