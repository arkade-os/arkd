package utils

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/status"
)

type grpcClientStream interface {
	CloseSend() error
}

// ReconnectingStreamConfig defines how to open, read and map a server stream
// into domain events while handling reconnects in a shared generic loop.
//
// Required fields: Open, Recv, HandleResp, ErrorEvent.
// Optional callbacks are used for connection lifecycle events, hooks and logs.
//
// Type parameters:
//   - S is the concrete gRPC client stream type (must implement CloseSend),
//     for example arkv1.ArkService_GetEventStreamClient.
//   - R is the raw message type returned by stream.Recv(),
//     for example *arkv1.GetEventStreamResponse.
//   - E is the final event type emitted on the output channel,
//     for example client.BatchEventChannel.
type ReconnectingStreamConfig[S grpcClientStream, R any, E any] struct {
	// Connect creates a new stream instance. Called once at startup
	Connect func(context.Context) (S, error)
	// Reconnect creates a new stream instance after retryable failures while reconnecting.
	Reconnect func(context.Context) (string, S, error)
	// Recv reads one response from the current stream instance.
	Recv func(S) (*R, error)
	// HandleResp maps one response into domain events and writes them to eventsCh.
	// Returning an error terminates the stream and emits ErrorEvent.
	HandleResp func(context.Context, chan<- E, R) error
	// ErrorEvent maps terminal errors into the stream event type.
	ErrorEvent func(error) E
	// ConnectionEvent maps DISCONNECTED/RECONNECTED lifecycle transitions into
	// the stream event type. Optional.
	ConnectionEvent func(ReconnectingStreamStateEvent) E

	// OnServerClosed runs when Recv returns io.EOF.
	OnServerClosed func()
	// OnDisconnect runs for every retryable receive error before sleep.
	OnDisconnect func(error)
	// OnReconnectSuccess runs after a stream reopen succeeds and the first
	// message has been received from the new stream.
	OnReconnectSuccess func(R)
}

type ReconnectingStreamState string

const (
	ReconnectingStreamStateDisconnected ReconnectingStreamState = "DISCONNECTED"
	ReconnectingStreamStateReconnected  ReconnectingStreamState = "RECONNECTED"
	ReconnectingStreamStateReady        ReconnectingStreamState = "READY"
)

type ReconnectingStreamStateEvent struct {
	State          ReconnectingStreamState
	At             time.Time
	DisconnectedAt time.Time
	Err            error
}

// recvResult holds the outcome of a single cfg.Recv call made by startRecvLoop.
type recvResult[R any] struct {
	resp *R
	err  error
}

// startRecvLoop spawns one goroutine that repeatedly calls recv(s), sending each
// result to the returned buffered channel. The goroutine stops after the first
// error (which is also sent before stopping). Using a dedicated goroutine per
// stream guarantees at most one concurrent recv call on any stream at a time,
// which is required by grpc-go.
func startRecvLoop[S grpcClientStream, R any](recv func(S) (*R, error), s S) <-chan recvResult[R] {
	ch := make(chan recvResult[R], 1)
	go func() {
		for {
			resp, err := recv(s)
			ch <- recvResult[R]{resp, err}
			if err != nil {
				return
			}
		}
	}()
	return ch
}

// StartReconnectingStream opens a stream, continuously receives messages and
// emits mapped events to a channel until context cancelation or a terminal
// error.
//
// Retryable receive/open errors are handled with backoff and reopen attempts.
// When ConnectionEvent is provided, DISCONNECTED/RECONNECTED lifecycle events
// are emitted around reconnect windows.
//
// It returns the event channel, a close function, and an initialization error
// if the initial stream open fails.
//
// Type parameters:
//   - S: concrete stream type used by Open/Recv.
//   - R: raw response type read from the stream.
//   - E: output event type written to the returned channel.
//
// Example:
//
//	eventsCh, closeFn, err := StartReconnectingStream(
//		ctx,
//		ReconnectingStreamConfig[
//			arkv1.ArkService_GetTransactionsStreamClient,
//			*arkv1.GetTransactionsStreamResponse,
//			client.TransactionEvent,
//		]{
//			Open: func(ctx context.Context) (arkv1.ArkService_GetTransactionsStreamClient, error) {
//				return svc.GetTransactionsStream(ctx, &arkv1.GetTransactionsStreamRequest{})
//			},
//			Recv: func(s arkv1.ArkService_GetTransactionsStreamClient) (*arkv1.GetTransactionsStreamResponse, error) {
//				return s.Recv()
//			},
//			HandleResp: func(
//				ctx context.Context,
//				out chan<- client.TransactionEvent,
//				resp *arkv1.GetTransactionsStreamResponse,
//			) error {
//				// map response and send out one or more domain events
//				return nil
//			},
//			ErrorEvent: func(err error) client.TransactionEvent {
//				return client.TransactionEvent{Err: err}
//			},
//		},
//	)
//	if err != nil {
//		return err
//	}
//	defer closeFn()
//
//	for ev := range eventsCh {
//		_ = ev
//	}
func StartReconnectingStream[S grpcClientStream, R any, E any](
	ctx context.Context,
	cfg ReconnectingStreamConfig[S, R, E],
) (<-chan E, func(), error) {
	// Validate mandatory callbacks before starting worker goroutine.
	if cfg.Connect == nil || cfg.Reconnect == nil || cfg.Recv == nil ||
		cfg.HandleResp == nil || cfg.ErrorEvent == nil {
		return nil, nil, fmt.Errorf("invalid reconnecting stream config")
	}

	// Tie stream lifetime to a derived cancelable context.
	ctx, cancel := context.WithCancel(ctx)

	// Open the initial stream eagerly and fail fast on startup errors.
	stream, err := cfg.Connect(ctx)
	if err != nil {
		cancel()
		return nil, nil, err
	}

	// Snapshot reconnect config so the goroutine never reads the global again.
	// This prevents data races when tests (or callers) modify GrpcReconnectConfig
	// after StartReconnectingStream returns.
	reconnectCfg := GrpcReconnectConfig

	// Shared output channel and guarded stream pointer used by recv and closeFn.
	// Buffer of 1 prevents the sender from blocking when the consumer is
	// momentarily busy processing the previous event.
	eventsCh := make(chan E, 1)
	streamMu := sync.Mutex{}

	// Emit terminal errors with best-effort delivery:
	// try immediate send; if context is still active, wait up to 5 seconds.
	// If context is already canceled, skip waiting to avoid teardown stalls.
	sendTerminalErr := func(err error) bool {
		// Fast path: immediate delivery.
		select {
		case eventsCh <- cfg.ErrorEvent(err):
			return true
		default:
		}

		// If caller context is already canceled, most consumers stop draining.
		// Avoid a fixed teardown stall.
		if ctx.Err() != nil {
			return false
		}

		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case eventsCh <- cfg.ErrorEvent(err):
			return true
		case <-ctx.Done():
			return false
		case <-timer.C:
			return false
		}
	}

	// Emit optional connection lifecycle events unless the context is done.
	sendConnectionEvent := func(event ReconnectingStreamStateEvent) bool {
		if cfg.ConnectionEvent == nil {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case eventsCh <- cfg.ConnectionEvent(event):
			return true
		}
	}

	// Worker goroutine: receive loop + reconnect loop.
	go func() {
		defer close(eventsCh)

		backoffDelay := reconnectCfg.InitialDelay
		disconnectedAt := time.Time{}
		isDisconnected := false
		// notReadyMessage captures the gRPC status message from the first error
		// of each disconnect window. It is used to suppress DISCONNECTED and
		// RECONNECTED events when the server is temporarily locked ("service not ready").
		notReadyMessage := ""

		// isReady is false after connect/reconnect until the first message
		// arrives or the 2-second probe timeout fires. While false, the select
		// includes a 2-second arm so quiet streams (e.g. GetTransactionsStream,
		// which may be silent for up to a minute) still emit READY promptly.
		isReady := false
		// isReconnect is true when the next READY transition follows a reconnect,
		// so OnReconnectSuccess is called with the first received message.
		isReconnect := false

		// recvCh is the output of the dedicated per-stream recv goroutine.
		// Exactly one goroutine ever calls cfg.Recv on the current stream,
		// satisfying grpc-go's single-reader constraint.
		recvCh := startRecvLoop(cfg.Recv, stream)

		for {
			var result recvResult[R]

			if !isReady {
				// Probe: wait up to 2 seconds for the first message.
				// A timeout means the stream is open but currently quiet.
				select {
				case <-ctx.Done():
					return
				case result = <-recvCh:
					// fall through to error/success handling below
				case <-time.After(2 * time.Second):
					// Quiet stream: assume ready without a message.
					if !sendConnectionEvent(ReconnectingStreamStateEvent{
						State: ReconnectingStreamStateReady,
						At:    time.Now(),
					}) {
						return
					}
					isReady = true
					isReconnect = false
					continue
				}
			} else {
				select {
				case <-ctx.Done():
					return
				case result = <-recvCh:
				}
			}

			if result.err != nil {
				// Classify receive errors as retryable/non-retryable.
				shouldRetry, retryDelay := ShouldReconnect(result.err)
				if !shouldRetry {
					sendTerminalErr(result.err)
					return
				}

				// Fire optional retry hooks.
				if result.err == io.EOF && cfg.OnServerClosed != nil {
					cfg.OnServerClosed()
				}

				// Emit DISCONNECTED once per outage window.
				if !isDisconnected {
					disconnectedAt = time.Now()
					isDisconnected = true
					if st, ok := status.FromError(result.err); ok {
						notReadyMessage = st.Message()
					}
					if !strings.Contains(notReadyMessage, "not ready") {
						if !sendConnectionEvent(ReconnectingStreamStateEvent{
							State: ReconnectingStreamStateDisconnected,
							At:    disconnectedAt,
							Err:   result.err,
						}) {
							return
						}
						if cfg.OnDisconnect != nil {
							cfg.OnDisconnect(result.err)
						}
					}
				}

				// Inner reconnect loop: stay here until a new stream is open.
				// We never continue the outer loop with the old dead recvCh.
				for {
					sleepDuration := applyJitter(
						max(retryDelay, backoffDelay),
						reconnectCfg.Jitter,
					)
					select {
					case <-ctx.Done():
						return
					case <-time.After(sleepDuration):
					}

					_, newStream, dialErr := cfg.Reconnect(ctx)
					if dialErr != nil {
						shouldRetryDial, dialRetryDelay := ShouldReconnect(dialErr)
						if !shouldRetryDial {
							sendTerminalErr(dialErr)
							return
						}
						retryDelay = dialRetryDelay
						backoffDelay = min(
							time.Duration(float64(backoffDelay)*reconnectCfg.Multiplier),
							reconnectCfg.MaxDelay,
						)
						continue // retry inner loop
					}

					// Reopen succeeded: swap stream, start dedicated recv goroutine, reset backoff.
					streamMu.Lock()
					stream = newStream
					streamMu.Unlock()
					recvCh = startRecvLoop(cfg.Recv, newStream)
					backoffDelay = reconnectCfg.InitialDelay
					isReady = false

					// Emit RECONNECTED once after successful reopen.
					if isDisconnected {
						if !strings.Contains(notReadyMessage, "not ready") {
							if !sendConnectionEvent(ReconnectingStreamStateEvent{
								State:          ReconnectingStreamStateReconnected,
								At:             time.Now(),
								DisconnectedAt: disconnectedAt,
							}) {
								return
							}
						}
						disconnectedAt = time.Time{}
						isDisconnected = false
						notReadyMessage = ""
						isReconnect = true
					}
					break // exit inner reconnect loop with a live recvCh
				}

				continue // outer loop: probe the fresh recvCh
			}

			// Successful receive: emit READY on first message after connect/reconnect.
			if !isReady {
				if !sendConnectionEvent(ReconnectingStreamStateEvent{
					State: ReconnectingStreamStateReady,
					At:    time.Now(),
				}) {
					return
				}
				isReady = true
				if isReconnect && cfg.OnReconnectSuccess != nil && result.resp != nil {
					cfg.OnReconnectSuccess(*result.resp)
				}
				isReconnect = false
			}

			// Any successful receive resets dial backoff state.
			backoffDelay = reconnectCfg.InitialDelay

			if result.resp != nil {
				// Convert response into domain events.
				if err := cfg.HandleResp(ctx, eventsCh, *result.resp); err != nil {
					sendTerminalErr(err)
					return
				}
			}
		}
	}()

	// Returned close function cancels loop and closes the latest stream.
	closeFn := func() {
		cancel()
		streamMu.Lock()
		defer streamMu.Unlock()
		//nolint
		stream.CloseSend()
	}

	return eventsCh, closeFn, nil
}

// applyJitter adds ±jitter randomness to a duration.
// with jitter = 0.2, d get + or - 20%
func applyJitter(d time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return d
	}
	if jitter >= 1.0 {
		jitter = 0.999
	}

	randomFactor := 2.0*rand.Float64() - 1.0 // [-1, +1] factor
	jitterFactor := 1.0 + jitter*randomFactor
	return time.Duration(float64(d) * jitterFactor)
}
