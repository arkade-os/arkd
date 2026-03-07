package utils

import (
	"context"
	"fmt"
	"io"
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
	Reconnect func(context.Context) (S, error)
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
	// OnRetryableRecvError runs for every retryable receive error before sleep.
	OnRetryableRecvError func(error)
	// OnReconnectSuccess runs after a stream reopen succeeds.
	OnReconnectSuccess func()
	// LogRetry logs receive-side retry attempts with their sleep duration.
	LogRetry func(error, time.Duration)
	// LogReconnectFailed logs failed reopen attempts.
	LogReconnectFailed func(error)
	// LogCloseError logs CloseSend errors from the returned close function.
	LogCloseError func(error)
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

	// Shared output channel and guarded stream pointer used by recv and closeFn.
	eventsCh := make(chan E)
	streamMu := sync.Mutex{}

	// Emit terminal errors unless the context is already done.
	sendTerminalErr := func(err error) bool {
		select {
		case <-ctx.Done():
			return false
		case eventsCh <- cfg.ErrorEvent(err):
			return true
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
		var resp *R
		// Backoff used for failed reopen attempts.
		backoffDelay := GrpcReconnectConfig.InitialDelay
		// Tracks a single disconnect window to avoid duplicate DISCONNECTED events.
		disconnectedAt := time.Time{}
		isDisconnected := false
		// firstSeen is used to filter out all reconnect/disconnect back and fort that can happen
		// once the server is up again but not yet unlocked. With firstSeen we make sure to notify
		// and log only once the "disconnected" and "reconnected" updated.
		firstSeen := true
		for {
			// Read current stream pointer under lock.
			streamMu.Lock()
			currentStream := stream
			streamMu.Unlock()

			// notReadyMessage is used to determine wether to send a connection event because when
			// the connection is re-established, there can be a brief moment where the server is
			// locked and it will return an error with code Unavailable and message
			// "service not ready".
			// In such case, we prevent sending repeated disconnected/reconnected events to not be
			// too noisy.
			notReadyMessage := ""
			if firstSeen {
				// The very first time we try to receive from the stream we make sure the operation
				// returns by adding a fallback timeout. This because once the stream is opened,
				// it can stay queiet up until a minute (hearthbeat). Thus, to ensure we notify the
				// connection is ready (the stream is opened), the very first time we wait up until
				// 2 seconds and if we didn't receive anything from the stream we assume the stream
				// is open.
				resp, err = timedOutRecv(cfg.Recv, currentStream)
			} else {
				resp, err = cfg.Recv(currentStream)
			}
			fmt.Println("AAAAAA", resp, err)
			if err != nil {
				// Classify receive errors as retryable/non-retryable.
				shouldRetry, retryDelay := ShouldReconnect(err)
				if !shouldRetry {
					sendTerminalErr(err)
					return
				}

				// Fire optional retry hooks.
				if err == io.EOF && cfg.OnServerClosed != nil {
					cfg.OnServerClosed()
				}
				if cfg.OnRetryableRecvError != nil {
					cfg.OnRetryableRecvError(err)
				}
				// Emit DISCONNECTED once per outage window.
				if !isDisconnected {
					disconnectedAt = time.Now()
					isDisconnected = true
					if st, ok := status.FromError(err); ok {
						notReadyMessage = st.Message()
					}
					if !strings.Contains(notReadyMessage, "not ready") {
						if !sendConnectionEvent(ReconnectingStreamStateEvent{
							State: ReconnectingStreamStateDisconnected,
							At:    disconnectedAt,
							Err:   err,
						}) {
							return
						}
					}
				}

				// Sleep before reopen attempt using max(classifier delay, backoff).
				sleepDuration := max(retryDelay, backoffDelay)
				if cfg.LogRetry != nil {
					cfg.LogRetry(err, sleepDuration)
				}

				select {
				case <-ctx.Done():
					return
				case <-time.After(sleepDuration):
				}

				// Attempt to reopen stream on same context.
				newStream, dialErr := cfg.Reconnect(ctx)
				if dialErr != nil {
					// Reopen failed: either terminate or backoff and retry.
					shouldRetryDial, _ := ShouldReconnect(dialErr)
					if !shouldRetryDial {
						sendTerminalErr(dialErr)
						return
					}

					backoffDelay = min(
						time.Duration(float64(backoffDelay)*GrpcReconnectConfig.Multiplier),
						GrpcReconnectConfig.MaxDelay,
					)
					if cfg.LogReconnectFailed != nil {
						cfg.LogReconnectFailed(dialErr)
					}
					continue
				}

				// Try to receeive from the stream with a timeout (2 seconds) to ensure the server
				// is online and also unlocked.
				recvResp, recvErr := timedOutRecv(cfg.Recv, currentStream)
				if recvErr == nil {
					if !sendConnectionEvent(ReconnectingStreamStateEvent{
						State: ReconnectingStreamStateReady,
						At:    time.Now(),
					}) {
						return
					}

					if recvResp != nil {
						if err := cfg.HandleResp(ctx, eventsCh, *recvResp); err != nil {
							sendTerminalErr(err)
							return
						}
					}
				}

				// Reopen succeeded: swap stream and reset backoff.
				streamMu.Lock()
				stream = newStream
				streamMu.Unlock()
				backoffDelay = GrpcReconnectConfig.InitialDelay
				// Emit RECONNECTED once after successful reopen.
				if isDisconnected {
					reconnectedAt := time.Now()
					if !strings.Contains(notReadyMessage, "not ready") {
						if !sendConnectionEvent(ReconnectingStreamStateEvent{
							State:          ReconnectingStreamStateReconnected,
							At:             reconnectedAt,
							DisconnectedAt: disconnectedAt,
						}) {
							return
						}
					}
					disconnectedAt = time.Time{}
					isDisconnected = false
					firstSeen = true
				}
				if cfg.OnReconnectSuccess != nil {
					cfg.OnReconnectSuccess()
				}
				continue
			}

			// Only the first time send a notification that the stream is ready just before
			// handling the response.
			if firstSeen {
				if !sendConnectionEvent(ReconnectingStreamStateEvent{
					State: ReconnectingStreamStateReady,
					At:    time.Now(),
				}) {
					return
				}
				firstSeen = false
			}

			// Any successful receive resets dial backoff state.
			backoffDelay = GrpcReconnectConfig.InitialDelay

			// resp can be nil if recv timed out, in that case we just skip handling the response
			if resp != nil {
				// Convert response into domain events.
				if err := cfg.HandleResp(ctx, eventsCh, *resp); err != nil {
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
		if err := stream.CloseSend(); err != nil && cfg.LogCloseError != nil {
			cfg.LogCloseError(err)
		}
	}

	return eventsCh, closeFn, nil
}

func timedOutRecv[S grpcClientStream, R any](recv func(S) (*R, error), s S) (*R, error) {
	type result struct {
		resp *R
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := recv(s)
		ch <- result{resp, err}
	}()
	select {
	case <-time.After(2 * time.Second):
		return nil, nil // timeout: server is ready but quiet
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return r.resp, nil
	}
}
