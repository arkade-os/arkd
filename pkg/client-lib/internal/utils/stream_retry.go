package utils

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

type grpcClientStream interface {
	CloseSend() error
}

type ReconnectingStreamConfig[S grpcClientStream, R any, E any] struct {
	Open            func(context.Context) (S, error)
	Recv            func(S) (R, error)
	HandleResp      func(context.Context, chan<- E, R) error
	ErrorEvent      func(error) E
	ConnectionEvent func(ReconnectingStreamStateEvent) E

	OnServerClosed       func()
	OnRetryableRecvError func(error)
	OnReconnectSuccess   func()
	LogRetry             func(error, time.Duration)
	LogReconnectFailed   func(error)
	LogCloseError        func(error)
}

type ReconnectingStreamState string

const (
	ReconnectingStreamStateDisconnected ReconnectingStreamState = "DISCONNECTED"
	ReconnectingStreamStateReconnected  ReconnectingStreamState = "RECONNECTED"
)

type ReconnectingStreamStateEvent struct {
	State          ReconnectingStreamState
	At             time.Time
	DisconnectedAt time.Time
	Err            error
}

func StartReconnectingStream[S grpcClientStream, R any, E any](
	ctx context.Context,
	cfg ReconnectingStreamConfig[S, R, E],
) (<-chan E, func(), error) {
	if cfg.Open == nil || cfg.Recv == nil || cfg.HandleResp == nil || cfg.ErrorEvent == nil {
		return nil, nil, fmt.Errorf("invalid reconnecting stream config")
	}

	ctx, cancel := context.WithCancel(ctx)

	stream, err := cfg.Open(ctx)
	if err != nil {
		cancel()
		return nil, nil, err
	}

	eventsCh := make(chan E)
	streamMu := sync.Mutex{}

	sendTerminalErr := func(err error) bool {
		select {
		case <-ctx.Done():
			return false
		case eventsCh <- cfg.ErrorEvent(err):
			return true
		}
	}

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

	go func() {
		defer close(eventsCh)
		backoffDelay := GrpcReconnectConfig.InitialDelay
		disconnectedAt := time.Time{}
		isDisconnected := false

		for {
			streamMu.Lock()
			currentStream := stream
			streamMu.Unlock()

			resp, err := cfg.Recv(currentStream)
			if err != nil {
				shouldRetry, retryDelay := ShouldReconnect(err)
				if !shouldRetry {
					sendTerminalErr(err)
					return
				}

				if err == io.EOF && cfg.OnServerClosed != nil {
					cfg.OnServerClosed()
				}
				if cfg.OnRetryableRecvError != nil {
					cfg.OnRetryableRecvError(err)
				}
				if !isDisconnected {
					disconnectedAt = time.Now()
					isDisconnected = true
					if !sendConnectionEvent(ReconnectingStreamStateEvent{
						State: ReconnectingStreamStateDisconnected,
						At:    disconnectedAt,
						Err:   err,
					}) {
						return
					}
				}

				sleepDuration := max(retryDelay, backoffDelay)
				if cfg.LogRetry != nil {
					cfg.LogRetry(err, sleepDuration)
				}

				select {
				case <-ctx.Done():
					return
				case <-time.After(sleepDuration):
				}

				newStream, dialErr := cfg.Open(ctx)
				if dialErr != nil {
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

				streamMu.Lock()
				stream = newStream
				streamMu.Unlock()
				backoffDelay = GrpcReconnectConfig.InitialDelay
				if isDisconnected {
					reconnectedAt := time.Now()
					if !sendConnectionEvent(ReconnectingStreamStateEvent{
						State:          ReconnectingStreamStateReconnected,
						At:             reconnectedAt,
						DisconnectedAt: disconnectedAt,
					}) {
						return
					}
					disconnectedAt = time.Time{}
					isDisconnected = false
				}
				if cfg.OnReconnectSuccess != nil {
					cfg.OnReconnectSuccess()
				}
				continue
			}

			backoffDelay = GrpcReconnectConfig.InitialDelay

			if err := cfg.HandleResp(ctx, eventsCh, resp); err != nil {
				sendTerminalErr(err)
				return
			}
		}
	}()

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
