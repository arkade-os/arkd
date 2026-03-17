package interceptors

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	arkServiceMethodPrefix     = fmt.Sprintf("/%s/", arkv1.ArkService_ServiceDesc.ServiceName)
	indexerServiceMethodPrefix = fmt.Sprintf("/%s/", arkv1.IndexerService_ServiceDesc.ServiceName)
)

const (
	arkServiceNotReadyMsg     = "ark service not ready: wallet is locked or syncing"
	indexerServiceNotReadyMsg = "indexer service not ready: wallet is locked or syncing"
)

type ReadinessService struct {
	walletReady, appStarted atomic.Bool
	ctx                     context.Context
	cancel                  context.CancelFunc
}

func NewReadinessService() *ReadinessService {
	ctx, cancel := context.WithCancel(context.Background())
	return &ReadinessService{ctx: ctx, cancel: cancel}
}

func (r *ReadinessService) ListenToWalletState(connect func() <-chan bool) {
	go func() {
		for {
			ch := connect()
			if ch == nil {
				r.walletReady.Store(false)
				return
			}
			if !r.listenUntilClosed(ch) {
				return
			}
			// channel was closed, mark not ready and reconnect
			r.walletReady.Store(false)
		}
	}()
}

// listenUntilClosed reads from ch until it closes or the context is canceled.
// Returns true if ch was closed (should reconnect), false if stopped.
func (r *ReadinessService) listenUntilClosed(ch <-chan bool) bool {
	for {
		select {
		case <-r.ctx.Done():
			r.walletReady.Store(false)
			return false
		case ready, ok := <-ch:
			if !ok {
				return true
			}
			r.walletReady.Store(ready)
		}
	}
}

func (r *ReadinessService) MarkAppServiceStarted() {
	r.appStarted.Store(true)
}

func (r *ReadinessService) MarkAppServiceStopped() {
	r.cancel()
	r.appStarted.Store(false)
}

func (r *ReadinessService) Check(_ context.Context, fullMethod string) error {
	if r == nil || !isPublicServiceMethod(fullMethod) {
		return nil
	}
	if !r.appStarted.Load() {
		return status.Error(codes.Unavailable, "server not ready")
	}
	if !r.walletReady.Load() {
		return publicServiceUnavailableErr(fullMethod)
	}
	return nil
}

func isPublicServiceMethod(fullMethod string) bool {
	return strings.HasPrefix(fullMethod, arkServiceMethodPrefix) ||
		strings.HasPrefix(fullMethod, indexerServiceMethodPrefix)
}

func publicServiceUnavailableErr(fullMethod string) error {
	msg := arkServiceNotReadyMsg
	if strings.HasPrefix(fullMethod, indexerServiceMethodPrefix) {
		msg = indexerServiceNotReadyMsg
	}
	return status.Error(codes.FailedPrecondition, msg)
}

func unaryReadinessHandler(readiness *ReadinessService) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context, req any,
		info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (any, error) {
		if err := readiness.Check(ctx, info.FullMethod); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

func streamReadinessHandler(readiness *ReadinessService) grpc.StreamServerInterceptor {
	return func(
		srv any, stream grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler,
	) error {
		if err := readiness.Check(stream.Context(), info.FullMethod); err != nil {
			return err
		}

		return handler(srv, stream)
	}
}
