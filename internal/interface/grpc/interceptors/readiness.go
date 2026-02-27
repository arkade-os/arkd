package interceptors

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/core/ports"
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

type WalletReadinessStatusProvider interface {
	Status(ctx context.Context) (ports.WalletStatus, error)
}

type ReadinessService struct {
	wallet     WalletReadinessStatusProvider
	appStarted atomic.Bool
}

func NewReadinessService(wallet WalletReadinessStatusProvider) *ReadinessService {
	return &ReadinessService{wallet: wallet}
}

func (r *ReadinessService) MarkAppServiceStarted() {
	r.appStarted.Store(true)
}

func (r *ReadinessService) MarkAppServiceStopped() {
	r.appStarted.Store(false)
}

func (r *ReadinessService) Check(ctx context.Context, fullMethod string) error {
	if r == nil || !isPublicServiceMethod(fullMethod) {
		return nil
	}
	// We need both checks:
	// 1) appStarted gates the Ark backend lifecycle (startup/shutdown races, start failures),
	// 2) wallet.Status() gates the current runtime condition (locked/syncing after backend started).
	if !r.appStarted.Load() {
		return status.Error(codes.Unavailable, "server not ready")
	}
	if r.wallet == nil {
		return publicServiceUnavailableErr(fullMethod)
	}

	walletStatus, err := r.wallet.Status(ctx)
	if err != nil {
		return publicServiceUnavailableErr(fullMethod)
	}
	if !walletStatus.IsInitialized() || !walletStatus.IsUnlocked() || !walletStatus.IsSynced() {
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
