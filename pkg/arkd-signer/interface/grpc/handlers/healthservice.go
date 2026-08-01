package handlers

import (
	"context"
	"time"

	"github.com/arkade-os/arkd/pkg/arkd-signer/core/application"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	healthServiceName = "arkd-signer"

	// The signer has no readiness state change to subscribe to, so Watch polls
	// rather than being woken.
	watchPollInterval = time.Second
)

type healthHandler struct {
	signer application.Signer
}

func NewHealthHandler(signer application.Signer) grpchealth.HealthServer {
	return &healthHandler{signer: signer}
}

func (h *healthHandler) Check(
	ctx context.Context,
	_ *grpchealth.HealthCheckRequest,
) (*grpchealth.HealthCheckResponse, error) {
	return &grpchealth.HealthCheckResponse{Status: h.status(ctx)}, nil
}

// Watch streams the current status and then every change to it. Returning
// immediately instead, as this did, closes the stream on a watching client
// without ever telling it anything.
func (h *healthHandler) Watch(
	_ *grpchealth.HealthCheckRequest,
	srv grpchealth.Health_WatchServer,
) error {
	ctx := srv.Context()

	last := h.status(ctx)
	if err := srv.Send(&grpchealth.HealthCheckResponse{Status: last}); err != nil {
		return err
	}

	ticker := time.NewTicker(watchPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			current := h.status(ctx)
			if current == last {
				continue
			}
			last = current
			if err := srv.Send(&grpchealth.HealthCheckResponse{Status: current}); err != nil {
				return err
			}
		}
	}
}

func (h *healthHandler) List(
	ctx context.Context,
	_ *grpchealth.HealthListRequest,
) (*grpchealth.HealthListResponse, error) {
	return &grpchealth.HealthListResponse{
		Statuses: map[string]*grpchealth.HealthCheckResponse{
			healthServiceName: {Status: h.status(ctx)},
		},
	}, nil
}

// status reports NOT_SERVING until the signing key is usable, so an orchestrator
// waiting on the health endpoint can tell a ready signer from one that came up
// without a usable key. Reporting SERVING unconditionally makes a misconfigured
// signer indistinguishable from a working one until the first signing request.
func (h *healthHandler) status(ctx context.Context) grpchealth.HealthCheckResponse_ServingStatus {
	if h.signer == nil || !h.signer.IsReady(ctx) {
		return grpchealth.HealthCheckResponse_NOT_SERVING
	}
	return grpchealth.HealthCheckResponse_SERVING
}
