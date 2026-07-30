package handlers

import (
	"context"

	"github.com/arkade-os/arkd/pkg/arkd-signer/core/application"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

const healthServiceName = "arkd-signer"

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

func (h *healthHandler) Watch(
	_ *grpchealth.HealthCheckRequest,
	_ grpchealth.Health_WatchServer,
) error {
	return nil
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
