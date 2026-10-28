package handlers

import (
	"context"

	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

type healthHandler struct{}

func NewHealthHandler() grpchealth.HealthServer {
	return &healthHandler{}
}

func (h *healthHandler) Check(
	context.Context, *grpchealth.HealthCheckRequest,
) (*grpchealth.HealthCheckResponse, error) {
	return &grpchealth.HealthCheckResponse{Status: grpchealth.HealthCheckResponse_SERVING}, nil
}

func (h *healthHandler) Watch(
	_ *grpchealth.HealthCheckRequest, srv grpchealth.Health_WatchServer,
) error {
	resp := &grpchealth.HealthCheckResponse{Status: grpchealth.HealthCheckResponse_SERVING}
	if err := srv.Send(resp); err != nil {
		return err
	}
	<-srv.Context().Done()
	return srv.Context().Err()
}

func (h *healthHandler) List(
	context.Context, *grpchealth.HealthListRequest,
) (*grpchealth.HealthListResponse, error) {
	return &grpchealth.HealthListResponse{
		Statuses: map[string]*grpchealth.HealthCheckResponse{
			"arkd-signer": {Status: grpchealth.HealthCheckResponse_SERVING},
		},
	}, nil
}
