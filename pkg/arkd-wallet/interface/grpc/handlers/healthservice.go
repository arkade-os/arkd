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
	_ context.Context,
	_ *grpchealth.HealthCheckRequest,
) (*grpchealth.HealthCheckResponse, error) {
	return &grpchealth.HealthCheckResponse{
		Status: grpchealth.HealthCheckResponse_SERVING,
	}, nil
}

func (h *healthHandler) Watch(
	_ *grpchealth.HealthCheckRequest,
	_ grpchealth.Health_WatchServer,
) error {
	return nil
}
