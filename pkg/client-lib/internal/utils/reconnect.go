package utils

import (
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var GrpcReconnectConfig = struct {
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
}{
	InitialDelay: 1 * time.Second,
	MaxDelay:     10 * time.Second,
	Multiplier:   2.0,
}

const grpcHTTPFallbackError = "unexpected HTTP status code received from server"

func ShouldReconnect(err error) (bool, time.Duration) {
	if err == nil {
		return false, 0
	}
	// During arkd restart/shutdown windows, gRPC calls may briefly hit the HTTP gateway
	// on the same port and return a plain HTTP response (e.g. 200 with no gRPC content-type).
	if strings.Contains(err.Error(), grpcHTTPFallbackError) {
		return true, time.Second
	}

	st, ok := status.FromError(err)
	if !ok {
		if strings.Contains(err.Error(), "524") {
			return true, 5 * time.Second
		}
		return true, time.Second
	}

	switch st.Code() {
	case codes.Unknown:
		if strings.Contains(st.Message(), "524") {
			return true, 5 * time.Second
		}
		return false, 0
	case codes.ResourceExhausted:
		return true, 5 * time.Second
	case codes.Unavailable, codes.Internal, codes.DeadlineExceeded, codes.Aborted:
		return true, time.Second
	case codes.FailedPrecondition:
		// Ark service may return this while wallet is still locked/syncing after restart.
		return true, 5 * time.Second
	case codes.Canceled,
		codes.InvalidArgument,
		codes.PermissionDenied,
		codes.Unauthenticated,
		codes.Unimplemented:
		return false, 0
	default:
		return false, 0
	}
}
