package interceptors

import (
	"github.com/arkade-os/arkd/pkg/macaroons"
	middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
)

// UnaryInterceptor returns the unary interceptor.
// serverVersion is the arkd build version (e.g. "v1.2.3"); only its major
// component is used for SDK compatibility checks.
func UnaryInterceptor(
	svc *macaroons.Service,
	readiness *ReadinessService,
	serverVersion string,
) grpc.ServerOption {
	major, _ := parseMajorVersion(serverVersion)
	return grpc.UnaryInterceptor(middleware.ChainUnaryServer(
		unaryPanicRecoveryInterceptor(),
		unaryLogger,
		unaryVersionCompatHandler(major, serverVersion),
		unaryMacaroonAuthHandler(svc),
		unaryReadinessHandler(readiness),
		errorConverter,
	))
}

// StreamInterceptor returns the stream interceptor with a logrus log.
// serverVersion is the arkd build version (e.g. "v1.2.3"); only its major
// component is used for SDK compatibility checks.
func StreamInterceptor(
	svc *macaroons.Service,
	readiness *ReadinessService,
	serverVersion string,
) grpc.ServerOption {
	major, _ := parseMajorVersion(serverVersion)
	return grpc.StreamInterceptor(middleware.ChainStreamServer(
		streamPanicRecoveryInterceptor(),
		streamLogger,
		streamVersionCompatHandler(major, serverVersion),
		streamMacaroonAuthHandler(svc),
		streamReadinessHandler(readiness),
	))
}
