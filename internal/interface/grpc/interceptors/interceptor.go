package interceptors

import (
	"github.com/arkade-os/arkd/pkg/macaroons"
	middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
)

// UnaryInterceptor returns the unary interceptor.
func UnaryInterceptor(
	svc *macaroons.Service, readiness *ReadinessService,
	getVersionGuard func() (*VersionGuard, error), getDigest func() (string, bool, error),
) grpc.ServerOption {
	return grpc.UnaryInterceptor(middleware.ChainUnaryServer(
		unaryPanicRecoveryInterceptor(),
		errorConverter,
		unaryLogger,
		unaryReadinessHandler(readiness),
		unaryVersionCompatHandler(getVersionGuard),
		unaryDigestHandler(getDigest),
		unaryMacaroonAuthHandler(svc),
	))
}

// StreamInterceptor returns the stream interceptor with a logrus log.
func StreamInterceptor(
	svc *macaroons.Service, readiness *ReadinessService,
	getVersionGuard func() (*VersionGuard, error), getDigest func() (string, bool, error),
) grpc.ServerOption {
	return grpc.StreamInterceptor(middleware.ChainStreamServer(
		streamPanicRecoveryInterceptor(),
		streamErrorConverter,
		streamLogger,
		streamReadinessHandler(readiness),
		streamVersionCompatHandler(getVersionGuard),
		streamDigestHandler(getDigest),
		streamMacaroonAuthHandler(svc),
	))
}
