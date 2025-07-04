package interceptors

import (
	"github.com/arkade-os/arkd/pkg/macaroons"
	middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
)

// UnaryInterceptor returns the unary interceptor
func UnaryInterceptor(svc *macaroons.Service) grpc.ServerOption {
	return grpc.UnaryInterceptor(middleware.ChainUnaryServer(
		unaryPanicRecoveryInterceptor(),
		unaryLogger,
		unaryMacaroonAuthHandler(svc),
	))
}

// StreamInterceptor returns the stream interceptor with a logrus log
func StreamInterceptor(svc *macaroons.Service) grpc.ServerOption {
	return grpc.StreamInterceptor(middleware.ChainStreamServer(
		streamPanicRecoveryInterceptor(),
		streamLogger,
		streamMacaroonAuthHandler(svc),
	))
}
