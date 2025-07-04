package interceptors

import (
	middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
)

// UnaryInterceptor returns the unary interceptor
func UnaryInterceptor() grpc.ServerOption {
	return grpc.UnaryInterceptor(middleware.ChainUnaryServer(
		unaryPanicRecoveryInterceptor(),
		unaryLogger,
	))
}

// StreamInterceptor returns the stream interceptor with a logrus log
func StreamInterceptor() grpc.ServerOption {
	return grpc.StreamInterceptor(middleware.ChainStreamServer(
		streamPanicRecoveryInterceptor(),
		streamLogger,
	))
}
