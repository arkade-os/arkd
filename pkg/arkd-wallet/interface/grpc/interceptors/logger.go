package interceptors

import (
	"context"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func unaryLogger(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	log.Debugf("gRPC method: %s", info.FullMethod)
	return handler(ctx, req)
}

func streamLogger(
	srv interface{},
	stream grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	log.Debugf("gRPC method: %s", info.FullMethod)
	return handler(srv, stream)
}
