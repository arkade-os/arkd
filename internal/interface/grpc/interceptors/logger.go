package interceptors

import (
	"context"
	"errors"

	arkerrors "github.com/arkade-os/arkd/pkg/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func unaryLogger(
	ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	log.Debugf("gRPC method: %s", info.FullMethod)
	resp, err := handler(ctx, req)
	if err != nil {
		var structuredErr arkerrors.Error
		if errors.As(err, &structuredErr) {
			if structuredErr.Code() == arkerrors.INTERNAL_ERROR.Code {
				structuredErr.Log().Error(err)
			}
		}
	}
	return resp, err
}

func streamLogger(
	srv any, stream grpc.ServerStream,
	info *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	log.Debugf("gRPC method: %s", info.FullMethod)
	return handler(srv, stream)
}
