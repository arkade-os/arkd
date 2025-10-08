package interceptors

import (
	"context"
	"errors"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	arkerrors "github.com/arkade-os/arkd/pkg/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// gRPCError is a wrapper implementing GRPCStatus method for errors.Error
// the protobuf service will use this to return the associated grpc status error with ErrorDetails message
type gRPCError struct {
	err arkerrors.Error
}

func (e gRPCError) Error() string {
	return e.err.Error()
}

func (e gRPCError) GRPCStatus() *status.Status {
	st := status.New(e.err.GrpcCode(), e.err.Error())

	metadata := e.err.Metadata()

	stWithDetails, err := st.WithDetails(&arkv1.ErrorDetails{
		Code:     int32(e.err.Code()),
		Name:     e.err.CodeName(),
		Message:  e.err.Error(),
		Metadata: metadata,
	})
	if err != nil {
		return st
	}
	return stWithDetails
}

func errorConverter(
	ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	log.Debugf("gRPC method: %s", info.FullMethod)
	resp, err := handler(ctx, req)
	if err != nil {
		var structuredErr arkerrors.Error
		if errors.As(err, &structuredErr) {
			return nil, gRPCError{structuredErr}
		}
	}
	return resp, err
}
