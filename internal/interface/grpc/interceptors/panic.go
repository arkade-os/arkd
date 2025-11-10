// panic.go recovers from panics and converts them into proper gRPC errors instead of crashing the server.
// the panic errors are converted to INTERNAL_ERROR errors and stack traces are logged.
package interceptors

import (
	"context"
	"runtime/debug"

	"github.com/arkade-os/arkd/pkg/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

var somethingWentWrong = errors.INTERNAL_ERROR.New("something went wrong")

func unaryPanicRecoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context, req any,
		info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("panic-recovery middleware recovered from panic: %v", r)
				log.Errorf("stack trace: %v", string(debug.Stack()))
				err = somethingWentWrong
			}
		}()

		resp, err = handler(ctx, req)
		return resp, err
	}
}

func streamPanicRecoveryInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv any, stream grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler,
	) (err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("panic-recovery middleware recovered from panic: %v", r)
				log.Errorf("stack trace: %v", string(debug.Stack()))
				err = somethingWentWrong
			}
		}()

		err = handler(srv, stream)
		return err
	}
}
