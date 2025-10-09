package interceptors

import (
	"context"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/internal/interface/grpc/permissions"
	"github.com/arkade-os/arkd/pkg/macaroons"
	"google.golang.org/grpc"
)

func unaryMacaroonAuthHandler(macaroonSvc *macaroons.Service) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context, req interface{},
		info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (interface{}, error) {
		if err := CheckMacaroon(ctx, info.FullMethod, macaroonSvc); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

func streamMacaroonAuthHandler(macaroonSvc *macaroons.Service) grpc.StreamServerInterceptor {
	return func(
		srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler,
	) error {
		if err := CheckMacaroon(ss.Context(), info.FullMethod, macaroonSvc); err != nil {
			return err
		}

		return handler(srv, ss)
	}
}

func CheckMacaroon(ctx context.Context, fullMethod string, svc *macaroons.Service) error {
	if svc == nil {
		return nil
	}
	// Check whether the method is whitelisted, if so we'll allow it regardless
	// of macaroons.
	if _, ok := permissions.Whitelist()[fullMethod]; ok {
		return nil
	}

	uriPermissions, ok := permissions.AllPermissionsByMethod()[fullMethod]
	if !ok {
		return fmt.Errorf("%s: unknown permissions required for method", fullMethod)
	}

	// Find out if there is an external validator registered for
	// this method. Fall back to the internal one if there isn't.
	validator, ok := svc.ExternalValidators[fullMethod]
	if !ok {
		validator = svc
	}
	// Now that we know what validator to use, let it do its work.
	if err := validator.ValidateMacaroon(ctx, uriPermissions, fullMethod); err != nil {
		if strings.Contains(err.Error(), "doesn't exist") {
			return fmt.Errorf("invalid macaroon")
		}
		return err
	}
	return nil
}
