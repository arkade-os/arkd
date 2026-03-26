package interceptors

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	errors "github.com/arkade-os/arkd/pkg/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const buildVersionHeader = "x-build-version"

// parseVersion extracts the major version component from a semver string.
// Accepts formats like "1.0.0", "v1.0.0", or just "1".
func parseVersion(ver string) (int64, int64, error) {
	ver = strings.TrimPrefix(ver, "v")
	parts := strings.Split(ver, ".")
	major, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot parse major version from %q: %w", ver, err)
	}
	if len(parts) < 2 {
		return major, 0, nil
	}

	minor, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot parse minor version from %q: %w", ver, err)
	}
	return major, minor, nil
}

func checkVersionCompat(
	ctx context.Context, serverMajor, serverMinor int64, serverVersion string,
) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}

	vals := md.Get(buildVersionHeader)
	if len(vals) == 0 {
		return nil
	}

	clientMajor, clientMinor, err := parseVersion(vals[0])
	if err != nil {
		// Don't break clients with malformed version strings.
		return nil
	}

	if clientMajor < serverMajor {
		log.Debugf(
			"rejecting request: build version header %d below server major version %d",
			clientMajor, serverMajor,
		)
		return errors.BUILD_VERSION_TOO_OLD.
			New("server requires build version header >= %s", serverVersion).
			WithMetadata(errors.BuildVersionMetadata{
				ClientVersion: vals[0],
				MinVersion:    serverVersion,
			})
	}
	if clientMajor == serverMajor && clientMinor < serverMinor {
		log.Debugf(
			"rejecting request: build version header %d below server minor version %d",
			clientMinor, serverMinor,
		)
		return errors.BUILD_VERSION_TOO_OLD.
			New("server requires build version header >= %s", serverVersion).
			WithMetadata(errors.BuildVersionMetadata{
				ClientVersion: vals[0],
				MinVersion:    serverVersion,
			})
	}

	return nil
}

func unaryVersionCompatHandler(
	serverMajor, serverMinor int64, serverVersion string,
) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context, req interface{},
		info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (interface{}, error) {
		if err := checkVersionCompat(ctx, serverMajor, serverMinor, serverVersion); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func streamVersionCompatHandler(
	serverMajor, serverMinor int64, serverVersion string,
) grpc.StreamServerInterceptor {
	return func(
		srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler,
	) error {
		if err := checkVersionCompat(
			ss.Context(), serverMajor, serverMinor, serverVersion,
		); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}
