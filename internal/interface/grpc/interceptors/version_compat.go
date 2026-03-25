package interceptors

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	arkerrors "github.com/arkade-os/arkd/pkg/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const sdkVersionHeader = "x-ark-sdk-version"

// parseMajorVersion extracts the major version component from a semver string.
// Accepts formats like "1.0.0", "v1.0.0", or just "1".
func parseMajorVersion(ver string) (int64, error) {
	ver = strings.TrimPrefix(ver, "v")
	parts := strings.SplitN(ver, ".", 2)
	major, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot parse major version from %q: %w", ver, err)
	}
	return major, nil
}

func checkVersionCompat(
	ctx context.Context, serverMajor int64, serverVersion string,
) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}

	vals := md.Get(sdkVersionHeader)
	if len(vals) == 0 {
		return nil
	}

	clientMajor, err := parseMajorVersion(vals[0])
	if err != nil {
		// Don't break clients with malformed version strings.
		return nil
	}

	if clientMajor < serverMajor {
		log.Debugf("rejecting request: client SDK major version %d below server major version %d",
			clientMajor, serverMajor)
		return arkerrors.SDK_VERSION_TOO_OLD.
			New("server requires SDK major version >= %d", serverMajor).
			WithMetadata(arkerrors.SdkVersionMetadata{
				ClientVersion: vals[0],
				MinVersion:    serverVersion,
			})
	}

	return nil
}

func unaryVersionCompatHandler(
	serverMajor int64, serverVersion string,
) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context, req interface{},
		info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (interface{}, error) {
		if err := checkVersionCompat(ctx, serverMajor, serverVersion); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func streamVersionCompatHandler(
	serverMajor int64, serverVersion string,
) grpc.StreamServerInterceptor {
	return func(
		srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler,
	) error {
		if err := checkVersionCompat(ss.Context(), serverMajor, serverVersion); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}
