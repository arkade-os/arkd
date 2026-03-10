package interceptors

import (
	"context"
	"strings"

	arkerrors "github.com/arkade-os/arkd/pkg/errors"
	"github.com/coreos/go-semver/semver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// BreakingChange defines a minimum SDK version required for a given gRPC method.
type BreakingChange struct {
	MinVersion semver.Version
	Message    string
}

// breakingChanges maps gRPC full method names to their minimum required SDK version.
var breakingChanges = map[string]BreakingChange{
	// Example (uncomment when a breaking change is introduced):
	// "/ark.v1.ArkService/RegisterIntent": {
	//     MinVersion: *semver.New("0.9.0"),
	//     Message:    "RegisterIntent request format changed in v0.9.0",
	// },
}

const sdkVersionHeader = "x-ark-sdk-version"

func checkVersionCompat(ctx context.Context, fullMethod string) error {
	bc, ok := breakingChanges[fullMethod]
	if !ok {
		return nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}

	vals := md.Get(sdkVersionHeader)
	if len(vals) == 0 {
		return nil
	}

	raw := strings.TrimPrefix(vals[0], "v")
	clientVer, err := semver.NewVersion(raw)
	if err != nil {
		// Don't break clients with malformed version strings.
		return nil
	}

	if clientVer.LessThan(bc.MinVersion) {
		return arkerrors.SDK_VERSION_TOO_OLD.
			New("%s", bc.Message).
			WithMetadata(arkerrors.SdkVersionMetadata{
				ClientVersion: vals[0],
				MinVersion:    bc.MinVersion.String(),
				Method:        fullMethod,
			})
	}

	return nil
}

func unaryVersionCompatHandler() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context, req interface{},
		info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (interface{}, error) {
		if err := checkVersionCompat(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func streamVersionCompatHandler() grpc.StreamServerInterceptor {
	return func(
		srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler,
	) error {
		if err := checkVersionCompat(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}
