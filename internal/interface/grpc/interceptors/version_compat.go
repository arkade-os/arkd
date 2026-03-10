package interceptors

import (
	"context"
	"fmt"
	"strings"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	arkerrors "github.com/arkade-os/arkd/pkg/errors"
	"github.com/coreos/go-semver/semver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// BreakingChange defines a minimum SDK version required for a given gRPC method.
type BreakingChange struct {
	MinVersion semver.Version
	Message    string
}

// breakingChanges maps gRPC full method names to their minimum required SDK version.
// Populated at init time by scanning proto method options.
var breakingChanges map[string]BreakingChange

func init() {
	breakingChanges = buildBreakingChanges()
}

// buildBreakingChanges discovers min_sdk_version annotations on all registered
// gRPC methods via proto reflection and returns the corresponding map.
func buildBreakingChanges() map[string]BreakingChange {
	out := make(map[string]BreakingChange)

	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			sd := services.Get(i)
			methods := sd.Methods()
			for j := 0; j < methods.Len(); j++ {
				md := methods.Get(j)
				opts, ok := md.Options().(*descriptorpb.MethodOptions)
				if !ok || opts == nil {
					continue
				}

				if !proto.HasExtension(opts, arkv1.E_MinSdkVersion) {
					continue
				}

				ver := proto.GetExtension(opts, arkv1.E_MinSdkVersion).(string)
				parsed, err := semver.NewVersion(ver)
				if err != nil {
					continue
				}

				// Build the gRPC full method name: /<package>.<service>/<method>
				fullMethod := fmt.Sprintf("/%s/%s",
					sd.FullName(), md.Name())

				out[fullMethod] = BreakingChange{
					MinVersion: *parsed,
					Message: fmt.Sprintf("%s requires SDK version >= %s",
						md.Name(), ver),
				}
			}
		}
		return true
	})

	return out
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
