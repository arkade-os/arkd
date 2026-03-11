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

// serviceMinVersions maps gRPC service full names (e.g. "ark.v1.ArkService")
// to a global minimum SDK version for all methods in that service.
// Populated at init time by scanning proto service options.
var serviceMinVersions map[string]BreakingChange

func init() {
	serviceMinVersions, breakingChanges = buildVersionMaps()
}

// buildVersionMaps discovers service_min_sdk_version and min_sdk_version
// annotations on all registered gRPC services and methods via proto reflection.
func buildVersionMaps() (map[string]BreakingChange, map[string]BreakingChange) {
	svcMap := make(map[string]BreakingChange)
	methodMap := make(map[string]BreakingChange)

	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			sd := services.Get(i)

			// Check service-level min_sdk_version.
			svcOpts, ok := sd.Options().(*descriptorpb.ServiceOptions)
			if ok && svcOpts != nil && proto.HasExtension(svcOpts, arkv1.E_ServiceMinSdkVersion) {
				ver := proto.GetExtension(svcOpts, arkv1.E_ServiceMinSdkVersion).(string)
				parsed, err := semver.NewVersion(ver)
				if err != nil {
					panic(fmt.Sprintf(
						"invalid service_min_sdk_version %q on %s: %v",
						ver, sd.FullName(), err,
					))
				}
				svcMap[string(sd.FullName())] = BreakingChange{
					MinVersion: *parsed,
					Message: fmt.Sprintf("service %s requires SDK version >= %s",
						sd.Name(), ver),
				}
			}

			// Check method-level min_sdk_version.
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
					panic(fmt.Sprintf(
						"invalid min_sdk_version %q on %s/%s: %v",
						ver, sd.FullName(), md.Name(), err,
					))
				}

				// Build the gRPC full method name: /<package>.<service>/<method>
				fullMethod := fmt.Sprintf("/%s/%s",
					sd.FullName(), md.Name())

				methodMap[fullMethod] = BreakingChange{
					MinVersion: *parsed,
					Message: fmt.Sprintf("%s requires SDK version >= %s",
						md.Name(), ver),
				}
			}
		}
		return true
	})

	return svcMap, methodMap
}

const sdkVersionHeader = "x-ark-sdk-version"

// serviceName extracts the service full name from a gRPC full method string.
// For example, "/ark.v1.ArkService/GetInfo" returns "ark.v1.ArkService".
func serviceName(fullMethod string) string {
	// fullMethod is "/<service>/<method>"
	name := strings.TrimPrefix(fullMethod, "/")
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		return name[:idx]
	}
	return name
}

func checkVersionCompat(ctx context.Context, fullMethod string) error {
	// Find the tightest constraint: pick whichever is higher between the
	// service-level and method-level minimum.
	var bc *BreakingChange
	if svc, ok := serviceMinVersions[serviceName(fullMethod)]; ok {
		bc = &svc
	}
	if method, ok := breakingChanges[fullMethod]; ok {
		if bc == nil || bc.MinVersion.LessThan(method.MinVersion) {
			bc = &method
		}
	}
	if bc == nil {
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
