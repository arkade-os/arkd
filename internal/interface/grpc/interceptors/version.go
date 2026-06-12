package interceptors

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	errors "github.com/arkade-os/arkd/pkg/errors"
	"google.golang.org/grpc"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

const buildVersionHeader = "x-build-version"

// versionGuardSkippedServices lists the admin-plane services (plus health
// checks) that are exempt from the build-version compatibility check: they are
// driven by operators and infrastructure, not by versioned SDK clients.
var versionGuardSkippedServices = map[string]struct{}{
	arkv1.AdminService_ServiceDesc.ServiceName:             {},
	arkv1.WalletService_ServiceDesc.ServiceName:            {},
	arkv1.WalletInitializerService_ServiceDesc.ServiceName: {},
	arkv1.SignerManagerService_ServiceDesc.ServiceName:     {},
	grpchealth.Health_ServiceDesc.ServiceName:              {},
}

// skipVersionGuard reports whether fullMethod ("/package.Service/Method")
// belongs to a service exempt from the version guard.
func skipVersionGuard(fullMethod string) bool {
	svc := strings.TrimPrefix(fullMethod, "/")
	if i := strings.Index(svc, "/"); i >= 0 {
		svc = svc[:i]
	}
	_, ok := versionGuardSkippedServices[svc]
	return ok
}

// VersionGuard holds the configuration for the build-version compatibility
// check. The threshold is always the server's own build version. Use
// NewVersionGuard to construct it: the server version is parsed once there
// instead of on every request.
type VersionGuard struct {
	BuilldVersion string
	RequireHeader bool

	serverMajor, serverMinor, serverPatch int64
	// // minAllowedVersion is the lowest client version accepted at the
	// // configured guard level, e.g. "2.3.0" for server 2.3.4 at minor level.
	// minAllowedVersion string
}

// NewVersionGuard builds a VersionGuard, pre-parsing serverVersion and
// pre-computing the minimum allowed client version for the given level.
func NewVersionGuard(
	serverVersion string, requireHeader bool,
) VersionGuard {
	guard := VersionGuard{
		BuilldVersion: serverVersion,
		RequireHeader: requireHeader,
	}
	major, minor, patch, err := parseVersion(serverVersion)
	if err != nil {
		// Server version unknown: cannot guard, allow all clients.
		return guard
	}
	guard.serverMajor, guard.serverMinor, guard.serverPatch = major, minor, patch
	return guard
}

// parseVersion extracts major, minor and patch from a semver-ish string.
// Accepts "1.0.0", "v1.0.0", "1", "1.2", and tolerates pre-release/build
// suffixes on the patch component (e.g. "1.2.3-rc1" -> patch 3). Returns an
// error only when the major component is unparseable.
func parseVersion(ver string) (int64, int64, int64, error) {
	ver = strings.TrimPrefix(ver, "v")
	parts := strings.Split(ver, ".")
	major, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("cannot parse major version from %q: %w", ver, err)
	}

	var minor, patch int64
	if len(parts) >= 2 {
		minor, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("cannot parse minor version from %q: %w", ver, err)
		}
	}
	if len(parts) >= 3 {
		patch, err = parseLeadingInt(parts[2])
		if err != nil {
			return 0, 0, 0, fmt.Errorf("cannot parse patch version from %q: %w", ver, err)
		}
	}
	return major, minor, patch, nil
}

// parseLeadingInt parses the leading run of digits in s, ignoring any
// pre-release/build suffix (e.g. "3-rc1" -> 3, "3+build" -> 3).
func parseLeadingInt(s string) (int64, error) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("no numeric prefix in %q", s)
	}
	return strconv.ParseInt(s[:i], 10, 64)
}

// isBehind reports whether the client version is strictly lower than the
// minimum required version, comparing major, then minor, then patch.
func isBehind(guard VersionGuard, clientMajor, clientMinor, clientPatch int64) bool {
	if clientMajor != guard.serverMajor {
		return clientMajor < guard.serverMajor
	}
	if clientMinor != guard.serverMinor {
		return clientMinor < guard.serverMinor
	}
	return clientPatch < guard.serverPatch
}

// versionHeaderValue returns the first x-build-version header value and whether
// the header was present at all.
func versionHeaderValue(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	vals := md.Get(buildVersionHeader)
	if len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}

func buildVersionTooOld(clientVersion string, guard VersionGuard) error {
	return errors.BUILD_VERSION_TOO_OLD.
		New("server requires build version header >= %s", guard.BuilldVersion).
		WithMetadata(errors.BuildVersionMetadata{
			ClientVersion: clientVersion,
			MinVersion:    guard.BuilldVersion,
		})
}

func checkVersionCompat(ctx context.Context, fullMethod string, guard VersionGuard) error {
	if !guard.RequireHeader || skipVersionGuard(fullMethod) {
		return nil
	}

	headerVal, present := versionHeaderValue(ctx)
	if !present || headerVal == "" {
		if guard.RequireHeader {
			return buildVersionTooOld("", guard)
		}
		return nil
	}

	clientMajor, clientMinor, clientPatch, err := parseVersion(headerVal)
	if err != nil {
		return buildVersionTooOld(headerVal, guard)
	}

	if isBehind(guard, clientMajor, clientMinor, clientPatch) {
		return buildVersionTooOld(headerVal, guard)
	}

	return nil
}

func unaryVersionCompatHandler(
	getVersionGuard func() (*VersionGuard, error),
) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context, req interface{},
		info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (interface{}, error) {
		guard, err := getVersionGuard()
		if err != nil {
			return nil, errors.INTERNAL_ERROR.New("failed to verify version header, retry later")
		}
		if err := checkVersionCompat(ctx, info.FullMethod, *guard); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func streamVersionCompatHandler(
	getVersionGuard func() (*VersionGuard, error),
) grpc.StreamServerInterceptor {
	return func(
		srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler,
	) error {
		guard, err := getVersionGuard()
		if err != nil {
			return errors.INTERNAL_ERROR.New("failed to verify version header, retry later")
		}
		if err := checkVersionCompat(ss.Context(), info.FullMethod, *guard); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}
