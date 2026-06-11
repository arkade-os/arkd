package interceptors

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/arkade-os/arkd/internal/config"
	errors "github.com/arkade-os/arkd/pkg/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const buildVersionHeader = "x-build-version"

// VersionGuard holds the configuration for the build-version compatibility
// check. The threshold is always the server's own build version.
type VersionGuard struct {
	ServerVersion string
	RequireHeader bool
	Level         config.VersionGuardLevel
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

// isBehind reports whether the client version is behind the server version at
// the configured guard level.
func isBehind(
	level config.VersionGuardLevel,
	serverMajor, serverMinor, serverPatch int64,
	clientMajor, clientMinor, clientPatch int64,
) bool {
	if clientMajor != serverMajor {
		return clientMajor < serverMajor
	}
	if level == config.VersionGuardMajor {
		return false
	}
	if clientMinor != serverMinor {
		return clientMinor < serverMinor
	}
	if level == config.VersionGuardMinor {
		return false
	}
	return clientPatch < serverPatch
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

func buildVersionTooOld(
	clientVersion string,
	level config.VersionGuardLevel,
	serverMajor, serverMinor, serverPatch int64,
	serverVersion string,
) error {
	var minAllowedVersion string
	switch level {
	case config.VersionGuardMajor:
		minAllowedVersion = fmt.Sprintf("%d.0.0", serverMajor)
	case config.VersionGuardPatch:
		minAllowedVersion = fmt.Sprintf("%d.%d.%d", serverMajor, serverMinor, serverPatch)
	default: // default is minor
		minAllowedVersion = fmt.Sprintf("%d.%d.0", serverMajor, serverMinor)
	}
	return errors.BUILD_VERSION_TOO_OLD.
		New("server requires build version header >= %s", serverVersion).
		WithMetadata(errors.BuildVersionMetadata{
			ClientVersion: clientVersion,
			MinVersion:    minAllowedVersion,
		})
}

func checkVersionCompat(ctx context.Context, guard VersionGuard) error {
	serverMajor, serverMinor, serverPatch, err := parseVersion(guard.ServerVersion)
	if err != nil {
		// Server version unknown: cannot guard, allow all clients.
		return nil
	}

	headerVal, present := versionHeaderValue(ctx)
	if !present || headerVal == "" {
		if guard.RequireHeader {
			log.Debug("rejecting request: missing build version header")
			return buildVersionTooOld(
				"", guard.Level, serverMajor, serverMinor, serverPatch, guard.ServerVersion,
			)
		}
		return nil
	}

	clientMajor, clientMinor, clientPatch, err := parseVersion(headerVal)
	if err != nil {
		if guard.RequireHeader {
			log.Debugf("rejecting request: unparseable build version header %q", headerVal)
			return buildVersionTooOld(
				headerVal, guard.Level, serverMajor, serverMinor, serverPatch, guard.ServerVersion,
			)
		}
		return nil
	}

	if isBehind(
		guard.Level,
		serverMajor, serverMinor, serverPatch,
		clientMajor, clientMinor, clientPatch,
	) {
		log.Debugf(
			"rejecting request: build version %q below server %q at %s level",
			headerVal, guard.ServerVersion, guard.Level,
		)
		return buildVersionTooOld(
			headerVal, guard.Level, serverMajor, serverMinor, serverPatch, guard.ServerVersion,
		)
	}

	return nil
}

func unaryVersionCompatHandler(guard VersionGuard) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context, req interface{},
		info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (interface{}, error) {
		if err := checkVersionCompat(ctx, guard); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func streamVersionCompatHandler(guard VersionGuard) grpc.StreamServerInterceptor {
	return func(
		srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler,
	) error {
		if err := checkVersionCompat(ss.Context(), guard); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}
