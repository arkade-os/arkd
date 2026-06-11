package interceptors

import (
	"context"
	"errors"
	"testing"

	"github.com/arkade-os/arkd/internal/config"
	arkerrors "github.com/arkade-os/arkd/pkg/errors"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const testMethod = "/ark.v1.ArkService/TestMethod"

func TestNewVersionGuardMinAllowedVersion(t *testing.T) {
	testCases := []struct {
		serverVersion  string
		level          config.VersionGuardLevel
		wantMinVersion string
	}{
		{"2.3.4", config.VersionGuardMajor, "2.0.0"},
		{"2.3.4", config.VersionGuardMinor, "2.3.0"},
		{"2.3.4", config.VersionGuardPatch, "2.3.4"},
		{"v1.2.3-rc1", config.VersionGuardPatch, "1.2.3"},
	}
	for _, tc := range testCases {
		guard := NewVersionGuard(tc.serverVersion, true, tc.level)
		require.True(t, guard.enabled)
		require.Equal(t, tc.wantMinVersion, guard.minAllowedVersion)
		// The human-readable message must advertise the same threshold as the
		// min_version metadata field.
		require.Contains(
			t, buildVersionTooOld("", guard).Error(), ">= "+tc.wantMinVersion,
		)
	}

	for _, bad := range []string{"", "unknown"} {
		require.False(t, NewVersionGuard(bad, true, config.VersionGuardMinor).enabled)
	}
}

func TestParseVersion(t *testing.T) {
	testCases := []struct {
		input     string
		wantMajor int64
		wantMinor int64
		wantPatch int64
	}{
		{"1.0.0", 1, 0, 0},
		{"v2.3.4", 2, 3, 4},
		{"0.9.0", 0, 9, 0},
		{"10.0.0", 10, 0, 0},
		{"3", 3, 0, 0},
		{"2.5", 2, 5, 0},
		{"1.2.3-rc1", 1, 2, 3},
		{"v1.2.3+build9", 1, 2, 3},
	}
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			gotMajor, gotMinor, gotPatch, err := parseVersion(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.wantMajor, gotMajor)
			require.Equal(t, tc.wantMinor, gotMinor)
			require.Equal(t, tc.wantPatch, gotPatch)
		})
	}

	for _, bad := range []string{"abc", ""} {
		_, _, _, err := parseVersion(bad)
		require.Error(t, err)
	}
}

// versionCompatCase describes a single VersionGuard scenario. Each case is run
// against both the unary and stream interceptors, which must behave identically
// since they share checkVersionCompat.
type versionCompatCase struct {
	description   string
	serverVersion string
	level         config.VersionGuardLevel
	requireHeader bool
	// ctx is the incoming context. Use ctxWithVersion to set a client header,
	// or context.Background() to simulate a missing header.
	ctx context.Context

	wantReject bool
	// The following are only asserted when wantReject is true.
	wantClientVersion string
	wantMinVersion    string
}

func TestVersionCompat(t *testing.T) {
	testCases := []versionCompatCase{
		// --- Major guard level ---
		{
			description:   "major: client below server major rejected",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMajor,
			ctx:           ctxWithVersion("1.9.9"),
			wantReject:    true, wantClientVersion: "1.9.9", wantMinVersion: "2.0.0",
		},
		{
			description:   "major: lower minor passes (only major guarded)",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMajor,
			ctx:           ctxWithVersion("2.0.0"),
		},
		{
			description:   "major: same major passes",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMajor,
			ctx:           ctxWithVersion("2.3.4"),
		},
		{
			description:   "major: higher major passes",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMajor,
			ctx:           ctxWithVersion("3.0.0"),
		},

		// --- Minor guard level ---
		{
			description:   "minor: client below server major rejected",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMinor,
			ctx:           ctxWithVersion("1.9.9"),
			wantReject:    true, wantClientVersion: "1.9.9", wantMinVersion: "2.3.0",
		},
		{
			description:   "minor: client below server minor rejected",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMinor,
			ctx:           ctxWithVersion("2.2.9"),
			wantReject:    true, wantClientVersion: "2.2.9", wantMinVersion: "2.3.0",
		},
		{
			description:   "minor: client below server minor with v prefix rejected",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMinor,
			ctx:           ctxWithVersion("v2.0.0"),
			wantReject:    true, wantClientVersion: "v2.0.0", wantMinVersion: "2.3.0",
		},
		{
			description:   "minor: same minor lower patch passes",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMinor,
			ctx:           ctxWithVersion("2.3.0"),
		},
		{
			description:   "minor: higher minor passes",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMinor,
			ctx:           ctxWithVersion("2.4.0"),
		},

		// --- Patch guard level ---
		{
			description:   "patch: client below server patch rejected",
			serverVersion: "2.3.4",
			level:         config.VersionGuardPatch,
			ctx:           ctxWithVersion("2.3.3"),
			wantReject:    true, wantClientVersion: "2.3.3", wantMinVersion: "2.3.4",
		},
		{
			description:   "patch: client below server minor rejected",
			serverVersion: "2.3.4",
			level:         config.VersionGuardPatch,
			ctx:           ctxWithVersion("2.2.9"),
			wantReject:    true, wantClientVersion: "2.2.9", wantMinVersion: "2.3.4",
		},
		{
			description:   "patch: same patch passes",
			serverVersion: "2.3.4",
			level:         config.VersionGuardPatch,
			ctx:           ctxWithVersion("2.3.4"),
		},
		{
			description:   "patch: higher patch passes",
			serverVersion: "2.3.4",
			level:         config.VersionGuardPatch,
			ctx:           ctxWithVersion("2.3.5"),
		},

		// --- RequireHeader behavior ---
		{
			description:   "require header: missing header rejected",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMinor,
			requireHeader: true,
			ctx:           context.Background(),
			wantReject:    true, wantClientVersion: "", wantMinVersion: "2.3.0",
		},
		{
			description:   "require header: empty header value rejected",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMinor,
			requireHeader: true,
			ctx:           ctxWithVersion(""),
			wantReject:    true, wantClientVersion: "", wantMinVersion: "2.3.0",
		},
		{
			description:   "require header: unparseable header rejected",
			serverVersion: "2.3.4",
			level:         config.VersionGuardPatch,
			requireHeader: true,
			ctx:           ctxWithVersion("not-a-version"),
			wantReject:    true, wantClientVersion: "not-a-version", wantMinVersion: "2.3.4",
		},
		{
			description:   "require header: valid up-to-date header passes",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMinor,
			requireHeader: true,
			ctx:           ctxWithVersion("2.3.4"),
		},

		// --- Header optional (default) behavior ---
		{
			description:   "optional header: missing header passes",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMinor,
			ctx:           context.Background(),
		},
		{
			description:   "optional header: empty header value passes",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMinor,
			ctx:           ctxWithVersion(""),
		},
		{
			description:   "optional header: unparseable header passes",
			serverVersion: "2.3.4",
			level:         config.VersionGuardMinor,
			ctx:           ctxWithVersion("not-a-version"),
		},

		// --- Unparseable server version allows all clients ---
		{
			description:   "unparseable server version allows all clients",
			serverVersion: "unknown",
			level:         config.VersionGuardMinor,
			requireHeader: true,
			ctx:           ctxWithVersion("0.1.0"),
		},
		{
			description:   "empty server version allows all clients",
			serverVersion: "",
			level:         config.VersionGuardMinor,
			requireHeader: true,
			ctx:           context.Background(),
		},
	}

	for _, tc := range testCases {
		guard := NewVersionGuard(tc.serverVersion, tc.requireHeader, tc.level)

		t.Run("unary/"+tc.description, func(t *testing.T) {
			called, err := runUnaryGuard(guard, tc.ctx, testMethod)
			assertVersionCompat(t, tc, called, err)
		})

		t.Run("stream/"+tc.description, func(t *testing.T) {
			called, err := runStreamGuard(guard, tc.ctx, testMethod)
			assertVersionCompat(t, tc, called, err)
		})
	}
}

// TestVersionCompatSkipsAdminEndpoints checks that admin-plane and health
// methods bypass the guard even with an outdated client version and a strict
// require-header policy, while the public ArkService is still guarded.
func TestVersionCompatSkipsAdminEndpoints(t *testing.T) {
	guard := NewVersionGuard("2.3.4", true, config.VersionGuardMinor)

	skippedMethods := []string{
		"/ark.v1.AdminService/Sweep",
		"/ark.v1.WalletService/GetBalance",
		"/ark.v1.WalletInitializerService/Unlock",
		"/ark.v1.SignerManagerService/LoadSigner",
		"/grpc.health.v1.Health/Check",
	}
	for _, method := range skippedMethods {
		for _, ctx := range []context.Context{
			context.Background(), ctxWithVersion("0.0.1"),
		} {
			called, err := runUnaryGuard(guard, ctx, method)
			require.NoError(t, err, method)
			require.True(t, called, method)

			called, err = runStreamGuard(guard, ctx, method)
			require.NoError(t, err, method)
			require.True(t, called, method)
		}
	}

	// Sanity check: the same outdated client is rejected on a public service.
	called, err := runUnaryGuard(guard, ctxWithVersion("0.0.1"), testMethod)
	require.Error(t, err)
	require.False(t, called)
}

// runUnaryGuard runs the unary interceptor for guard with ctx and reports
// whether the wrapped handler was invoked.
func runUnaryGuard(guard VersionGuard, ctx context.Context, method string) (bool, error) {
	called := false
	_, err := unaryVersionCompatHandler(guard)(
		ctx,
		nil,
		&grpc.UnaryServerInfo{FullMethod: method},
		func(ctx context.Context, req any) (any, error) {
			called = true
			return "ok", nil
		},
	)
	return called, err
}

// runStreamGuard runs the stream interceptor for guard with ctx and reports
// whether the wrapped handler was invoked.
func runStreamGuard(guard VersionGuard, ctx context.Context, method string) (bool, error) {
	called := false
	err := streamVersionCompatHandler(guard)(
		nil,
		&testServerStream{ctx: ctx},
		&grpc.StreamServerInfo{FullMethod: method},
		func(srv any, ss grpc.ServerStream) error {
			called = true
			return nil
		},
	)
	return called, err
}

func assertVersionCompat(t *testing.T, tc versionCompatCase, called bool, err error) {
	t.Helper()
	if !tc.wantReject {
		require.NoError(t, err)
		require.True(t, called)
		return
	}

	require.Error(t, err)
	require.False(t, called)

	var sdkErr arkerrors.Error
	require.True(t, errors.As(err, &sdkErr))
	require.Equal(t, arkerrors.BUILD_VERSION_TOO_OLD.Code, sdkErr.Code())
	meta := sdkErr.Metadata()
	require.Equal(t, tc.wantClientVersion, meta["client_version"])
	require.Equal(t, tc.wantMinVersion, meta["min_version"])
}

func ctxWithVersion(version string) context.Context {
	md := metadata.New(map[string]string{buildVersionHeader: version})
	return metadata.NewIncomingContext(context.Background(), md)
}
