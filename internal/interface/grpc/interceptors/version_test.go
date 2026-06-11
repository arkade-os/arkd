package interceptors

import (
	"context"
	"errors"
	"testing"

	arkerrors "github.com/arkade-os/arkd/pkg/errors"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const testMethod = "/ark.v1.ArkService/TestMethod"

func TestParseVersion(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
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
		for _, tt := range testCases {
			t.Run(tt.input, func(t *testing.T) {
				gotMajor, gotMinor, gotPatch, err := parseVersion(tt.input)
				require.NoError(t, err)
				require.Equal(t, tt.wantMajor, gotMajor)
				require.Equal(t, tt.wantMinor, gotMinor)
				require.Equal(t, tt.wantPatch, gotPatch)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, bad := range []string{"abc", ""} {
			t.Run(bad, func(t *testing.T) {
				_, _, _, err := parseVersion(bad)
				require.Error(t, err)
			})
		}
	})
}

// versionCompatCase describes a single VersionGuard scenario. Each case is run
// against both the unary and stream interceptors, which must behave identically
// since they share checkVersionCompat.
type versionCompatCase struct {
	description string
	// minVersion is the configured minimum build version clients must send.
	minVersion    string
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
		// --- Client below the minimum is rejected ---
		{
			description:       "client below min major rejected",
			minVersion:        "2.3.4",
			ctx:               ctxWithVersion("1.9.9"),
			wantReject:        true,
			wantClientVersion: "1.9.9",
			wantMinVersion:    "2.3.4",
		},
		{
			description:       "client below min minor rejected",
			minVersion:        "2.3.4",
			ctx:               ctxWithVersion("2.2.9"),
			wantReject:        true,
			wantClientVersion: "2.2.9",
			wantMinVersion:    "2.3.4",
		},
		{
			description:       "client below min patch rejected",
			minVersion:        "2.3.4",
			ctx:               ctxWithVersion("2.3.3"),
			wantReject:        true,
			wantClientVersion: "2.3.3",
			wantMinVersion:    "2.3.4",
		},
		{
			description:       "client below min with v prefix rejected",
			minVersion:        "2.3.4",
			ctx:               ctxWithVersion("v2.0.0"),
			wantReject:        true,
			wantClientVersion: "v2.0.0",
			wantMinVersion:    "2.3.4",
		},

		// --- Configured min version is normalized to major.minor.patch ---
		{
			description:       "min without patch normalized, client below rejected",
			minVersion:        "2.3",
			ctx:               ctxWithVersion("2.2.9"),
			wantReject:        true,
			wantClientVersion: "2.2.9",
			wantMinVersion:    "2.3.0",
		},
		{
			description: "min without patch normalized, client at threshold passes",
			minVersion:  "2.3",
			ctx:         ctxWithVersion("2.3.0"),
		},
		{
			description:       "min with v prefix and pre-release normalized, client below rejected",
			minVersion:        "v1.2.3-rc1",
			ctx:               ctxWithVersion("1.2.2"),
			wantReject:        true,
			wantClientVersion: "1.2.2",
			wantMinVersion:    "1.2.3",
		},
		{
			description: "min with v prefix and pre-release normalized, client at threshold passes",
			minVersion:  "v1.2.3-rc1",
			ctx:         ctxWithVersion("1.2.3"),
		},

		// --- Client at or above the minimum passes ---
		{
			description: "client equal to min passes",
			minVersion:  "2.3.4",
			ctx:         ctxWithVersion("2.3.4"),
		},
		{
			description: "client higher patch passes",
			minVersion:  "2.3.4",
			ctx:         ctxWithVersion("2.3.5"),
		},
		{
			description: "client higher minor passes despite lower patch",
			minVersion:  "2.3.4",
			ctx:         ctxWithVersion("2.4.0"),
		},
		{
			description: "client higher major passes despite lower minor and patch",
			minVersion:  "2.3.4",
			ctx:         ctxWithVersion("3.0.0"),
		},

		// --- RequireHeader behavior ---
		{
			description:    "require header: missing header rejected",
			minVersion:     "2.3.4",
			requireHeader:  true,
			ctx:            context.Background(),
			wantReject:     true,
			wantMinVersion: "2.3.4",
		},
		{
			description:    "require header: empty header value rejected",
			minVersion:     "2.3.4",
			requireHeader:  true,
			ctx:            ctxWithVersion(""),
			wantReject:     true,
			wantMinVersion: "2.3.4",
		},
		{
			description:       "require header: unparseable header rejected",
			minVersion:        "2.3.4",
			requireHeader:     true,
			ctx:               ctxWithVersion("not-a-version"),
			wantReject:        true,
			wantClientVersion: "not-a-version",
			wantMinVersion:    "2.3.4",
		},
		{
			description:   "require header: valid up-to-date header passes",
			minVersion:    "2.3.4",
			requireHeader: true,
			ctx:           ctxWithVersion("2.3.4"),
		},

		// --- Header optional (default) behavior ---
		{
			description: "optional header: missing header passes",
			minVersion:  "2.3.4",
			ctx:         context.Background(),
		},
		{
			description: "optional header: empty header value passes",
			minVersion:  "2.3.4",
			ctx:         ctxWithVersion(""),
		},
		{
			description: "optional header: unparseable header passes",
			minVersion:  "2.3.4",
			ctx:         ctxWithVersion("not-a-version"),
		},

		// --- Unparseable min version allows all clients ---
		{
			description:   "unparseable min version allows all clients",
			minVersion:    "unknown",
			requireHeader: true,
			ctx:           ctxWithVersion("0.1.0"),
		},
		{
			description:   "empty min version allows all clients",
			minVersion:    "",
			requireHeader: true,
			ctx:           context.Background(),
		},
	}

	for _, tc := range testCases {
		guard := NewVersionGuard(tc.minVersion, tc.requireHeader)

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
	guard := NewVersionGuard("2.3.4", true)

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
	// The human-readable message must advertise the same threshold as the
	// min_version metadata field.
	require.Contains(t, err.Error(), ">= "+tc.wantMinVersion)
}

func ctxWithVersion(version string) context.Context {
	md := metadata.New(map[string]string{buildVersionHeader: version})
	return metadata.NewIncomingContext(context.Background(), md)
}
