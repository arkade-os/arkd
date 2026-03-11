package interceptors

import (
	"context"
	"errors"
	"testing"

	arkerrors "github.com/arkade-os/arkd/pkg/errors"
	"github.com/coreos/go-semver/semver"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const testMethod = "/ark.v1.ArkService/TestMethod"
const testService = "ark.v1.ArkService"

// Integration tests: verify buildVersionMaps picks up real proto annotations
// from test_version_compat.proto (TestVersionService).

const (
	testVersionSvc     = "ark.v1.TestVersionService"
	breakingMethodFull = "/ark.v1.TestVersionService/BreakingMethod"
	stableMethodFull   = "/ark.v1.TestVersionService/StableMethod"
)

func TestBuildVersionMaps_ServiceAnnotation(t *testing.T) {
	svcMap, _ := buildVersionMaps()
	bc, ok := svcMap[testVersionSvc]
	require.True(t, ok, "expected service-level entry for %s", testVersionSvc)
	require.Equal(t, "1.0.0", bc.MinVersion.String())
}

func TestBuildVersionMaps_MethodAnnotation(t *testing.T) {
	_, methodMap := buildVersionMaps()
	bc, ok := methodMap[breakingMethodFull]
	require.True(t, ok, "expected method-level entry for %s", breakingMethodFull)
	require.Equal(t, "2.0.0", bc.MinVersion.String())
}

func TestBuildVersionMaps_UnannotatedMethod(t *testing.T) {
	_, methodMap := buildVersionMaps()
	_, ok := methodMap[stableMethodFull]
	require.False(t, ok, "StableMethod has no method-level annotation")
}

func TestIntegration_StableMethod_ServiceMinRejects(t *testing.T) {
	// StableMethod has no method annotation, but the service requires 1.0.0.
	// A client at 0.5.0 should be rejected.
	interceptor := unaryVersionCompatHandler()
	called := false
	_, err := interceptor(
		ctxWithVersion("0.5.0"),
		nil,
		&grpc.UnaryServerInfo{FullMethod: stableMethodFull},
		func(ctx context.Context, req any) (any, error) {
			called = true
			return "ok", nil
		},
	)
	require.Error(t, err)
	require.False(t, called)

	var sdkErr arkerrors.Error
	require.True(t, errors.As(err, &sdkErr))
	require.Equal(t, arkerrors.SDK_VERSION_TOO_OLD.Code, sdkErr.Code())
	require.Equal(t, "1.0.0", sdkErr.Metadata()["min_version"])
}

func TestIntegration_StableMethod_ServiceMinAllows(t *testing.T) {
	// Client at 1.0.0 meets the service minimum, should pass.
	interceptor := unaryVersionCompatHandler()
	called := false
	_, err := interceptor(
		ctxWithVersion("1.0.0"),
		nil,
		&grpc.UnaryServerInfo{FullMethod: stableMethodFull},
		func(ctx context.Context, req any) (any, error) {
			called = true
			return "ok", nil
		},
	)
	require.NoError(t, err)
	require.True(t, called)
}

func TestIntegration_BreakingMethod_MethodMinWins(t *testing.T) {
	// BreakingMethod requires 2.0.0 (method) while service requires 1.0.0.
	// A client at 1.5.0 passes the service check but fails the method check.
	interceptor := unaryVersionCompatHandler()
	called := false
	_, err := interceptor(
		ctxWithVersion("1.5.0"),
		nil,
		&grpc.UnaryServerInfo{FullMethod: breakingMethodFull},
		func(ctx context.Context, req any) (any, error) {
			called = true
			return "ok", nil
		},
	)
	require.Error(t, err)
	require.False(t, called)

	var sdkErr arkerrors.Error
	require.True(t, errors.As(err, &sdkErr))
	require.Equal(t, "2.0.0", sdkErr.Metadata()["min_version"])
}

func TestIntegration_BreakingMethod_AboveBoth(t *testing.T) {
	// Client at 2.0.0 meets both service and method minimums.
	interceptor := unaryVersionCompatHandler()
	called := false
	_, err := interceptor(
		ctxWithVersion("2.0.0"),
		nil,
		&grpc.UnaryServerInfo{FullMethod: breakingMethodFull},
		func(ctx context.Context, req any) (any, error) {
			called = true
			return "ok", nil
		},
	)
	require.NoError(t, err)
	require.True(t, called)
}

func withBreakingChange(t *testing.T, minVersion string, fn func()) {
	t.Helper()
	breakingChanges[testMethod] = BreakingChange{
		MinVersion: *semver.New(minVersion),
		Message:    "TestMethod changed in v" + minVersion,
	}
	defer delete(breakingChanges, testMethod)
	fn()
}

func withServiceMinVersion(t *testing.T, minVersion string, fn func()) {
	t.Helper()
	serviceMinVersions[testService] = BreakingChange{
		MinVersion: *semver.New(minVersion),
		Message:    "service ArkService requires SDK version >= " + minVersion,
	}
	defer delete(serviceMinVersions, testService)
	fn()
}

func ctxWithVersion(version string) context.Context {
	md := metadata.New(map[string]string{sdkVersionHeader: version})
	return metadata.NewIncomingContext(context.Background(), md)
}

func TestUnaryVersionCompat_NoHeader(t *testing.T) {
	withBreakingChange(t, "0.9.0", func() {
		interceptor := unaryVersionCompatHandler()
		called := false
		_, err := interceptor(
			context.Background(),
			nil,
			&grpc.UnaryServerInfo{FullMethod: testMethod},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return "ok", nil
			},
		)
		require.NoError(t, err)
		require.True(t, called)
	})
}

func TestUnaryVersionCompat_AboveMinimum(t *testing.T) {
	withBreakingChange(t, "0.9.0", func() {
		interceptor := unaryVersionCompatHandler()
		called := false
		_, err := interceptor(
			ctxWithVersion("0.10.0"),
			nil,
			&grpc.UnaryServerInfo{FullMethod: testMethod},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return "ok", nil
			},
		)
		require.NoError(t, err)
		require.True(t, called)
	})
}

func TestUnaryVersionCompat_EqualToMinimum(t *testing.T) {
	withBreakingChange(t, "0.9.0", func() {
		interceptor := unaryVersionCompatHandler()
		called := false
		_, err := interceptor(
			ctxWithVersion("0.9.0"),
			nil,
			&grpc.UnaryServerInfo{FullMethod: testMethod},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return "ok", nil
			},
		)
		require.NoError(t, err)
		require.True(t, called)
	})
}

func TestUnaryVersionCompat_BelowMinimum(t *testing.T) {
	withBreakingChange(t, "0.9.0", func() {
		interceptor := unaryVersionCompatHandler()
		called := false
		_, err := interceptor(
			ctxWithVersion("0.8.0"),
			nil,
			&grpc.UnaryServerInfo{FullMethod: testMethod},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return "ok", nil
			},
		)
		require.Error(t, err)
		require.False(t, called)

		var sdkErr arkerrors.Error
		require.True(t, errors.As(err, &sdkErr))
		require.Equal(t, arkerrors.SDK_VERSION_TOO_OLD.Code, sdkErr.Code())
		meta := sdkErr.Metadata()
		require.Equal(t, "0.8.0", meta["client_version"])
		require.Equal(t, "0.9.0", meta["min_version"])
		require.Equal(t, testMethod, meta["method"])
	})
}

func TestUnaryVersionCompat_VPrefix(t *testing.T) {
	withBreakingChange(t, "0.9.0", func() {
		interceptor := unaryVersionCompatHandler()
		called := false
		_, err := interceptor(
			ctxWithVersion("v0.8.0"),
			nil,
			&grpc.UnaryServerInfo{FullMethod: testMethod},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return "ok", nil
			},
		)
		require.Error(t, err)
		require.False(t, called)

		var sdkErr arkerrors.Error
		require.True(t, errors.As(err, &sdkErr))
		require.Equal(t, "v0.8.0", sdkErr.Metadata()["client_version"])
	})
}

func TestUnaryVersionCompat_MalformedVersion(t *testing.T) {
	withBreakingChange(t, "0.9.0", func() {
		interceptor := unaryVersionCompatHandler()
		called := false
		_, err := interceptor(
			ctxWithVersion("not-a-version"),
			nil,
			&grpc.UnaryServerInfo{FullMethod: testMethod},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return "ok", nil
			},
		)
		require.NoError(t, err)
		require.True(t, called)
	})
}

func TestUnaryVersionCompat_MethodNotInRegistry(t *testing.T) {
	interceptor := unaryVersionCompatHandler()
	called := false
	_, err := interceptor(
		ctxWithVersion("0.1.0"),
		nil,
		&grpc.UnaryServerInfo{FullMethod: "/ark.v1.ArkService/UnregisteredMethod"},
		func(ctx context.Context, req any) (any, error) {
			called = true
			return "ok", nil
		},
	)
	require.NoError(t, err)
	require.True(t, called)
}

func TestStreamVersionCompat_BelowMinimum(t *testing.T) {
	withBreakingChange(t, "0.9.0", func() {
		interceptor := streamVersionCompatHandler()
		called := false
		err := interceptor(
			nil,
			&testServerStream{ctx: ctxWithVersion("0.7.0")},
			&grpc.StreamServerInfo{FullMethod: testMethod},
			func(srv any, ss grpc.ServerStream) error {
				called = true
				return nil
			},
		)
		require.Error(t, err)
		require.False(t, called)
	})
}

func TestStreamVersionCompat_PassesThrough(t *testing.T) {
	withBreakingChange(t, "0.9.0", func() {
		interceptor := streamVersionCompatHandler()
		called := false
		err := interceptor(
			nil,
			&testServerStream{ctx: ctxWithVersion("1.0.0")},
			&grpc.StreamServerInfo{FullMethod: testMethod},
			func(srv any, ss grpc.ServerStream) error {
				called = true
				return nil
			},
		)
		require.NoError(t, err)
		require.True(t, called)
	})
}

// Service-level minimum version tests.

func TestServiceMinVersion_BelowMinimum(t *testing.T) {
	withServiceMinVersion(t, "1.0.0", func() {
		interceptor := unaryVersionCompatHandler()
		called := false
		_, err := interceptor(
			ctxWithVersion("0.8.0"),
			nil,
			&grpc.UnaryServerInfo{FullMethod: testMethod},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return "ok", nil
			},
		)
		require.Error(t, err)
		require.False(t, called)

		var sdkErr arkerrors.Error
		require.True(t, errors.As(err, &sdkErr))
		require.Equal(t, arkerrors.SDK_VERSION_TOO_OLD.Code, sdkErr.Code())
		require.Equal(t, "0.8.0", sdkErr.Metadata()["client_version"])
		require.Equal(t, "1.0.0", sdkErr.Metadata()["min_version"])
	})
}

func TestServiceMinVersion_AboveMinimum(t *testing.T) {
	withServiceMinVersion(t, "1.0.0", func() {
		interceptor := unaryVersionCompatHandler()
		called := false
		_, err := interceptor(
			ctxWithVersion("1.1.0"),
			nil,
			&grpc.UnaryServerInfo{FullMethod: testMethod},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return "ok", nil
			},
		)
		require.NoError(t, err)
		require.True(t, called)
	})
}

func TestServiceMinVersion_NoHeader(t *testing.T) {
	withServiceMinVersion(t, "1.0.0", func() {
		interceptor := unaryVersionCompatHandler()
		called := false
		_, err := interceptor(
			context.Background(),
			nil,
			&grpc.UnaryServerInfo{FullMethod: testMethod},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return "ok", nil
			},
		)
		require.NoError(t, err)
		require.True(t, called)
	})
}

func TestServiceMinVersion_MethodOverridesHigher(t *testing.T) {
	// Service requires 1.0.0, method requires 2.0.0.
	// The method-level constraint wins since it's higher.
	withServiceMinVersion(t, "1.0.0", func() {
		withBreakingChange(t, "2.0.0", func() {
			interceptor := unaryVersionCompatHandler()
			called := false
			_, err := interceptor(
				ctxWithVersion("1.5.0"),
				nil,
				&grpc.UnaryServerInfo{FullMethod: testMethod},
				func(ctx context.Context, req any) (any, error) {
					called = true
					return "ok", nil
				},
			)
			require.Error(t, err)
			require.False(t, called)

			var sdkErr arkerrors.Error
			require.True(t, errors.As(err, &sdkErr))
			require.Equal(t, "2.0.0", sdkErr.Metadata()["min_version"])
		})
	})
}

func TestServiceMinVersion_ServiceHigherThanMethod(t *testing.T) {
	// Service requires 2.0.0, method requires 1.0.0.
	// The service-level constraint wins since it's higher.
	withServiceMinVersion(t, "2.0.0", func() {
		withBreakingChange(t, "1.0.0", func() {
			interceptor := unaryVersionCompatHandler()
			called := false
			_, err := interceptor(
				ctxWithVersion("1.5.0"),
				nil,
				&grpc.UnaryServerInfo{FullMethod: testMethod},
				func(ctx context.Context, req any) (any, error) {
					called = true
					return "ok", nil
				},
			)
			require.Error(t, err)
			require.False(t, called)

			var sdkErr arkerrors.Error
			require.True(t, errors.As(err, &sdkErr))
			require.Equal(t, "2.0.0", sdkErr.Metadata()["min_version"])
		})
	})
}

func TestServiceName(t *testing.T) {
	require.Equal(t, "ark.v1.ArkService", serviceName("/ark.v1.ArkService/GetInfo"))
	require.Equal(t, "ark.v1.IndexerService", serviceName("/ark.v1.IndexerService/GetVtxos"))
	require.Equal(t, "foo", serviceName("/foo/bar"))
}
