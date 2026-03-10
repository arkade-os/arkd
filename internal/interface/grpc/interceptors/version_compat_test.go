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

func withBreakingChange(t *testing.T, minVersion string, fn func()) {
	t.Helper()
	breakingChanges[testMethod] = BreakingChange{
		MinVersion: *semver.New(minVersion),
		Message:    "TestMethod changed in v" + minVersion,
	}
	defer delete(breakingChanges, testMethod)
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
