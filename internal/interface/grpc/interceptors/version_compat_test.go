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

func ctxWithVersion(version string) context.Context {
	md := metadata.New(map[string]string{sdkVersionHeader: version})
	return metadata.NewIncomingContext(context.Background(), md)
}

func TestUnaryVersionCompat_NoHeader(t *testing.T) {
	interceptor := unaryVersionCompatHandler(2, "2.0.0")
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
}

func TestUnaryVersionCompat_SameMajorAllows(t *testing.T) {
	interceptor := unaryVersionCompatHandler(2, "2.0.0")
	called := false
	_, err := interceptor(
		ctxWithVersion("2.0.0"),
		nil,
		&grpc.UnaryServerInfo{FullMethod: testMethod},
		func(ctx context.Context, req any) (any, error) {
			called = true
			return "ok", nil
		},
	)
	require.NoError(t, err)
	require.True(t, called)
}

func TestUnaryVersionCompat_HigherMajorAllows(t *testing.T) {
	interceptor := unaryVersionCompatHandler(2, "2.0.0")
	called := false
	_, err := interceptor(
		ctxWithVersion("3.1.0"),
		nil,
		&grpc.UnaryServerInfo{FullMethod: testMethod},
		func(ctx context.Context, req any) (any, error) {
			called = true
			return "ok", nil
		},
	)
	require.NoError(t, err)
	require.True(t, called)
}

func TestUnaryVersionCompat_MinorPatchIgnored(t *testing.T) {
	// Server is 2.5.0, client is 2.0.0. Same major — should pass.
	interceptor := unaryVersionCompatHandler(2, "2.5.0")
	called := false
	_, err := interceptor(
		ctxWithVersion("2.0.0"),
		nil,
		&grpc.UnaryServerInfo{FullMethod: testMethod},
		func(ctx context.Context, req any) (any, error) {
			called = true
			return "ok", nil
		},
	)
	require.NoError(t, err)
	require.True(t, called)
}

func TestUnaryVersionCompat_BelowMajor(t *testing.T) {
	interceptor := unaryVersionCompatHandler(2, "2.0.0")
	called := false
	_, err := interceptor(
		ctxWithVersion("1.9.9"),
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
	require.Equal(t, "1.9.9", meta["client_version"])
	require.Equal(t, "2.0.0", meta["min_version"])
}

func TestUnaryVersionCompat_VPrefix(t *testing.T) {
	interceptor := unaryVersionCompatHandler(2, "2.0.0")
	called := false
	_, err := interceptor(
		ctxWithVersion("v1.8.0"),
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
	require.Equal(t, "v1.8.0", sdkErr.Metadata()["client_version"])
}

func TestUnaryVersionCompat_MalformedVersion(t *testing.T) {
	interceptor := unaryVersionCompatHandler(2, "2.0.0")
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
}

func TestUnaryVersionCompat_UnparsableServerVersion(t *testing.T) {
	// If the server version can't be parsed, major defaults to 0 — no rejection.
	interceptor := unaryVersionCompatHandler(0, "unknown")
	called := false
	_, err := interceptor(
		ctxWithVersion("0.1.0"),
		nil,
		&grpc.UnaryServerInfo{FullMethod: testMethod},
		func(ctx context.Context, req any) (any, error) {
			called = true
			return "ok", nil
		},
	)
	require.NoError(t, err)
	require.True(t, called)
}

func TestUnaryVersionCompat_EmptyServerVersion(t *testing.T) {
	// When no version is set via ldflags, Version is "". parseMajorVersion
	// fails, major defaults to 0, and all clients are allowed through.
	major, _ := parseMajorVersion("")
	interceptor := unaryVersionCompatHandler(major, "")
	called := false
	_, err := interceptor(
		ctxWithVersion("0.1.0"),
		nil,
		&grpc.UnaryServerInfo{FullMethod: testMethod},
		func(ctx context.Context, req any) (any, error) {
			called = true
			return "ok", nil
		},
	)
	require.NoError(t, err)
	require.True(t, called)
}

func TestStreamVersionCompat_BelowMajor(t *testing.T) {
	interceptor := streamVersionCompatHandler(2, "2.0.0")
	called := false
	err := interceptor(
		nil,
		&testServerStream{ctx: ctxWithVersion("1.7.0")},
		&grpc.StreamServerInfo{FullMethod: testMethod},
		func(srv any, ss grpc.ServerStream) error {
			called = true
			return nil
		},
	)
	require.Error(t, err)
	require.False(t, called)
}

func TestStreamVersionCompat_PassesThrough(t *testing.T) {
	interceptor := streamVersionCompatHandler(2, "2.0.0")
	called := false
	err := interceptor(
		nil,
		&testServerStream{ctx: ctxWithVersion("2.0.0")},
		&grpc.StreamServerInfo{FullMethod: testMethod},
		func(srv any, ss grpc.ServerStream) error {
			called = true
			return nil
		},
	)
	require.NoError(t, err)
	require.True(t, called)
}

func TestParseMajorVersion(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"1.0.0", 1},
		{"v2.3.4", 2},
		{"0.9.0", 0},
		{"10.0.0", 10},
		{"3", 3},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseMajorVersion(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}

	_, err := parseMajorVersion("abc")
	require.Error(t, err)
}
