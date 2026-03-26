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
	testCases := []struct {
		input     string
		wantMajor int64
		wantMinor int64
	}{
		{"1.0.0", 1, 0},
		{"v2.3.4", 2, 3},
		{"0.9.0", 0, 9},
		{"10.0.0", 10, 0},
		{"3", 3, 0},
	}
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			gotMajor, gotMinor, err := parseVersion(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.wantMajor, gotMajor)
			require.Equal(t, tc.wantMinor, gotMinor)
		})
	}

	for _, bad := range []string{"abc", ""} {
		_, _, err := parseVersion(bad)
		require.Error(t, err)
	}
}

func TestUnaryVersionCompat(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		testCases := []struct {
			description   string
			serverVersion string
			ctx           context.Context
		}{
			{
				description:   "no header passes through",
				serverVersion: "2.0.0",
				ctx:           context.Background(),
			},
			{
				description:   "same major version",
				serverVersion: "2.0.0",
				ctx:           ctxWithVersion("2.0.0"),
			},
			{
				description:   "higher client major version",
				serverVersion: "2.0.0",
				ctx:           ctxWithVersion("3.1.0"),
			},
			{
				description:   "same minor version",
				serverVersion: "2.1.0",
				ctx:           ctxWithVersion("2.1.0"),
			},
			{
				description:   "higher client minor version",
				serverVersion: "2.0.0",
				ctx:           ctxWithVersion("2.1.0"),
			},
			{
				description:   "higher patch version",
				serverVersion: "2.5.0",
				ctx:           ctxWithVersion("2.5.1"),
			},
			{
				description:   "lower patch version",
				serverVersion: "2.5.1",
				ctx:           ctxWithVersion("2.5.0"),
			},
			{
				description:   "malformed client version passes through",
				serverVersion: "2.0.0",
				ctx:           ctxWithVersion("not-a-version"),
			},
			{
				description:   "empty header value passes through",
				serverVersion: "2.0.0",
				ctx:           ctxWithVersion(""),
			},
			{
				description:   "unparsable server version allows all clients",
				serverVersion: "unknown",
				ctx:           ctxWithVersion("0.1.0"),
			},
			{
				description:   "empty server version allows all clients",
				serverVersion: "",
				ctx:           ctxWithVersion("0.1.0"),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				major, minor, _ := parseVersion(tc.serverVersion)

				interceptor := unaryVersionCompatHandler(major, minor, tc.serverVersion)
				called := false
				_, err := interceptor(
					tc.ctx,
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
	})

	t.Run("invalid", func(t *testing.T) {
		serverVersion := "2.1.0"
		major, minor, err := parseVersion(serverVersion)
		require.NoError(t, err)
		require.Equal(t, int64(2), major)
		require.Equal(t, int64(1), minor)

		testCases := []struct {
			description   string
			clientVersion string
		}{
			{
				description:   "client major below server major",
				clientVersion: "1.9.9",
			},
			{
				description:   "client major below server major with v prefix",
				clientVersion: "v1.8.0",
			},
			{
				description:   "client minor below server minor",
				clientVersion: "2.0.0",
			},
			{
				description:   "client minor below server minor with v prefix",
				clientVersion: "v2.0.0",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				require.NoError(t, err)
				interceptor := unaryVersionCompatHandler(major, minor, serverVersion)
				called := false
				_, err := interceptor(
					ctxWithVersion(tc.clientVersion),
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
				require.Equal(t, arkerrors.BUILD_VERSION_TOO_OLD.Code, sdkErr.Code())
				meta := sdkErr.Metadata()
				require.Equal(t, tc.clientVersion, meta["client_version"])
				require.Equal(t, serverVersion, meta["min_version"])
			})
		}
	})
}

func TestStreamVersionCompat(t *testing.T) {
	serverVersion := "2.1.1"
	major, minor, err := parseVersion(serverVersion)
	require.NoError(t, err)
	require.Equal(t, int64(2), major)
	require.Equal(t, int64(1), minor)

	t.Run("valid", func(t *testing.T) {
		testCases := []struct {
			description string
			ctx         context.Context
		}{
			{
				description: "no header passes through",
				ctx:         context.Background(),
			},
			{
				description: "same major version passes through",
				ctx:         ctxWithVersion("2.1.1"),
			},
			{
				description: "higher client major version",
				ctx:         ctxWithVersion("3.0.0"),
			},
			{
				description: "same minor version passes through",
				ctx:         ctxWithVersion("2.1.1"),
			},
			{
				description: "higher patch version",
				ctx:         ctxWithVersion("2.1.5"),
			},
			{
				description: "lower patch version",
				ctx:         ctxWithVersion("2.1.0"),
			},
			{
				description: "malformed client version passes through",
				ctx:         ctxWithVersion("not-a-version"),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				interceptor := streamVersionCompatHandler(major, minor, serverVersion)
				called := false
				err := interceptor(
					nil,
					&testServerStream{ctx: tc.ctx},
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
	})

	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			description   string
			clientVersion string
		}{
			{
				description:   "client major below server major",
				clientVersion: "1.7.0",
			},
			{
				description:   "client major below server major with v prefix",
				clientVersion: "v1.8.0",
			},
			{
				description:   "client minor below server minor",
				clientVersion: "2.0.0",
			},
			{
				description:   "client minor below server minor with v prefix",
				clientVersion: "v2.0.0",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				interceptor := streamVersionCompatHandler(major, minor, serverVersion)
				called := false
				err := interceptor(
					nil,
					&testServerStream{ctx: ctxWithVersion(tc.clientVersion)},
					&grpc.StreamServerInfo{FullMethod: testMethod},
					func(srv any, ss grpc.ServerStream) error {
						called = true
						return nil
					},
				)
				require.Error(t, err)
				require.False(t, called)

				var sdkErr arkerrors.Error
				require.True(t, errors.As(err, &sdkErr))
				require.Equal(t, arkerrors.BUILD_VERSION_TOO_OLD.Code, sdkErr.Code())
				meta := sdkErr.Metadata()
				require.Equal(t, tc.clientVersion, meta["client_version"])
				require.Equal(t, serverVersion, meta["min_version"])
			})
		}
	})
}

func ctxWithVersion(version string) context.Context {
	md := metadata.New(map[string]string{buildVersionHeader: version})
	return metadata.NewIncomingContext(context.Background(), md)
}
