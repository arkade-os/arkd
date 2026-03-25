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

func TestUnaryVersionCompat(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		testCases := []struct {
			description   string
			serverMajor   int64
			serverVersion string
			ctx           context.Context
		}{
			{
				description:   "no header passes through",
				serverMajor:   2,
				serverVersion: "2.0.0",
				ctx:           context.Background(),
			},
			{
				description:   "same major version",
				serverMajor:   2,
				serverVersion: "2.0.0",
				ctx:           ctxWithVersion("2.0.0"),
			},
			{
				description:   "higher client major version",
				serverMajor:   2,
				serverVersion: "2.0.0",
				ctx:           ctxWithVersion("3.1.0"),
			},
			{
				description:   "minor and patch differences ignored on same major",
				serverMajor:   2,
				serverVersion: "2.5.0",
				ctx:           ctxWithVersion("2.0.0"),
			},
			{
				description:   "malformed client version passes through",
				serverMajor:   2,
				serverVersion: "2.0.0",
				ctx:           ctxWithVersion("not-a-version"),
			},
			{
				description:   "empty header value passes through",
				serverMajor:   2,
				serverVersion: "2.0.0",
				ctx:           ctxWithVersion(""),
			},
			{
				description:   "unparsable server version allows all clients",
				serverMajor:   0,
				serverVersion: "unknown",
				ctx:           ctxWithVersion("0.1.0"),
			},
			{
				description:   "empty server version allows all clients",
				serverMajor:   0,
				serverVersion: "",
				ctx:           ctxWithVersion("0.1.0"),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				interceptor := unaryVersionCompatHandler(tc.serverMajor, tc.serverVersion)
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
		testCases := []struct {
			description     string
			clientVersion   string
			expectedVersion string
			expectedMin     string
		}{
			{
				description:     "client major below server major",
				clientVersion:   "1.9.9",
				expectedVersion: "1.9.9",
				expectedMin:     "2.0.0",
			},
			{
				description:     "client major below server major with v prefix",
				clientVersion:   "v1.8.0",
				expectedVersion: "v1.8.0",
				expectedMin:     "2.0.0",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				interceptor := unaryVersionCompatHandler(2, "2.0.0")
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
				require.Equal(t, tc.expectedVersion, meta["client_version"])
				require.Equal(t, tc.expectedMin, meta["min_version"])
			})
		}
	})
}

func TestStreamVersionCompat(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		testCases := []struct {
			description   string
			serverMajor   int64
			serverVersion string
			ctx           context.Context
		}{
			{
				description:   "no header passes through",
				serverMajor:   2,
				serverVersion: "2.0.0",
				ctx:           context.Background(),
			},
			{
				description:   "same major version passes through",
				serverMajor:   2,
				serverVersion: "2.0.0",
				ctx:           ctxWithVersion("2.0.0"),
			},
			{
				description:   "higher client major version",
				serverMajor:   2,
				serverVersion: "2.0.0",
				ctx:           ctxWithVersion("3.0.0"),
			},
			{
				description:   "malformed client version passes through",
				serverMajor:   2,
				serverVersion: "2.0.0",
				ctx:           ctxWithVersion("not-a-version"),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				interceptor := streamVersionCompatHandler(tc.serverMajor, tc.serverVersion)
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
			description     string
			clientVersion   string
			expectedVersion string
			expectedMin     string
		}{
			{
				description:     "client major below server major",
				clientVersion:   "1.7.0",
				expectedVersion: "1.7.0",
				expectedMin:     "2.0.0",
			},
			{
				description:     "client major below server major with v prefix",
				clientVersion:   "v1.8.0",
				expectedVersion: "v1.8.0",
				expectedMin:     "2.0.0",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				interceptor := streamVersionCompatHandler(2, "2.0.0")
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
				require.Equal(t, tc.expectedVersion, meta["client_version"])
				require.Equal(t, tc.expectedMin, meta["min_version"])
			})
		}
	})
}

func TestParseMajorVersion(t *testing.T) {
	testCases := []struct {
		input string
		want  int64
	}{
		{"1.0.0", 1},
		{"v2.3.4", 2},
		{"0.9.0", 0},
		{"10.0.0", 10},
		{"3", 3},
	}
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseMajorVersion(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	for _, bad := range []string{"abc", ""} {
		_, err := parseMajorVersion(bad)
		require.Error(t, err)
	}
}

func ctxWithVersion(version string) context.Context {
	md := metadata.New(map[string]string{buildVersionHeader: version})
	return metadata.NewIncomingContext(context.Background(), md)
}
