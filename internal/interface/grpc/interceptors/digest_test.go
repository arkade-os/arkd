package interceptors

import (
	"context"
	"errors"
	"testing"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	arkerrors "github.com/arkade-os/arkd/pkg/errors"
	middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// guardedMethod is an ArkService method that is NOT digest-exempt, used to
// exercise the digest check itself. (testMethod is GetInfo, which is exempt.)
const guardedMethod = "/ark.v1.ArkService/SubmitTx"

// digestCompatCase describes a single digest-guard scenario. Each case is run
// against both the unary and stream interceptors, which must behave identically
// since they share the same logic. All cases target an ArkService method (the
// only service the digest guard applies to).
type digestCompatCase struct {
	description string
	// guardEnabled and expectedDigest are what the provider returns.
	guardEnabled   bool
	expectedDigest string
	// ctx is the incoming context. Use ctxWithDigest to set a client header, or
	// context.Background() to simulate a missing header.
	ctx context.Context

	wantReject bool
	// The following are only asserted when wantReject is true.
	wantExpected string
	wantGot      string
}

func TestDigestCompat(t *testing.T) {
	testCases := []digestCompatCase{
		// --- Guard enabled: the client digest must match exactly ---
		{
			description:    "matching digest passes",
			guardEnabled:   true,
			expectedDigest: "abc123",
			ctx:            ctxWithDigest("abc123"),
		},
		{
			description:    "mismatched digest rejected",
			guardEnabled:   true,
			expectedDigest: "abc123",
			ctx:            ctxWithDigest("deadbeef"),
			wantReject:     true,
			wantExpected:   "abc123",
			wantGot:        "deadbeef",
		},
		{
			description:    "missing digest header rejected",
			guardEnabled:   true,
			expectedDigest: "abc123",
			ctx:            context.Background(),
			wantReject:     true,
			wantExpected:   "abc123",
			wantGot:        "",
		},
		{
			description:    "empty digest header value rejected",
			guardEnabled:   true,
			expectedDigest: "abc123",
			ctx:            ctxWithDigest(""),
			wantReject:     true,
			wantExpected:   "abc123",
			wantGot:        "",
		},
		{
			description:    "empty expected digest with no header passes",
			guardEnabled:   true,
			expectedDigest: "",
			ctx:            context.Background(),
		},
		{
			description:    "empty expected digest with a header rejected",
			guardEnabled:   true,
			expectedDigest: "",
			ctx:            ctxWithDigest("abc123"),
			wantReject:     true,
			wantExpected:   "",
			wantGot:        "abc123",
		},

		// --- Guard disabled: every request passes regardless of the header ---
		{
			description:    "disabled guard passes despite mismatch",
			guardEnabled:   false,
			expectedDigest: "abc123",
			ctx:            ctxWithDigest("deadbeef"),
		},
		{
			description:    "disabled guard passes with no header",
			guardEnabled:   false,
			expectedDigest: "abc123",
			ctx:            context.Background(),
		},
	}

	for _, tc := range testCases {
		getDigest := staticDigest(tc.expectedDigest, tc.guardEnabled)

		t.Run("unary/"+tc.description, func(t *testing.T) {
			called, err := runUnaryDigest(getDigest, tc.ctx, guardedMethod)
			assertDigestCompat(t, tc, called, err)
		})

		t.Run("stream/"+tc.description, func(t *testing.T) {
			called, err := runStreamDigest(getDigest, tc.ctx, guardedMethod)
			assertDigestCompat(t, tc, called, err)
		})
	}
}

// TestDigestSkipsNonArkService checks that only ArkService methods are digest
// guarded: admin-plane, indexer and health methods pass even with a strict
// guard and a wrong/absent digest, and without consulting the provider.
func TestDigestSkipsNonArkService(t *testing.T) {
	// A provider that would reject everything on ArkService if consulted.
	strict := staticDigest("expected-digest", true)

	nonArkMethods := []string{
		"/ark.v1.AdminService/Sweep",
		"/ark.v1.WalletService/GetBalance",
		"/ark.v1.IndexerService/GetVtxos",
		"/grpc.health.v1.Health/Check",
	}
	for _, method := range nonArkMethods {
		for _, ctx := range []context.Context{
			context.Background(), ctxWithDigest("wrong-digest"),
		} {
			called, err := runUnaryDigest(strict, ctx, method)
			require.NoError(t, err, method)
			require.True(t, called, method)

			called, err = runStreamDigest(strict, ctx, method)
			require.NoError(t, err, method)
			require.True(t, called, method)
		}
	}

	// Sanity check: the same strict guard rejects a wrong digest on ArkService.
	called, err := runUnaryDigest(strict, ctxWithDigest("wrong-digest"), guardedMethod)
	require.Error(t, err)
	require.False(t, called)
}

// TestDigestProviderError checks that when the digest provider fails (e.g. the
// settings cache is unreachable), guarded ArkService requests are rejected with
// an internal error and the handler is never invoked. The guard inspects the
// method before the provider, so non-ArkService methods still pass.
func TestDigestProviderError(t *testing.T) {
	failing := func() (string, bool, error) {
		return "", false, errors.New("settings cache unavailable")
	}

	t.Run("unary guarded request rejected", func(t *testing.T) {
		called, err := runUnaryDigest(failing, ctxWithDigest("whatever"), guardedMethod)
		require.Error(t, err)
		require.False(t, called)
	})

	t.Run("stream guarded request rejected", func(t *testing.T) {
		called, err := runStreamDigest(failing, ctxWithDigest("whatever"), guardedMethod)
		require.Error(t, err)
		require.False(t, called)
	})

	t.Run("non-ArkService method ignores provider error", func(t *testing.T) {
		called, err := runUnaryDigest(failing, context.Background(), "/ark.v1.AdminService/Sweep")
		require.NoError(t, err)
		require.True(t, called)
	})
}

// TestDigestExemptsGetInfo proves GetInfo stays reachable even with the digest
// guard enabled and a stale/empty/absent client digest. GetInfo is the only way a
// client learns the current server digest, so guarding it would lock fresh clients
// (and any client after a server config change) out permanently. The exemption
// also short-circuits before the provider, so GetInfo works even if the cache is
// down.
func TestDigestExemptsGetInfo(t *testing.T) {
	const getInfoMethod = "/ark.v1.ArkService/GetInfo"

	// Guard enabled with a server digest the client can't have yet.
	strict := staticDigest("server-digest", true)
	// Provider that errors, to prove GetInfo doesn't even consult it.
	failing := func() (string, bool, error) {
		return "", false, errors.New("settings cache unavailable")
	}

	cases := []struct {
		name      string
		getDigest func() (string, bool, error)
		ctx       context.Context
	}{
		{"guard on, no digest", strict, context.Background()},
		{"guard on, stale digest", strict, ctxWithDigest("stale")},
		{"guard on, empty digest", strict, ctxWithDigest("")},
		{"provider error", failing, context.Background()},
	}
	for _, c := range cases {
		t.Run("unary/"+c.name, func(t *testing.T) {
			called, err := runUnaryDigest(c.getDigest, c.ctx, getInfoMethod)
			require.NoError(t, err)
			require.True(t, called)
		})
		t.Run("stream/"+c.name, func(t *testing.T) {
			called, err := runStreamDigest(c.getDigest, c.ctx, getInfoMethod)
			require.NoError(t, err)
			require.True(t, called)
		})
	}
}

func assertDigestCompat(t *testing.T, tc digestCompatCase, called bool, err error) {
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
	require.Equal(t, arkerrors.DIGEST_MISMATCH.Code, sdkErr.Code())
	meta := sdkErr.Metadata()
	require.Equal(t, tc.wantExpected, meta["expected_digest"])
	require.Equal(t, tc.wantGot, meta["got_digest"])
	require.Contains(t, err.Error(), "invalid digest header")
}

// TestDigestMismatchReachesClient checks the client receives a proper status with details, not a bare Unknown. Chain mirrors UnaryInterceptor and must stay in sync.
func TestDigestMismatchReachesClient(t *testing.T) {
	chain := middleware.ChainUnaryServer(
		unaryPanicRecoveryInterceptor(),
		errorConverter,
		unaryLogger,
		unaryDigestHandler(staticDigest("server-digest", true)),
	)

	_, err := chain(
		ctxWithDigest("stale-digest"),
		nil,
		&grpc.UnaryServerInfo{FullMethod: guardedMethod},
		func(ctx context.Context, req any) (any, error) { return "ok", nil },
	)
	require.Error(t, err)

	st := status.Convert(err)
	require.Equal(t, codes.FailedPrecondition, st.Code())

	details := st.Details()
	require.NotEmpty(t, details, "client should receive structured error details")

	errDetails, ok := details[0].(*arkv1.ErrorDetails)
	require.True(t, ok)
	require.Equal(t, arkerrors.DIGEST_MISMATCH.Name, errDetails.GetName())
	require.Equal(t, "server-digest", errDetails.GetMetadata()["expected_digest"])
	require.Equal(t, "stale-digest", errDetails.GetMetadata()["got_digest"])
}

// runUnaryDigest runs the unary digest interceptor and reports whether the
// wrapped handler was invoked.
func runUnaryDigest(
	getDigest func() (string, bool, error), ctx context.Context, method string,
) (bool, error) {
	called := false
	_, err := unaryDigestHandler(getDigest)(
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

// runStreamDigest runs the stream digest interceptor and reports whether the
// wrapped handler was invoked.
func runStreamDigest(
	getDigest func() (string, bool, error), ctx context.Context, method string,
) (bool, error) {
	called := false
	err := streamDigestHandler(getDigest)(
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

// staticDigest adapts a fixed (expectedDigest, enabled) policy to the getDigest
// provider the interceptors expect.
func staticDigest(expected string, enabled bool) func() (string, bool, error) {
	return func() (string, bool, error) { return expected, enabled, nil }
}

func ctxWithDigest(digest string) context.Context {
	md := metadata.New(map[string]string{digestHeader: digest})
	return metadata.NewIncomingContext(context.Background(), md)
}
