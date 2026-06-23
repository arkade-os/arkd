package interceptors

import (
	"context"
	"testing"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	arkerrors "github.com/arkade-os/arkd/pkg/errors"
	middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestDigestMismatchReachesClient checks the client receives a proper status with details
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

// TestStreamDigestMismatchReachesClient is the stream counterpart
func TestStreamDigestMismatchReachesClient(t *testing.T) {
	chain := middleware.ChainStreamServer(
		streamPanicRecoveryInterceptor(),
		streamErrorConverter,
		streamLogger,
		streamDigestHandler(staticDigest("server-digest", true)),
	)

	err := chain(
		nil,
		&testServerStream{ctx: ctxWithDigest("stale-digest")},
		&grpc.StreamServerInfo{FullMethod: guardedMethod},
		func(srv any, ss grpc.ServerStream) error { return nil },
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
