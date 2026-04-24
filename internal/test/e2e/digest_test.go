package e2e_test

import (
	"testing"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestDigestValidation(t *testing.T) {
	conn, err := grpc.NewClient(
		serverUrl,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	svc := arkv1.NewArkServiceClient(conn)
	ctx := t.Context()

	// Call GetInfo to get the current digest and seed the server's digest store.
	info, err := svc.GetInfo(ctx, &arkv1.GetInfoRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, info.GetDigest())

	digest := info.GetDigest()

	t.Run("no header passes (opt-in)", func(t *testing.T) {
		// Calling GetInfo without the digest header should always succeed.
		resp, err := svc.GetInfo(t.Context(), &arkv1.GetInfoRequest{})
		require.NoError(t, err)
		require.NotEmpty(t, resp.GetDigest())
	})

	t.Run("correct digest header passes", func(t *testing.T) {
		// Attach the correct digest and call a non-GetInfo ArkService method.
		// Even though the request payload is empty and will fail validation,
		// the error should come from the handler (InvalidArgument), not from
		// the digest interceptor (FailedPrecondition).
		mdCtx := metadata.NewOutgoingContext(
			t.Context(),
			metadata.Pairs("x-ark-digest", digest),
		)

		_, err := svc.RegisterIntent(mdCtx, &arkv1.RegisterIntentRequest{})
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		// Handler rejects the empty request as InvalidArgument, not FailedPrecondition.
		require.Equal(t, codes.InvalidArgument, st.Code(),
			"expected a handler error, not a digest mismatch")
	})

	t.Run("stale digest header returns DIGEST_MISMATCH", func(t *testing.T) {
		mdCtx := metadata.NewOutgoingContext(
			t.Context(),
			metadata.Pairs("x-ark-digest", "stale-digest-value"),
		)

		_, err := svc.RegisterIntent(mdCtx, &arkv1.RegisterIntentRequest{})
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.FailedPrecondition, st.Code())

		// Extract structured error details.
		details := st.Details()
		require.NotEmpty(t, details)

		errDetails, ok := details[0].(*arkv1.ErrorDetails)
		require.True(t, ok)
		require.Equal(t, int32(49), errDetails.Code)
		require.Equal(t, "DIGEST_MISMATCH", errDetails.Name)
		require.Equal(t, digest, errDetails.Metadata["current_digest"])
	})

	t.Run("GetInfo always allowed even with wrong digest", func(t *testing.T) {
		mdCtx := metadata.NewOutgoingContext(
			t.Context(),
			metadata.Pairs("x-ark-digest", "completely-wrong"),
		)

		resp, err := svc.GetInfo(mdCtx, &arkv1.GetInfoRequest{})
		require.NoError(t, err)
		require.NotEmpty(t, resp.GetDigest())
	})

	t.Run("stale digest on stream returns DIGEST_MISMATCH", func(t *testing.T) {
		mdCtx := metadata.NewOutgoingContext(
			t.Context(),
			metadata.Pairs("x-ark-digest", "stale-digest-value"),
		)

		stream, err := svc.GetEventStream(mdCtx, &arkv1.GetEventStreamRequest{})
		if err != nil {
			// Some gRPC implementations return the error on the initial call.
			st, ok := status.FromError(err)
			require.True(t, ok)
			require.Equal(t, codes.FailedPrecondition, st.Code())

			details := st.Details()
			require.NotEmpty(t, details)

			errDetails, ok := details[0].(*arkv1.ErrorDetails)
			require.True(t, ok)
			require.Equal(t, "DIGEST_MISMATCH", errDetails.Name)
			require.Equal(t, digest, errDetails.Metadata["current_digest"])
			return
		}

		// Others return it on the first Recv.
		_, err = stream.Recv()
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.FailedPrecondition, st.Code())

		details := st.Details()
		require.NotEmpty(t, details)

		errDetails, ok := details[0].(*arkv1.ErrorDetails)
		require.True(t, ok)
		require.Equal(t, "DIGEST_MISMATCH", errDetails.Name)
		require.Equal(t, digest, errDetails.Metadata["current_digest"])
	})
}
