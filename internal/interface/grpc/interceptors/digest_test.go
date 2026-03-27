package interceptors

import (
	"context"
	"testing"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestDigestServiceCheckDigest(t *testing.T) {
	t.Run("skips GetInfo method", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("abc123")

		md := metadata.Pairs("x-ark-digest", "wrong")
		err := d.checkDigest(arkv1.ArkService_GetInfo_FullMethodName, md)
		require.NoError(t, err)
	})

	t.Run("skips non-public methods", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("abc123")

		md := metadata.Pairs("x-ark-digest", "wrong")
		err := d.checkDigest("/ark.v1.WalletService/Lock", md)
		require.NoError(t, err)
	})

	t.Run("skips admin service methods", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("abc123")

		md := metadata.Pairs("x-ark-digest", "wrong")
		err := d.checkDigest("/ark.v1.AdminService/GetRoundDetails", md)
		require.NoError(t, err)
	})

	t.Run("skips when no digest stored yet", func(t *testing.T) {
		d := NewDigestService()

		md := metadata.Pairs("x-ark-digest", "anything")
		err := d.checkDigest("/ark.v1.ArkService/RegisterIntent", md)
		require.NoError(t, err)
	})

	t.Run("skips when header absent (opt-in)", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("abc123")

		md := metadata.MD{}
		err := d.checkDigest("/ark.v1.ArkService/RegisterIntent", md)
		require.NoError(t, err)
	})

	t.Run("skips when metadata is nil", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("abc123")

		err := d.checkDigest("/ark.v1.ArkService/RegisterIntent", nil)
		require.NoError(t, err)
	})

	t.Run("passes when digest matches", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("abc123")

		md := metadata.Pairs("x-ark-digest", "abc123")
		err := d.checkDigest("/ark.v1.ArkService/RegisterIntent", md)
		require.NoError(t, err)
	})

	t.Run("passes for IndexerService with matching digest", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("abc123")

		md := metadata.Pairs("x-ark-digest", "abc123")
		err := d.checkDigest("/ark.v1.IndexerService/GetAsset", md)
		require.NoError(t, err)
	})

	t.Run("returns error on digest mismatch", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("current-digest")

		md := metadata.Pairs("x-ark-digest", "stale-digest")
		err := d.checkDigest("/ark.v1.ArkService/RegisterIntent", md)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.FailedPrecondition, st.Code())

		details := st.Details()
		require.Len(t, details, 1)

		errDetails, ok := details[0].(*arkv1.ErrorDetails)
		require.True(t, ok)
		require.Equal(t, int32(49), errDetails.Code)
		require.Equal(t, "DIGEST_MISMATCH", errDetails.Name)
		require.Equal(t, "current-digest", errDetails.Metadata["current_digest"])
	})

	t.Run("returns error on IndexerService digest mismatch", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("current-digest")

		md := metadata.Pairs("x-ark-digest", "stale-digest")
		err := d.checkDigest("/ark.v1.IndexerService/GetAsset", md)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.FailedPrecondition, st.Code())

		details := st.Details()
		require.Len(t, details, 1)

		errDetails, ok := details[0].(*arkv1.ErrorDetails)
		require.True(t, ok)
		require.Equal(t, int32(49), errDetails.Code)
		require.Equal(t, "DIGEST_MISMATCH", errDetails.Name)
		require.Equal(t, "current-digest", errDetails.Metadata["current_digest"])
	})

	t.Run("reflects updated digest", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("digest-v1")

		md := metadata.Pairs("x-ark-digest", "digest-v1")
		require.NoError(t, d.checkDigest("/ark.v1.ArkService/RegisterIntent", md))

		d.SetDigest("digest-v2")
		err := d.checkDigest("/ark.v1.ArkService/RegisterIntent", md)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)

		details := st.Details()
		require.Len(t, details, 1)
		errDetails, ok := details[0].(*arkv1.ErrorDetails)
		require.True(t, ok)
		require.Equal(t, "digest-v2", errDetails.Metadata["current_digest"])
	})
}

func TestUnaryDigestValidator(t *testing.T) {
	t.Run("passes when digest matches", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("abc123")
		interceptor := unaryDigestValidator(d)

		ctx := metadata.NewIncomingContext(
			t.Context(),
			metadata.Pairs("x-ark-digest", "abc123"),
		)

		called := false
		_, err := interceptor(
			ctx,
			nil,
			&grpc.UnaryServerInfo{FullMethod: "/ark.v1.ArkService/RegisterIntent"},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return "ok", nil
			},
		)
		require.NoError(t, err)
		require.True(t, called)
	})

	t.Run("blocks when digest mismatches", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("abc123")
		interceptor := unaryDigestValidator(d)

		ctx := metadata.NewIncomingContext(
			t.Context(),
			metadata.Pairs("x-ark-digest", "wrong"),
		)

		called := false
		_, err := interceptor(
			ctx,
			nil,
			&grpc.UnaryServerInfo{FullMethod: "/ark.v1.ArkService/RegisterIntent"},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return nil, nil
			},
		)
		require.Error(t, err)
		require.False(t, called)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("passes without header (opt-in)", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("abc123")
		interceptor := unaryDigestValidator(d)

		called := false
		_, err := interceptor(
			t.Context(),
			nil,
			&grpc.UnaryServerInfo{FullMethod: "/ark.v1.ArkService/RegisterIntent"},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return "ok", nil
			},
		)
		require.NoError(t, err)
		require.True(t, called)
	})

	t.Run("passes for GetInfo even with wrong digest", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("abc123")
		interceptor := unaryDigestValidator(d)

		ctx := metadata.NewIncomingContext(
			t.Context(),
			metadata.Pairs("x-ark-digest", "wrong"),
		)

		called := false
		_, err := interceptor(
			ctx,
			nil,
			&grpc.UnaryServerInfo{FullMethod: arkv1.ArkService_GetInfo_FullMethodName},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return "ok", nil
			},
		)
		require.NoError(t, err)
		require.True(t, called)
	})
}

func TestStreamDigestValidator(t *testing.T) {
	t.Run("passes when digest matches", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("abc123")
		interceptor := streamDigestValidator(d)

		ctx := metadata.NewIncomingContext(
			t.Context(),
			metadata.Pairs("x-ark-digest", "abc123"),
		)

		called := false
		err := interceptor(
			nil,
			&testServerStream{ctx: ctx},
			&grpc.StreamServerInfo{FullMethod: "/ark.v1.ArkService/GetEventStream"},
			func(srv any, ss grpc.ServerStream) error {
				called = true
				return nil
			},
		)
		require.NoError(t, err)
		require.True(t, called)
	})

	t.Run("blocks when digest mismatches", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("abc123")
		interceptor := streamDigestValidator(d)

		ctx := metadata.NewIncomingContext(
			t.Context(),
			metadata.Pairs("x-ark-digest", "wrong"),
		)

		called := false
		err := interceptor(
			nil,
			&testServerStream{ctx: ctx},
			&grpc.StreamServerInfo{FullMethod: "/ark.v1.ArkService/GetEventStream"},
			func(srv any, ss grpc.ServerStream) error {
				called = true
				return nil
			},
		)
		require.Error(t, err)
		require.False(t, called)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("passes without header (opt-in)", func(t *testing.T) {
		d := NewDigestService()
		d.SetDigest("abc123")
		interceptor := streamDigestValidator(d)

		called := false
		err := interceptor(
			nil,
			&testServerStream{ctx: t.Context()},
			&grpc.StreamServerInfo{FullMethod: "/ark.v1.ArkService/GetEventStream"},
			func(srv any, ss grpc.ServerStream) error {
				called = true
				return nil
			},
		)
		require.NoError(t, err)
		require.True(t, called)
	})
}
