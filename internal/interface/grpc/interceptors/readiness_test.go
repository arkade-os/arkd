package interceptors

import (
	"context"
	"testing"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestUnaryReadinessHandler(t *testing.T) {
	t.Run("passes when checker allows", func(t *testing.T) {
		readiness := NewReadinessService(&fakeWalletProvider{
			status: fakeWalletStatus{initialized: true, unlocked: true, synced: true},
		})
		readiness.MarkAppServiceStarted()
		interceptor := unaryReadinessHandler(readiness)

		called := false
		_, err := interceptor(
			context.Background(),
			nil,
			&grpc.UnaryServerInfo{FullMethod: "/ark.v1.ArkService/GetInfo"},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return "ok", nil
			},
		)
		require.NoError(t, err)
		require.True(t, called)
	})

	t.Run("blocks when checker denies", func(t *testing.T) {
		interceptor := unaryReadinessHandler(NewReadinessService(nil))

		called := false
		_, err := interceptor(
			context.Background(),
			nil,
			&grpc.UnaryServerInfo{FullMethod: "/ark.v1.ArkService/GetInfo"},
			func(ctx context.Context, req any) (any, error) {
				called = true
				return nil, nil
			},
		)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.Unavailable, st.Code())
		require.False(t, called)
	})
}

func TestStreamReadinessHandler(t *testing.T) {
	t.Run("passes when checker allows", func(t *testing.T) {
		readiness := NewReadinessService(&fakeWalletProvider{
			status: fakeWalletStatus{initialized: true, unlocked: true, synced: true},
		})
		readiness.MarkAppServiceStarted()
		interceptor := streamReadinessHandler(readiness)

		called := false
		err := interceptor(
			nil,
			&testServerStream{ctx: context.Background()},
			&grpc.StreamServerInfo{FullMethod: "/ark.v1.IndexerService/GetAsset"},
			func(srv any, ss grpc.ServerStream) error {
				called = true
				return nil
			},
		)
		require.NoError(t, err)
		require.True(t, called)
	})

	t.Run("blocks when checker denies", func(t *testing.T) {
		interceptor := streamReadinessHandler(NewReadinessService(nil))

		called := false
		err := interceptor(
			nil,
			&testServerStream{ctx: context.Background()},
			&grpc.StreamServerInfo{FullMethod: "/ark.v1.IndexerService/GetAsset"},
			func(srv any, ss grpc.ServerStream) error {
				called = true
				return nil
			},
		)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.Unavailable, st.Code())
		require.False(t, called)
	})
}

func TestReadinessServiceCheck(t *testing.T) {
	t.Run("ignores non protected methods", func(t *testing.T) {
		r := NewReadinessService(nil)
		require.NoError(t, r.Check(context.Background(), "/ark.v1.WalletService/Lock"))
	})

	t.Run("app not started returns unavailable", func(t *testing.T) {
		r := NewReadinessService(&fakeWalletProvider{
			status: fakeWalletStatus{initialized: true, unlocked: true, synced: true},
		})
		err := r.Check(context.Background(), "/ark.v1.ArkService/GetInfo")
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("wallet status error returns unavailable", func(t *testing.T) {
		r := NewReadinessService(&fakeWalletProvider{err: status.Error(codes.Internal, "boom")})
		r.MarkAppServiceStarted()
		err := r.Check(context.Background(), "/ark.v1.ArkService/GetInfo")
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("locked or syncing wallet returns failed precondition", func(t *testing.T) {
		r := NewReadinessService(&fakeWalletProvider{
			status: fakeWalletStatus{initialized: true, unlocked: false, synced: false},
		})
		r.MarkAppServiceStarted()
		err := r.Check(context.Background(), "/ark.v1.IndexerService/GetAsset")
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("ready wallet allows protected methods", func(t *testing.T) {
		r := NewReadinessService(&fakeWalletProvider{
			status: fakeWalletStatus{initialized: true, unlocked: true, synced: true},
		})
		r.MarkAppServiceStarted()
		require.NoError(t, r.Check(context.Background(), "/ark.v1.ArkService/GetInfo"))
	})
}

type testServerStream struct {
	ctx context.Context
}

func (s *testServerStream) SetHeader(_ metadata.MD) error { return nil }

func (s *testServerStream) SendHeader(_ metadata.MD) error { return nil }

func (s *testServerStream) SetTrailer(_ metadata.MD) {}

func (s *testServerStream) Context() context.Context { return s.ctx }

func (s *testServerStream) SendMsg(any) error { return nil }

func (s *testServerStream) RecvMsg(any) error { return nil }

type fakeWalletProvider struct {
	status fakeWalletStatus
	err    error
}

func (f *fakeWalletProvider) Status(context.Context) (ports.WalletStatus, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.status, nil
}

type fakeWalletStatus struct {
	initialized bool
	unlocked    bool
	synced      bool
}

func (s fakeWalletStatus) IsInitialized() bool { return s.initialized }
func (s fakeWalletStatus) IsUnlocked() bool    { return s.unlocked }
func (s fakeWalletStatus) IsSynced() bool      { return s.synced }
