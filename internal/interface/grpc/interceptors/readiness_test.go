package interceptors

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestUnaryReadinessHandler(t *testing.T) {
	t.Run("passes when checker allows", func(t *testing.T) {
		readiness := NewReadinessService()
		readiness.walletReady.Store(true)
		readiness.MarkAppServiceStarted()
		interceptor := unaryReadinessHandler(readiness)

		called := false
		_, err := interceptor(
			t.Context(),
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
		interceptor := unaryReadinessHandler(NewReadinessService())

		called := false
		_, err := interceptor(
			t.Context(),
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
		readiness := NewReadinessService()
		readiness.walletReady.Store(true)
		readiness.MarkAppServiceStarted()
		interceptor := streamReadinessHandler(readiness)

		called := false
		err := interceptor(
			nil,
			&testServerStream{ctx: t.Context()},
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
		interceptor := streamReadinessHandler(NewReadinessService())

		called := false
		err := interceptor(
			nil,
			&testServerStream{ctx: t.Context()},
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
	t.Run("ignores non public methods", func(t *testing.T) {
		r := NewReadinessService()
		require.NoError(t, r.Check(t.Context(), "/ark.v1.WalletService/Lock"))
	})

	t.Run("app not started returns unavailable", func(t *testing.T) {
		r := NewReadinessService()
		r.walletReady.Store(true)
		err := r.Check(t.Context(), "/ark.v1.ArkService/GetInfo")
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("wallet not ready returns failed precondition", func(t *testing.T) {
		r := NewReadinessService()
		r.MarkAppServiceStarted()
		err := r.Check(t.Context(), "/ark.v1.ArkService/GetInfo")
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("wallet not ready returns failed precondition for indexer", func(t *testing.T) {
		r := NewReadinessService()
		r.MarkAppServiceStarted()
		err := r.Check(t.Context(), "/ark.v1.IndexerService/GetAsset")
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("ready wallet allows public methods", func(t *testing.T) {
		r := NewReadinessService()
		r.walletReady.Store(true)
		r.MarkAppServiceStarted()
		require.NoError(t, r.Check(t.Context(), "/ark.v1.ArkService/GetInfo"))
	})

	t.Run("listen to wallet state updates atomic", func(t *testing.T) {
		r := NewReadinessService()
		ch := make(chan bool, 1)
		r.ListenToWalletState(func() <-chan bool { return ch })

		ch <- true
		require.Eventually(
			t,
			func() bool { return r.walletReady.Load() },
			100*time.Millisecond,
			5*time.Millisecond,
		)

		ch <- false
		require.Eventually(
			t,
			func() bool { return !r.walletReady.Load() },
			100*time.Millisecond,
			5*time.Millisecond,
		)
	})

	t.Run("listen to wallet state handles channel close and reconnect", func(t *testing.T) {
		r := NewReadinessService()
		r.walletReady.Store(true)

		ch1 := make(chan bool)
		ch2 := make(chan bool, 1)
		calls := 0
		r.ListenToWalletState(func() <-chan bool {
			calls++
			if calls == 1 {
				return ch1
			}
			return ch2
		})

		// Close first channel — should set walletReady to false and reconnect.
		close(ch1)
		require.Eventually(
			t,
			func() bool { return !r.walletReady.Load() },
			100*time.Millisecond,
			5*time.Millisecond,
		)

		// Second channel should be active — send true.
		ch2 <- true
		require.Eventually(
			t,
			func() bool { return r.walletReady.Load() },
			100*time.Millisecond,
			5*time.Millisecond,
		)
	})

	t.Run("MarkAppServiceStopped stops listener goroutine", func(t *testing.T) {
		r := NewReadinessService()
		ch := make(chan bool, 1)
		r.ListenToWalletState(func() <-chan bool { return ch })

		ch <- true
		require.Eventually(
			t,
			func() bool { return r.walletReady.Load() },
			100*time.Millisecond,
			5*time.Millisecond,
		)

		r.MarkAppServiceStopped()
		require.Eventually(
			t,
			func() bool { return !r.walletReady.Load() },
			100*time.Millisecond,
			5*time.Millisecond,
		)
	})
}

type testServerStream struct {
	ctx context.Context
}

func (s *testServerStream) SetHeader(_ metadata.MD) error  { return nil }
func (s *testServerStream) SendHeader(_ metadata.MD) error { return nil }
func (s *testServerStream) SetTrailer(_ metadata.MD)       {}
func (s *testServerStream) Context() context.Context       { return s.ctx }
func (s *testServerStream) SendMsg(any) error              { return nil }
func (s *testServerStream) RecvMsg(any) error              { return nil }
