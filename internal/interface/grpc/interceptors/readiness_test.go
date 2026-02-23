package interceptors

import (
	"context"
	"testing"

	"github.com/arkade-os/arkd/internal/core/ports"
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !called {
			t.Fatalf("expected handler to be called")
		}
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
		if !ok || st.Code() != codes.FailedPrecondition {
			t.Fatalf("expected FailedPrecondition, got %v", err)
		}
		if called {
			t.Fatalf("expected handler not to be called")
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !called {
			t.Fatalf("expected handler to be called")
		}
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
		if !ok || st.Code() != codes.FailedPrecondition {
			t.Fatalf("expected FailedPrecondition, got %v", err)
		}
		if called {
			t.Fatalf("expected handler not to be called")
		}
	})
}

func TestReadinessServiceCheck(t *testing.T) {
	t.Run("ignores non protected methods", func(t *testing.T) {
		r := NewReadinessService(nil)
		if err := r.Check(context.Background(), "/ark.v1.WalletService/Lock"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("app not started returns failed precondition", func(t *testing.T) {
		r := NewReadinessService(&fakeWalletProvider{
			status: fakeWalletStatus{initialized: true, unlocked: true, synced: true},
		})
		err := r.Check(context.Background(), "/ark.v1.ArkService/GetInfo")
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.FailedPrecondition {
			t.Fatalf("expected FailedPrecondition, got %v", err)
		}
	})

	t.Run("wallet status error returns unavailable", func(t *testing.T) {
		r := NewReadinessService(&fakeWalletProvider{err: status.Error(codes.Internal, "boom")})
		r.MarkAppServiceStarted()
		err := r.Check(context.Background(), "/ark.v1.ArkService/GetInfo")
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.Unavailable {
			t.Fatalf("expected Unavailable, got %v", err)
		}
	})

	t.Run("locked or syncing wallet returns failed precondition", func(t *testing.T) {
		r := NewReadinessService(&fakeWalletProvider{
			status: fakeWalletStatus{initialized: true, unlocked: false, synced: false},
		})
		r.MarkAppServiceStarted()
		err := r.Check(context.Background(), "/ark.v1.IndexerService/GetAsset")
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.FailedPrecondition {
			t.Fatalf("expected FailedPrecondition, got %v", err)
		}
	})

	t.Run("ready wallet allows protected methods", func(t *testing.T) {
		r := NewReadinessService(&fakeWalletProvider{
			status: fakeWalletStatus{initialized: true, unlocked: true, synced: true},
		})
		r.MarkAppServiceStarted()
		if err := r.Check(context.Background(), "/ark.v1.ArkService/GetInfo"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
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
