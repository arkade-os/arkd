package client

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

// TestBuildVersionHeaderInjected_Unary verifies that a unary RPC issued through
// the real NewClient constructor carries the x-build-version header server-side.
func TestBuildVersionHeaderInjected_Unary(t *testing.T) {
	capture := &headerCapture{key: buildVersionHeader}
	dialer := startArkHeaderServer(t, capture)

	// Drive the REAL NewClient path; the bufconn dialer is injected via the
	// test-only seam so the production interceptors registered in NewClient
	// are exercised end to end.
	prev := testDialOptions
	testDialOptions = []grpc.DialOption{grpc.WithContextDialer(dialer)}
	t.Cleanup(func() { testDialOptions = prev })

	c, err := NewClient("passthrough:///bufconn", "")
	require.NoError(t, err)
	t.Cleanup(c.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// GetInfo returns Unimplemented from the stub server; that is expected.
	// The server-side interceptor still captures the header before the handler.
	_, _ = c.GetInfo(ctx)

	value, seen := capture.get()
	require.True(t, seen, "server did not receive x-build-version header on unary call")
	require.Equal(t, buildVersion, value)
}

// TestBuildVersionHeaderInjected_Stream verifies that a streaming RPC issued
// through the real NewClient constructor carries the x-build-version header
// server-side.
func TestBuildVersionHeaderInjected_Stream(t *testing.T) {
	capture := &headerCapture{key: buildVersionHeader}
	dialer := startArkHeaderServer(t, capture)

	prev := testDialOptions
	testDialOptions = []grpc.DialOption{grpc.WithContextDialer(dialer)}
	t.Cleanup(func() { testDialOptions = prev })

	c, err := NewClient("passthrough:///bufconn", "")
	require.NoError(t, err)
	t.Cleanup(c.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// GetTransactionsStream opens a server-streaming RPC. The stream
	// interceptor on the server captures the header as the stream is
	// established, regardless of the Unimplemented handler outcome.
	_, closeFn, err := c.GetTransactionsStream(ctx)
	if closeFn != nil {
		defer closeFn()
	}
	// An error is acceptable (Unimplemented); we only require that the stream
	// reached the server and the header was captured.
	_ = err

	require.Eventually(t, func() bool {
		_, seen := capture.get()
		return seen
	}, 5*time.Second, 20*time.Millisecond,
		"server did not receive x-build-version header on streaming call")

	value, _ := capture.get()
	require.Equal(t, buildVersion, value)
}

// headerCapture records the value of the metadata key it is configured for, as
// seen by the server on incoming calls.
type headerCapture struct {
	mu    sync.Mutex
	key   string
	value string
	seen  bool
}

func (h *headerCapture) record(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get(h.key); len(vals) > 0 {
			h.value = vals[0]
			h.seen = true
		}
	}
}

func (h *headerCapture) get() (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.value, h.seen
}

// startArkHeaderServer starts an in-process ArkService server that captures the
// build-version header on both unary and streaming calls, and returns the
// bufconn dialer to reach it.
func startArkHeaderServer(
	t *testing.T, capture *headerCapture,
) func(context.Context, string) (net.Conn, error) {
	t.Helper()

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(func(
			ctx context.Context, req interface{},
			_ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
		) (interface{}, error) {
			capture.record(ctx)
			return handler(ctx, req)
		}),
		grpc.StreamInterceptor(func(
			srv interface{}, ss grpc.ServerStream,
			_ *grpc.StreamServerInfo, handler grpc.StreamHandler,
		) error {
			capture.record(ss.Context())
			return handler(srv, ss)
		}),
	)
	arkv1.RegisterArkServiceServer(srv, &arkv1.UnimplementedArkServiceServer{})

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	return func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
}
