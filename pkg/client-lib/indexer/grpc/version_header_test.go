package grpcindexer

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	internalgrpc "github.com/arkade-os/arkd/pkg/client-lib/internal/grpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

// headerCapture records the x-build-version metadata value seen by the server.
type headerCapture struct {
	mu     sync.Mutex
	values map[string]string
}

func newHeaderCapture() *headerCapture {
	return &headerCapture{values: make(map[string]string)}
}

func (h *headerCapture) record(ctx context.Context, kind string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get(internalgrpc.BuildVersionHeader); len(vals) > 0 {
			h.values[kind] = vals[0]
		}
	}
}

func (h *headerCapture) get(kind string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	v, ok := h.values[kind]
	return v, ok
}

// stubIndexerServer is a minimal IndexerService that lets NewSubscription
// progress to the GetSubscription stream, so the stream interceptor is
// exercised through the real NewClient path.
type stubIndexerServer struct {
	arkv1.UnimplementedIndexerServiceServer
	capture *headerCapture
}

func (s *stubIndexerServer) SubscribeForScripts(
	ctx context.Context, _ *arkv1.SubscribeForScriptsRequest,
) (*arkv1.SubscribeForScriptsResponse, error) {
	s.capture.record(ctx, "subscribe")
	return &arkv1.SubscribeForScriptsResponse{SubscriptionId: "sub-1"}, nil
}

func (s *stubIndexerServer) GetSubscription(
	_ *arkv1.GetSubscriptionRequest,
	stream grpc.ServerStreamingServer[arkv1.GetSubscriptionResponse],
) error {
	s.capture.record(stream.Context(), "stream")
	<-stream.Context().Done()
	return stream.Context().Err()
}

func startIndexerHeaderServer(
	t *testing.T, srvImpl arkv1.IndexerServiceServer, capture *headerCapture,
) func(context.Context, string) (net.Conn, error) {
	t.Helper()

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(func(
			ctx context.Context, req interface{},
			_ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
		) (interface{}, error) {
			capture.record(ctx, "unary")
			return handler(ctx, req)
		}),
		grpc.StreamInterceptor(func(
			srv interface{}, ss grpc.ServerStream,
			_ *grpc.StreamServerInfo, handler grpc.StreamHandler,
		) error {
			capture.record(ss.Context(), "stream")
			return handler(srv, ss)
		}),
	)
	arkv1.RegisterIndexerServiceServer(srv, srvImpl)

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	return func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
}

// TestBuildVersionHeaderInjected_Unary verifies that a unary IndexerService RPC
// issued through the real NewClient constructor carries the x-build-version
// header server-side.
func TestBuildVersionHeaderInjected_Unary(t *testing.T) {
	capture := newHeaderCapture()
	dialer := startIndexerHeaderServer(
		t, &arkv1.UnimplementedIndexerServiceServer{}, capture,
	)

	prev := testDialOptions
	testDialOptions = []grpc.DialOption{grpc.WithContextDialer(dialer)}
	t.Cleanup(func() { testDialOptions = prev })

	c, err := NewClient("passthrough:///bufconn")
	require.NoError(t, err)
	t.Cleanup(c.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// GetVtxos with scripts dispatches a real unary RPC (it returns
	// Unimplemented from the stub); the server-side unary interceptor still
	// captures the header before the handler runs.
	_, _ = c.GetVtxos(ctx, indexer.WithScripts([]string{"deadbeef"}))

	value, seen := capture.get("unary")
	require.True(t, seen, "server did not receive x-build-version header on unary call")
	require.Equal(t, internalgrpc.ClientBuildVersion, value)
}

// TestBuildVersionHeaderInjected_Stream verifies that the GetSubscription
// stream opened through the real NewClient constructor carries the
// x-build-version header server-side.
func TestBuildVersionHeaderInjected_Stream(t *testing.T) {
	capture := newHeaderCapture()
	dialer := startIndexerHeaderServer(
		t, &stubIndexerServer{capture: capture}, capture,
	)

	prev := testDialOptions
	testDialOptions = []grpc.DialOption{grpc.WithContextDialer(dialer)}
	t.Cleanup(func() { testDialOptions = prev })

	c, err := NewClient("passthrough:///bufconn")
	require.NoError(t, err)
	t.Cleanup(c.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// NewSubscription issues SubscribeForScripts (unary) then opens the
	// GetSubscription stream. We assert the header arrives on the stream.
	_, _, closeFn, err := c.NewSubscription(ctx, []string{"deadbeef"})
	require.NoError(t, err)
	if closeFn != nil {
		defer closeFn()
	}

	require.Eventually(t, func() bool {
		_, seen := capture.get("stream")
		return seen
	}, 5*time.Second, 20*time.Millisecond,
		"server did not receive x-build-version header on streaming call")

	value, _ := capture.get("stream")
	require.Equal(t, internalgrpc.ClientBuildVersion, value)
}
