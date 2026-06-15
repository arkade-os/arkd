package grpcclient

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// TestClientVersionHeaderInjected_Unary verifies that a unary RPC issued through
// the real NewClient constructor carries the x-sdk-version header server-side
// when a client version is configured.
func TestClientVersionHeaderInjected_Unary(t *testing.T) {
	const clientVersion = "9.9.9"

	capture := &headerCapture{key: clientVersionHeader}
	dialer := startArkHeaderServer(t, capture)

	// Drive the REAL NewClient path; the bufconn dialer is injected via the
	// test-only seam so the production interceptors registered in NewClient
	// are exercised end to end.
	prev := testDialOptions
	testDialOptions = []grpc.DialOption{grpc.WithContextDialer(dialer)}
	t.Cleanup(func() { testDialOptions = prev })

	c, err := NewClient("passthrough:///bufconn", clientVersion)
	require.NoError(t, err)
	t.Cleanup(c.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// GetInfo returns Unimplemented from the stub server; that is expected.
	// The server-side interceptor still captures the header before the handler.
	_, _ = c.GetInfo(ctx)

	value, seen := capture.get()
	require.True(t, seen, "server did not receive x-sdk-version header on unary call")
	require.Equal(t, clientVersion, value)
}

// TestClientVersionHeaderInjected_Stream verifies that a streaming RPC issued
// through the real NewClient constructor carries the x-sdk-version header
// server-side when a client version is configured.
func TestClientVersionHeaderInjected_Stream(t *testing.T) {
	const clientVersion = "9.9.9"

	capture := &headerCapture{key: clientVersionHeader}
	dialer := startArkHeaderServer(t, capture)

	prev := testDialOptions
	testDialOptions = []grpc.DialOption{grpc.WithContextDialer(dialer)}
	t.Cleanup(func() { testDialOptions = prev })

	c, err := NewClient("passthrough:///bufconn", clientVersion)
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
		"server did not receive x-sdk-version header on streaming call")

	value, _ := capture.get()
	require.Equal(t, clientVersion, value)
}

// TestClientVersionHeaderOmitted_Unary verifies that no x-sdk-version header is
// sent when NewClient is constructed without a client version, mirroring the
// conditional wiring in NewClient.
func TestClientVersionHeaderOmitted_Unary(t *testing.T) {
	capture := &headerCapture{key: clientVersionHeader}
	dialer := startArkHeaderServer(t, capture)

	prev := testDialOptions
	testDialOptions = []grpc.DialOption{grpc.WithContextDialer(dialer)}
	t.Cleanup(func() { testDialOptions = prev })

	c, err := NewClient("passthrough:///bufconn", "")
	require.NoError(t, err)
	t.Cleanup(c.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _ = c.GetInfo(ctx)

	_, seen := capture.get()
	require.False(t, seen, "x-sdk-version header should be absent without a client version")
}

// TestUnaryClientVersionInterceptor drives the unary interceptor directly and
// asserts on the outgoing metadata it hands to the invoker.
func TestUnaryClientVersionInterceptor(t *testing.T) {
	const version = "1.2.3"

	t.Run("sets header", func(t *testing.T) {
		var got metadata.MD
		invoker := func(
			ctx context.Context, _ string, _, _ interface{},
			_ *grpc.ClientConn, _ ...grpc.CallOption,
		) error {
			got, _ = metadata.FromOutgoingContext(ctx)
			return nil
		}

		err := unaryClientVersionInterceptor(version)(
			context.Background(), "/ark.v1.ArkService/GetInfo",
			nil, nil, nil, invoker,
		)
		require.NoError(t, err)
		require.Equal(t, []string{version}, got.Get(clientVersionHeader))
	})

	t.Run("preserves existing metadata", func(t *testing.T) {
		var got metadata.MD
		invoker := func(
			ctx context.Context, _ string, _, _ interface{},
			_ *grpc.ClientConn, _ ...grpc.CallOption,
		) error {
			got, _ = metadata.FromOutgoingContext(ctx)
			return nil
		}

		ctx := metadata.NewOutgoingContext(
			context.Background(), metadata.Pairs("x-other", "keep-me"),
		)
		err := unaryClientVersionInterceptor(version)(
			ctx, "/ark.v1.ArkService/GetInfo", nil, nil, nil, invoker,
		)
		require.NoError(t, err)
		require.Equal(t, []string{version}, got.Get(clientVersionHeader))
		require.Equal(t, []string{"keep-me"}, got.Get("x-other"))
	})

	t.Run("overwrites stale header and leaves caller context untouched", func(t *testing.T) {
		var got metadata.MD
		invoker := func(
			ctx context.Context, _ string, _, _ interface{},
			_ *grpc.ClientConn, _ ...grpc.CallOption,
		) error {
			got, _ = metadata.FromOutgoingContext(ctx)
			return nil
		}

		caller := metadata.Pairs(clientVersionHeader, "0.0.1")
		ctx := metadata.NewOutgoingContext(context.Background(), caller)
		err := unaryClientVersionInterceptor(version)(
			ctx, "/ark.v1.ArkService/GetInfo", nil, nil, nil, invoker,
		)
		require.NoError(t, err)
		// The invoker sees the fresh version, not the stale one.
		require.Equal(t, []string{version}, got.Get(clientVersionHeader))
		// The caller's own metadata was copied, not mutated in place.
		require.Equal(t, []string{"0.0.1"}, caller.Get(clientVersionHeader))
	})

	t.Run("propagates invoker error", func(t *testing.T) {
		wantErr := context.Canceled
		invoker := func(
			_ context.Context, _ string, _, _ interface{},
			_ *grpc.ClientConn, _ ...grpc.CallOption,
		) error {
			return wantErr
		}

		err := unaryClientVersionInterceptor(version)(
			context.Background(), "/ark.v1.ArkService/GetInfo",
			nil, nil, nil, invoker,
		)
		require.ErrorIs(t, err, wantErr)
	})
}

// TestStreamClientVersionInterceptor drives the stream interceptor directly and
// asserts on the outgoing metadata it hands to the streamer.
func TestStreamClientVersionInterceptor(t *testing.T) {
	const version = "1.2.3"

	t.Run("sets header", func(t *testing.T) {
		var got metadata.MD
		streamer := func(
			ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn,
			_ string, _ ...grpc.CallOption,
		) (grpc.ClientStream, error) {
			got, _ = metadata.FromOutgoingContext(ctx)
			return nil, nil
		}

		_, err := streamClientVersionInterceptor(version)(
			context.Background(), &grpc.StreamDesc{}, nil,
			"/ark.v1.ArkService/GetEventStream", streamer,
		)
		require.NoError(t, err)
		require.Equal(t, []string{version}, got.Get(clientVersionHeader))
	})

	t.Run("preserves existing metadata", func(t *testing.T) {
		var got metadata.MD
		streamer := func(
			ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn,
			_ string, _ ...grpc.CallOption,
		) (grpc.ClientStream, error) {
			got, _ = metadata.FromOutgoingContext(ctx)
			return nil, nil
		}

		ctx := metadata.NewOutgoingContext(
			context.Background(), metadata.Pairs("x-other", "keep-me"),
		)
		_, err := streamClientVersionInterceptor(version)(
			ctx, &grpc.StreamDesc{}, nil,
			"/ark.v1.ArkService/GetEventStream", streamer,
		)
		require.NoError(t, err)
		require.Equal(t, []string{version}, got.Get(clientVersionHeader))
		require.Equal(t, []string{"keep-me"}, got.Get("x-other"))
	})

	t.Run("overwrites stale header and leaves caller context untouched", func(t *testing.T) {
		var got metadata.MD
		streamer := func(
			ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn,
			_ string, _ ...grpc.CallOption,
		) (grpc.ClientStream, error) {
			got, _ = metadata.FromOutgoingContext(ctx)
			return nil, nil
		}

		caller := metadata.Pairs(clientVersionHeader, "0.0.1")
		ctx := metadata.NewOutgoingContext(context.Background(), caller)
		_, err := streamClientVersionInterceptor(version)(
			ctx, &grpc.StreamDesc{}, nil,
			"/ark.v1.ArkService/GetEventStream", streamer,
		)
		require.NoError(t, err)
		require.Equal(t, []string{version}, got.Get(clientVersionHeader))
		require.Equal(t, []string{"0.0.1"}, caller.Get(clientVersionHeader))
	})

	t.Run("propagates streamer error", func(t *testing.T) {
		wantErr := context.Canceled
		streamer := func(
			_ context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn,
			_ string, _ ...grpc.CallOption,
		) (grpc.ClientStream, error) {
			return nil, wantErr
		}

		_, err := streamClientVersionInterceptor(version)(
			context.Background(), &grpc.StreamDesc{}, nil,
			"/ark.v1.ArkService/GetEventStream", streamer,
		)
		require.ErrorIs(t, err, wantErr)
	})
}
