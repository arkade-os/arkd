package grpcservice

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/interface/grpc/handlers"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

// Mock connection object implementing grpc.ClientConnInterface
// to count unary vs stream call counts.
type mockConn struct {
	invokeCalls atomic.Int64
	streamCalls atomic.Int64
}

func (m *mockConn) Invoke(
	_ context.Context, _ string, _, _ any, _ ...grpc.CallOption,
) error {
	m.invokeCalls.Add(1)
	return nil
}

func (m *mockConn) NewStream(
	_ context.Context, _ *grpc.StreamDesc, _ string, _ ...grpc.CallOption,
) (grpc.ClientStream, error) {
	m.streamCalls.Add(1)
	return nil, nil
}

func TestSplitConnInvoke(t *testing.T) {
	t.Run("routes unary only", func(t *testing.T) {
		unary := &mockConn{}
		streams := []grpc.ClientConnInterface{&mockConn{}, &mockConn{}}
		sc := &splitConn{unary: unary, streamPool: streams}

		for i := 0; i < 10; i++ {
			require.NoError(t, sc.Invoke(context.Background(), "/test", nil, nil))
		}

		require.Equal(t, int64(10), unary.invokeCalls.Load())
		for i, s := range streams {
			mock := s.(*mockConn)
			require.Zero(t, mock.invokeCalls.Load(), "stream pool[%d] received invoke calls", i)
			require.Zero(t, mock.streamCalls.Load(), "stream pool[%d] received stream calls", i)
		}
	})
}

func TestSplitConnNewStream(t *testing.T) {
	t.Run("round robins across pool", func(t *testing.T) {
		unary := &mockConn{}
		poolSize := 4
		streams := make([]grpc.ClientConnInterface, poolSize)
		for i := range streams {
			streams[i] = &mockConn{}
		}
		sc := &splitConn{unary: unary, streamPool: streams}

		totalCalls := 100
		for i := 0; i < totalCalls; i++ {
			_, err := sc.NewStream(context.Background(), nil, "/test")
			require.NoError(t, err)
		}

		expectedPerConn := int64(totalCalls / poolSize)
		for i, s := range streams {
			require.Equal(t, expectedPerConn, s.(*mockConn).streamCalls.Load(),
				"stream pool[%d] call count", i)
		}
		require.Zero(t, unary.streamCalls.Load(), "unary conn received stream calls")
	})

	t.Run("pool size one", func(t *testing.T) {
		unary := &mockConn{}
		single := &mockConn{}
		sc := &splitConn{unary: unary, streamPool: []grpc.ClientConnInterface{single}}

		for i := 0; i < 50; i++ {
			_, err := sc.NewStream(context.Background(), nil, "/test")
			require.NoError(t, err)
		}

		require.Equal(t, int64(50), single.streamCalls.Load())
	})

	t.Run("concurrent creation safe and evenly distributed", func(t *testing.T) {
		unary := &mockConn{}
		poolSize := 4
		streams := make([]grpc.ClientConnInterface, poolSize)
		for i := range streams {
			streams[i] = &mockConn{}
		}
		sc := &splitConn{unary: unary, streamPool: streams}

		goroutines := 100
		callsPerGoroutine := 100
		totalCalls := goroutines * callsPerGoroutine

		var wg sync.WaitGroup
		wg.Add(goroutines)
		for g := 0; g < goroutines; g++ {
			go func() {
				defer wg.Done()
				for i := 0; i < callsPerGoroutine; i++ {
					_, err := sc.NewStream(context.Background(), nil, "/test")
					require.NoError(t, err)
				}
			}()
		}
		wg.Wait()

		var totalObserved int64
		for _, s := range streams {
			totalObserved += s.(*mockConn).streamCalls.Load()
		}
		require.Equal(t, int64(totalCalls), totalObserved)

		// Verify roughly even distribution (allow 20% deviation).
		expected := int64(totalCalls / poolSize)
		tolerance := expected / 5
		for i, s := range streams {
			got := s.(*mockConn).streamCalls.Load()
			require.InDelta(t, expected, got, float64(tolerance),
				"stream pool[%d] distribution", i)
		}
	})
}

func TestStopWaitsForGrpcHandlers(t *testing.T) {
	tests := []struct {
		name           string
		waitForTimeout bool
	}{
		{name: "waits for canceled handler cleanup"},
		{name: "gives up after timeout", waitForTimeout: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entered, canceled := make(chan struct{}), make(chan struct{})
			release, finished := make(chan struct{}), make(chan struct{})
			releaseHandler := sync.OnceFunc(func() { close(release) })

			grpcServer := grpc.NewServer(grpc.UnaryInterceptor(func(
				ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
			) (any, error) {
				defer close(finished)
				close(entered)
				<-ctx.Done()
				close(canceled)
				// Keep the RPC running after cancellation, as slow cleanup or a blocked
				// dependency can. Closing the HTTP transport must not count as its exit.
				<-release
				return handler(ctx, req)
			}))
			t.Cleanup(grpcServer.Stop)
			grpchealth.RegisterHealthServer(grpcServer, handlers.NewHealthHandler())

			server := httptest.NewUnstartedServer(router(grpcServer, http.NotFoundHandler()))
			server.Config.Protocols = new(http.Protocols)
			server.Config.Protocols.SetUnencryptedHTTP2(true)
			server.Start()
			t.Cleanup(server.Close)

			conn, err := grpc.NewClient(
				server.Listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			t.Cleanup(releaseHandler)
			client := grpchealth.NewHealthClient(conn)
			result := make(chan error, 1)
			go func() {
				_, err := client.Check(t.Context(), &grpchealth.HealthCheckRequest{})
				result <- err
			}()
			waitForShutdownSignal(t, entered, "RPC did not start")

			svc := &service{server: server.Config, grpcServer: grpcServer}
			stopped := make(chan time.Duration, 1)
			go func() {
				start := time.Now()
				svc.stop()
				stopped <- time.Since(start)
			}()
			waitForShutdownSignal(t, canceled, "RPC was not canceled")

			// The HTTP listener must close while handler cleanup is still pending.
			newConn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
			if newConn != nil {
				_ = newConn.Close()
			}
			require.Error(t, err)
			select {
			case <-stopped:
				t.Fatal("stop returned before handler cleanup or timeout")
			case <-time.After(100 * time.Millisecond):
			}

			bound := 5 * time.Second
			if tt.waitForTimeout {
				bound += handlersShutdownTimeout
			} else {
				releaseHandler()
			}
			select {
			case elapsed := <-stopped:
				if tt.waitForTimeout {
					require.GreaterOrEqual(t, elapsed, handlersShutdownTimeout)
				}
			case <-time.After(bound):
				t.Fatal("stop blocked past the shutdown bound")
			}
			releaseHandler()
			waitForShutdownSignal(t, finished, "handler did not exit")
			select {
			case err := <-result:
				require.Error(t, err, "HTTP Close interrupts the client response")
			case <-time.After(5 * time.Second):
				t.Fatal("client did not observe connection closure")
			}
		})
	}
}

func waitForShutdownSignal(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal(msg)
	}
}
