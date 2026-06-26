package grpcservice

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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
