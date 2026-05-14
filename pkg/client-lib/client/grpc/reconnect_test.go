package grpcclient

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type testArkStreamServer struct {
	arkv1.UnimplementedArkServiceServer
	txStreamCalls atomic.Int32
}

func (s *testArkStreamServer) GetTransactionsStream(
	_ *arkv1.GetTransactionsStreamRequest,
	stream grpc.ServerStreamingServer[arkv1.GetTransactionsStreamResponse],
) error {
	call := s.txStreamCalls.Add(1)

	if err := stream.Send(&arkv1.GetTransactionsStreamResponse{
		Data: &arkv1.GetTransactionsStreamResponse_CommitmentTx{
			CommitmentTx: &arkv1.TxNotification{
				Txid: fmt.Sprintf("commitment-%d", call),
				Tx:   "deadbeef",
			},
		},
	}); err != nil {
		return err
	}

	if call == 1 {
		return status.Error(codes.Unavailable, "forced reconnect")
	}

	<-stream.Context().Done()
	return stream.Context().Err()
}

func TestGetTransactionsStreamEmitsConnectionLifecycleEvents(t *testing.T) {
	originalCfg := utils.GrpcReconnectConfig
	t.Cleanup(func() {
		utils.GrpcReconnectConfig = originalCfg
	})

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	arkv1.RegisterArkServiceServer(srv, &testArkStreamServer{})
	go func() {
		_ = srv.Serve(lis)
	}()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	c := &grpcClient{
		conn:       conn,
		connMu:     &sync.RWMutex{},
		listenerMu: &sync.RWMutex{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	eventsCh, closeFn, err := c.GetTransactionsStream(ctx)
	require.NoError(t, err)
	defer closeFn()

	var (
		disconnectedAt time.Time
		reconnectedAt  time.Time
		seenSecondTx   bool
	)

	for {
		select {
		case <-ctx.Done():
			require.FailNow(t, "timed out waiting for lifecycle events and post-reconnect data")
		case event, ok := <-eventsCh:
			require.True(t, ok, "transaction stream unexpectedly closed")
			require.Nil(t, event.Err)

			if event.Connection != nil {
				switch event.Connection.State {
				case types.StreamConnectionStateDisconnected:
					disconnectedAt = event.Connection.At
				case types.StreamConnectionStateReconnected:
					reconnectedAt = event.Connection.At
				}
			}

			if event.CommitmentTx != nil && event.CommitmentTx.Txid == "commitment-2" {
				seenSecondTx = true
			}

			if !disconnectedAt.IsZero() && !reconnectedAt.IsZero() && seenSecondTx {
				require.True(
					t, reconnectedAt.After(disconnectedAt) || reconnectedAt.Equal(disconnectedAt),
					"reconnected timestamp must be >= disconnected timestamp",
				)
				return
			}
		}
	}
}

func TestGetTransactionsStreamReconnectsAfterServerRestart(t *testing.T) {
	originalCfg := utils.GrpcReconnectConfig
	utils.GrpcReconnectConfig.InitialDelay = 100 * time.Millisecond
	utils.GrpcReconnectConfig.MaxDelay = 500 * time.Millisecond
	utils.GrpcReconnectConfig.Jitter = 0
	t.Cleanup(func() {
		utils.GrpcReconnectConfig = originalCfg
	})

	// Shared counter across server instances so each stream call returns
	// a unique txid even after restart.
	txCounter := &atomic.Int32{}

	// Start the first server instance on a random port.
	lis1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := lis1.Addr().String()

	srv1 := grpc.NewServer()
	arkv1.RegisterArkServiceServer(srv1, &mockArkStreamServer{txCounter: txCounter})
	go func() {
		_ = srv1.Serve(lis1)
	}()

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	c := &grpcClient{
		conn:       conn,
		connMu:     &sync.RWMutex{},
		listenerMu: &sync.RWMutex{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	eventsCh, closeFn, err := c.GetTransactionsStream(ctx)
	require.NoError(t, err)
	defer closeFn()

	// Collect initial READY + first tx, then stop the server.
	seenInitialReady := false
	seenFirstTx := false
	for !seenInitialReady || !seenFirstTx {
		select {
		case <-ctx.Done():
			require.FailNow(t, "timed out waiting for initial READY and first tx")
		case event, ok := <-eventsCh:
			require.True(t, ok, "stream unexpectedly closed")
			require.Nil(t, event.Err)

			if event.Connection != nil &&
				event.Connection.State == types.StreamConnectionStateReady {
				seenInitialReady = true
			}
			if event.CommitmentTx != nil && event.CommitmentTx.Txid == "commitment-1" {
				seenFirstTx = true
			}
		}
	}

	// Stop the server to simulate arkd going down.
	srv1.Stop()
	time.Sleep(500 * time.Millisecond)

	// Start a new server on the same address to simulate arkd restart.
	lis2, err := net.Listen("tcp", addr)
	require.NoError(t, err)

	srv2 := grpc.NewServer()
	arkv1.RegisterArkServiceServer(srv2, &mockArkStreamServer{txCounter: txCounter})
	go func() {
		_ = srv2.Serve(lis2)
	}()
	t.Cleanup(srv2.Stop)

	var (
		disconnectedAt time.Time
		reconnectedAt  time.Time
		seenSecondTx   bool
	)

	for {
		select {
		case <-ctx.Done():
			require.FailNow(t, "timed out waiting for lifecycle events and post-reconnect data")
		case event, ok := <-eventsCh:
			require.True(t, ok, "transaction stream unexpectedly closed")
			require.Nil(t, event.Err)

			if event.Connection != nil {
				switch event.Connection.State {
				case types.StreamConnectionStateDisconnected:
					disconnectedAt = event.Connection.At
				case types.StreamConnectionStateReconnected:
					reconnectedAt = event.Connection.At
				}
			}

			if event.CommitmentTx != nil && event.CommitmentTx.Txid == "commitment-2" {
				seenSecondTx = true
			}

			if !disconnectedAt.IsZero() && !reconnectedAt.IsZero() && seenSecondTx {
				require.True(
					t, reconnectedAt.After(disconnectedAt) || reconnectedAt.Equal(disconnectedAt),
					"reconnected timestamp must be >= disconnected timestamp",
				)
				return
			}
		}
	}
}

type mockArkStreamServer struct {
	arkv1.UnimplementedArkServiceServer
	txCounter *atomic.Int32
}

func (s *mockArkStreamServer) GetTransactionsStream(
	_ *arkv1.GetTransactionsStreamRequest,
	stream grpc.ServerStreamingServer[arkv1.GetTransactionsStreamResponse],
) error {
	n := s.txCounter.Add(1)

	if err := stream.Send(&arkv1.GetTransactionsStreamResponse{
		Data: &arkv1.GetTransactionsStreamResponse_CommitmentTx{
			CommitmentTx: &arkv1.TxNotification{
				Txid: fmt.Sprintf("commitment-%d", n),
				Tx:   "deadbeef",
			},
		},
	}); err != nil {
		return err
	}

	<-stream.Context().Done()
	return stream.Context().Err()
}
