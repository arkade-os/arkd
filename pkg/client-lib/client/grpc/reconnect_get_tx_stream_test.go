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
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
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
				case client.StreamConnectionStateDisconnected:
					disconnectedAt = event.Connection.At
				case client.StreamConnectionStateReconnected:
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
