package indexer

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type testIndexerStreamServer struct {
	arkv1.UnimplementedIndexerServiceServer
	subscriptionCalls atomic.Int32

	rangeMu    sync.Mutex
	lastAfter  int64
	lastBefore int64
}

func (s *testIndexerStreamServer) GetSubscription(
	_ *arkv1.GetSubscriptionRequest,
	stream grpc.ServerStreamingServer[arkv1.GetSubscriptionResponse],
) error {
	call := s.subscriptionCalls.Add(1)

	if err := stream.Send(&arkv1.GetSubscriptionResponse{
		Data: &arkv1.GetSubscriptionResponse_Event{
			Event: &arkv1.IndexerSubscriptionEvent{
				Txid: fmt.Sprintf("subscription-tx-%d", call),
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

func (s *testIndexerStreamServer) SubscribeForScripts(
	_ context.Context,
	req *arkv1.SubscribeForScriptsRequest,
) (*arkv1.SubscribeForScriptsResponse, error) {
	return &arkv1.SubscribeForScriptsResponse{
		SubscriptionId: "id",
	}, nil
}

func (s *testIndexerStreamServer) GetVtxos(
	_ context.Context,
	req *arkv1.GetVtxosRequest,
) (*arkv1.GetVtxosResponse, error) {
	s.rangeMu.Lock()
	s.lastAfter = req.GetAfter()
	s.lastBefore = req.GetBefore()
	s.rangeMu.Unlock()

	return &arkv1.GetVtxosResponse{
		Vtxos: []*arkv1.IndexerVtxo{
			{
				Outpoint: &arkv1.IndexerOutpoint{
					Txid: "delta-vtxo-txid",
					Vout: 0,
				},
				Script:    "0014deadbeef",
				Amount:    1000,
				CreatedAt: req.GetAfter() + 1,
			},
		},
	}, nil
}

func (s *testIndexerStreamServer) lastRange() (after, before int64) {
	s.rangeMu.Lock()
	defer s.rangeMu.Unlock()
	return s.lastAfter, s.lastBefore
}

func TestSubscriptionLifecycleEventsAndDeltaFetchByTimestamp(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	testSrv := &testIndexerStreamServer{}
	srv := grpc.NewServer()
	arkv1.RegisterIndexerServiceServer(srv, testSrv)
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
		conn:    conn,
		connMu:  &sync.RWMutex{},
		scripts: newScriptsCache(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)

	subId, eventsCh, closeFn, err := c.NewSubscription(ctx, []string{"script1", "script2"})
	require.NoError(t, err)
	require.NotEmpty(t, subId)
	require.NotNil(t, eventsCh)
	require.NotNil(t, closeFn)
	t.Cleanup(closeFn)

	var (
		disconnectedAt time.Time
		reconnectedAt  time.Time
		seenSecondTx   bool
	)

	for {
		select {
		case <-ctx.Done():
			require.FailNow(
				t,
				"timed out waiting for lifecycle events and post-reconnect subscription event",
			)
		case event, ok := <-eventsCh:
			require.True(t, ok, "subscription stream unexpectedly closed")
			require.Nil(t, event.Err)

			if event.Connection != nil {
				switch event.Connection.State {
				case types.StreamConnectionStateDisconnected:
					disconnectedAt = event.Connection.At
				case types.StreamConnectionStateReconnected:
					reconnectedAt = event.Connection.At
				}
			}

			if event.Data != nil {
				if event.Data.Txid == "subscription-tx-2" {
					seenSecondTx = true
				}
			}

			if !disconnectedAt.IsZero() && !reconnectedAt.IsZero() && seenSecondTx {
				require.True(
					t, reconnectedAt.After(disconnectedAt) || reconnectedAt.Equal(disconnectedAt),
					"reconnected timestamp must be >= disconnected timestamp",
				)

				// Demonstrate delta fetch over downtime window.
				after := disconnectedAt.Add(-100 * time.Millisecond).UnixMilli()
				before := reconnectedAt.Add(100 * time.Millisecond).UnixMilli()

				opts := []indexer.GetVtxosOption{
					indexer.WithScripts([]string{"0014deadbeef"}),
					indexer.WithTimeRange(before, after),
				}
				resp, getErr := c.GetVtxos(ctx, opts...)
				require.NoError(t, getErr)
				require.Len(t, resp.Vtxos, 1)
				require.Equal(t, "delta-vtxo-txid", resp.Vtxos[0].Txid)

				gotAfter, gotBefore := testSrv.lastRange()
				require.Equal(t, after, gotAfter)
				require.Equal(t, before, gotBefore)
				return
			}
		}
	}
}
