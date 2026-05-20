package handlers

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Valid P2TR scripts for testing (secp256k1 generator point multiples).
const (
	testScript1 = "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	testScript2 = "5120c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	testScript3 = "5120f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
)

// Compile-time check that mockGetSubscriptionServer satisfies the stream interface.
var _ arkv1.IndexerService_GetSubscriptionServer = (*mockGetSubscriptionServer)(nil)

type mockGetSubscriptionServer struct {
	ctx    context.Context
	sendCh chan *arkv1.GetSubscriptionResponse
}

func newMockGetSubscriptionServer(ctx context.Context) *mockGetSubscriptionServer {
	return &mockGetSubscriptionServer{
		ctx:    ctx,
		sendCh: make(chan *arkv1.GetSubscriptionResponse, 100),
	}
}

func (m *mockGetSubscriptionServer) Send(resp *arkv1.GetSubscriptionResponse) error {
	m.sendCh <- resp
	return nil
}

func (m *mockGetSubscriptionServer) Context() context.Context     { return m.ctx }
func (m *mockGetSubscriptionServer) SetHeader(metadata.MD) error  { return nil }
func (m *mockGetSubscriptionServer) SendHeader(metadata.MD) error { return nil }
func (m *mockGetSubscriptionServer) SetTrailer(metadata.MD)       {}
func (m *mockGetSubscriptionServer) SendMsg(any) error            { return nil }
func (m *mockGetSubscriptionServer) RecvMsg(any) error            { return nil }

// recv waits for the next message sent via stream.Send, failing the test on timeout.
func (m *mockGetSubscriptionServer) recv(t *testing.T, timeout time.Duration) *arkv1.GetSubscriptionResponse {
	t.Helper()
	select {
	case msg := <-m.sendCh:
		return msg
	case <-time.After(timeout):
		t.Fatal("timeout waiting for stream message")
		return nil
	}
}

func newTestIndexerService() *indexerService {
	return &indexerService{
		scriptSubsHandler:           newBroker[*arkv1.GetSubscriptionResponse](),
		subscriptionTimeoutDuration: 10 * time.Second,
		heartbeat:                   time.Second,
	}
}

func overwriteScriptsFilter(scripts ...string) *arkv1.SubscriptionFilter {
	return &arkv1.SubscriptionFilter{
		Filter: &arkv1.SubscriptionFilter_Scripts{
			Scripts: &arkv1.ScriptsFilter{
				Change: &arkv1.ScriptsFilter_Overwrite{
					Overwrite: &arkv1.OverwriteScripts{Scripts: scripts},
				},
			},
		},
	}
}

func overwriteTxFilter(exprs ...string) *arkv1.SubscriptionFilter {
	return &arkv1.SubscriptionFilter{
		Filter: &arkv1.SubscriptionFilter_Txs{
			Txs: &arkv1.TxFilter{
				Change: &arkv1.TxFilter_Overwrite{
					Overwrite: &arkv1.OverwriteTxFilters{Expressions: exprs},
				},
			},
		},
	}
}

func modifyTxFilter(add, remove []string) *arkv1.SubscriptionFilter {
	return &arkv1.SubscriptionFilter{
		Filter: &arkv1.SubscriptionFilter_Txs{
			Txs: &arkv1.TxFilter{
				Change: &arkv1.TxFilter_Modify{
					Modify: &arkv1.ModifyTxFilters{
						AddExpressions:    add,
						RemoveExpressions: remove,
					},
				},
			},
		},
	}
}

// buildTxHexWithPackets builds a minimal tx whose only output is the ARK
// OP_RETURN extension carrying the given packets, and returns it hex-encoded.
// A dummy input is added because wire.MsgTx.Serialize emits the SegWit marker
// for txs with zero inputs, making round-trip via Deserialize fail.
func buildTxHexWithPackets(t *testing.T, pkts ...extension.Packet) string {
	t.Helper()
	ext, err := extension.NewExtensionFromPackets(pkts...)
	require.NoError(t, err)
	out, err := ext.TxOut()
	require.NoError(t, err)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}})
	tx.AddTxOut(out)
	var buf bytes.Buffer
	require.NoError(t, tx.Serialize(&buf))
	return hex.EncodeToString(buf.Bytes())
}

// buildTxHexEmpty builds a tx with one dummy input and no outputs.
func buildTxHexEmpty(t *testing.T) string {
	t.Helper()
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}})
	var buf bytes.Buffer
	require.NoError(t, tx.Serialize(&buf))
	return hex.EncodeToString(buf.Bytes())
}

func TestGetSubscription(t *testing.T) {
	t.Parallel()

	t.Run("new flow sends SubscriptionStartedEvent", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		stream := newMockGetSubscriptionServer(ctx)

		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetSubscription(&arkv1.GetSubscriptionRequest{}, stream)
		}()

		msg := stream.recv(t, time.Second)
		started := msg.GetSubscriptionStarted()
		require.NotNil(t, started)
		require.NotEmpty(t, started.GetSubscriptionId())

		cancel()

		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("GetSubscription did not return after context cancellation")
		}
	})

	t.Run("new flow receives events on subscribed scripts", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		stream := newMockGetSubscriptionServer(ctx)

		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetSubscription(
				&arkv1.GetSubscriptionRequest{
					Filter: overwriteScriptsFilter(testScript1),
				},
				stream,
			)
		}()

		// First message must be SubscriptionStartedEvent.
		msg := stream.recv(t, time.Second)
		subId := msg.GetSubscriptionStarted().GetSubscriptionId()
		require.NotEmpty(t, subId)

		// Push an event via the broker channel.
		ch, err := svc.scriptSubsHandler.getListenerChannel(subId)
		require.NoError(t, err)

		ch <- &arkv1.GetSubscriptionResponse{
			Data: &arkv1.GetSubscriptionResponse_Event{
				Event: &arkv1.IndexerSubscriptionEvent{
					Txid: "deadbeef",
				},
			},
		}

		got := stream.recv(t, time.Second)
		require.Equal(t, "deadbeef", got.GetEvent().GetTxid())

		cancel()

		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("GetSubscription did not return")
		}
	})

	t.Run("new flow listener removed on stream close", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		ctx, cancel := context.WithCancel(context.Background())
		stream := newMockGetSubscriptionServer(ctx)

		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetSubscription(&arkv1.GetSubscriptionRequest{}, stream)
		}()

		msg := stream.recv(t, time.Second)
		subId := msg.GetSubscriptionStarted().GetSubscriptionId()
		require.NotEmpty(t, subId)

		// Listener should be present while the stream is open.
		_, err := svc.scriptSubsHandler.getListenerChannel(subId)
		require.NoError(t, err)

		cancel()

		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("GetSubscription did not return")
		}

		// After handler returns, listener must be removed (defer removeListener).
		_, err = svc.scriptSubsHandler.getListenerChannel(subId)
		require.Error(t, err)
	})

	t.Run("new flow invalid scripts returns error", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		stream := newMockGetSubscriptionServer(context.Background())

		err := svc.GetSubscription(
			&arkv1.GetSubscriptionRequest{
				Filter: overwriteScriptsFilter("notahex"),
			},
			stream,
		)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("new flow sends heartbeat when idle", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		svc.heartbeat = 50 * time.Millisecond // short heartbeat for test speed

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		stream := newMockGetSubscriptionServer(ctx)

		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetSubscription(&arkv1.GetSubscriptionRequest{}, stream)
		}()

		// First message: SubscriptionStartedEvent.
		msg := stream.recv(t, time.Second)
		require.NotNil(t, msg.GetSubscriptionStarted())

		// Second message should be a heartbeat (no events pushed).
		msg = stream.recv(t, time.Second)
		require.NotNil(t, msg.GetHeartbeat())

		cancel()

		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("GetSubscription did not return")
		}
	})

	t.Run("new flow update scripts mid-stream", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		stream := newMockGetSubscriptionServer(ctx)

		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetSubscription(
				&arkv1.GetSubscriptionRequest{
					Filter: overwriteScriptsFilter(testScript1),
				},
				stream,
			)
		}()

		// Receive the SubscriptionStartedEvent to get the subscription ID.
		msg := stream.recv(t, time.Second)
		subId := msg.GetSubscriptionStarted().GetSubscriptionId()
		require.NotEmpty(t, subId)

		// Update scripts: add testScript2 via UpdateSubscription.
		resp, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: subId,
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{
							Change: &arkv1.ScriptsFilter_Modify{
								Modify: &arkv1.ModifyScripts{
									AddScripts: []string{testScript2},
								},
							},
						},
					},
				},
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{testScript1, testScript2}, resp.GetScripts().GetAll())

		// Push an event via the broker channel.
		ch, err := svc.scriptSubsHandler.getListenerChannel(subId)
		require.NoError(t, err)

		ch <- &arkv1.GetSubscriptionResponse{
			Data: &arkv1.GetSubscriptionResponse_Event{
				Event: &arkv1.IndexerSubscriptionEvent{
					Txid: "abc123",
				},
			},
		}

		got := stream.recv(t, time.Second)
		require.Equal(t, "abc123", got.GetEvent().GetTxid())

		cancel()

		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("GetSubscription did not return")
		}
	})

	t.Run("new flow heartbeat resets after event", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		svc.heartbeat = 80 * time.Millisecond

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		stream := newMockGetSubscriptionServer(ctx)

		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetSubscription(
				&arkv1.GetSubscriptionRequest{
					Filter: overwriteScriptsFilter(testScript1),
				},
				stream,
			)
		}()

		msg := stream.recv(t, time.Second)
		subId := msg.GetSubscriptionStarted().GetSubscriptionId()
		require.NotEmpty(t, subId)

		ch, err := svc.scriptSubsHandler.getListenerChannel(subId)
		require.NoError(t, err)

		// Send an event before the heartbeat fires.
		ch <- &arkv1.GetSubscriptionResponse{
			Data: &arkv1.GetSubscriptionResponse_Event{
				Event: &arkv1.IndexerSubscriptionEvent{Txid: "evt1"},
			},
		}

		got := stream.recv(t, time.Second)
		require.Equal(t, "evt1", got.GetEvent().GetTxid())

		// The heartbeat timer was reset by the event. Next message should be
		// a heartbeat ~80ms after the event, not ~20ms.
		got = stream.recv(t, time.Second)
		require.NotNil(t, got.GetHeartbeat())

		cancel()
		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("GetSubscription did not return")
		}
	})

	t.Run("old flow listener preserved with timeout on disconnect", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		svc.subscriptionTimeoutDuration = 500 * time.Millisecond

		// Create subscription via old flow.
		subResp, err := svc.SubscribeForScripts(context.Background(),
			&arkv1.SubscribeForScriptsRequest{Scripts: []string{testScript1}},
		)
		require.NoError(t, err)
		subId := subResp.GetSubscriptionId()

		ctx, cancel := context.WithCancel(context.Background())
		stream := newMockGetSubscriptionServer(ctx)

		ch, err := svc.scriptSubsHandler.getListenerChannel(subId)
		require.NoError(t, err)

		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetSubscription(
				&arkv1.GetSubscriptionRequest{SubscriptionId: subId},
				stream,
			)
		}()

		ch <- &arkv1.GetSubscriptionResponse{
			Data: &arkv1.GetSubscriptionResponse_Event{
				Event: &arkv1.IndexerSubscriptionEvent{Txid: "x"},
			},
		}
		stream.recv(t, time.Second) // consume event

		// Disconnect stream.
		cancel()
		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("GetSubscription did not return")
		}

		// Listener should still exist (timeout not yet expired).
		_, err = svc.scriptSubsHandler.getListenerChannel(subId)
		require.NoError(t, err)

		// After the timeout fires, listener should be cleaned up.
		require.Eventually(t, func() bool {
			_, err := svc.scriptSubsHandler.getListenerChannel(subId)
			return err != nil
		}, 2*time.Second, 50*time.Millisecond)
	})

	t.Run("old flow listener removed on disconnect when no scripts", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		// Create subscription then unsubscribe from all scripts.
		subResp, err := svc.SubscribeForScripts(context.Background(),
			&arkv1.SubscribeForScriptsRequest{Scripts: []string{testScript1}},
		)
		require.NoError(t, err)
		subId := subResp.GetSubscriptionId()

		_, err = svc.UnsubscribeForScripts(context.Background(),
			&arkv1.UnsubscribeForScriptsRequest{SubscriptionId: subId},
		)
		require.NoError(t, err)

		// Re-register the listener (UnsubscribeForScripts with empty scripts
		// removes the listener entirely, so re-create it with no topics).
		listener := newListener[*arkv1.GetSubscriptionResponse](subId, nil)
		svc.scriptSubsHandler.pushListener(listener)

		ctx, cancel := context.WithCancel(context.Background())
		stream := newMockGetSubscriptionServer(ctx)

		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetSubscription(
				&arkv1.GetSubscriptionRequest{SubscriptionId: subId},
				stream,
			)
		}()

		// Give the handler a moment to enter the select loop then disconnect.
		time.Sleep(20 * time.Millisecond)
		cancel()

		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("GetSubscription did not return")
		}

		// Listener should be removed immediately (no scripts → no timeout).
		_, err = svc.scriptSubsHandler.getListenerChannel(subId)
		require.Error(t, err)
	})

	t.Run("old flow existing subscription_id works", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		// Create subscription via SubscribeForScripts (old flow).
		subResp, err := svc.SubscribeForScripts(context.Background(),
			&arkv1.SubscribeForScriptsRequest{
				Scripts: []string{testScript1},
			},
		)
		require.NoError(t, err)
		subId := subResp.GetSubscriptionId()
		require.NotEmpty(t, subId)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		stream := newMockGetSubscriptionServer(ctx)

		// Grab the channel before starting GetSubscription; it is the same
		// channel the handler will read from.
		ch, err := svc.scriptSubsHandler.getListenerChannel(subId)
		require.NoError(t, err)

		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetSubscription(
				&arkv1.GetSubscriptionRequest{SubscriptionId: subId},
				stream,
			)
		}()

		// Push an event; the handler will forward it once it enters the select loop.
		ch <- &arkv1.GetSubscriptionResponse{
			Data: &arkv1.GetSubscriptionResponse_Event{
				Event: &arkv1.IndexerSubscriptionEvent{
					Txid: "cafebabe",
				},
			},
		}

		got := stream.recv(t, time.Second)
		require.Equal(t, "cafebabe", got.GetEvent().GetTxid())

		cancel()

		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("GetSubscription did not return")
		}
	})
}

func TestUpdateSubscription(t *testing.T) {
	t.Parallel()

	t.Run("missing subscription_id", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{},
		)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing filter", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "some-id",
			},
		)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("empty SubscriptionFilter returns InvalidArgument", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "some-id",
				Filter:         &arkv1.SubscriptionFilter{},
			},
		)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("empty ScriptsFilter returns InvalidArgument", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "some-id",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{},
					},
				},
			},
		)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("overwrite replaces all scripts", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse]("test-sub", []string{testScript1})
		svc.scriptSubsHandler.pushListener(listener)

		resp, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{
							Change: &arkv1.ScriptsFilter_Overwrite{
								Overwrite: &arkv1.OverwriteScripts{
									Scripts: []string{testScript2, testScript3},
								},
							},
						},
					},
				},
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{testScript2, testScript3}, resp.GetScripts().GetAll())
	})

	t.Run("modify adds and removes scripts", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse](
			"test-sub", []string{testScript1, testScript2},
		)
		svc.scriptSubsHandler.pushListener(listener)

		resp, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{
							Change: &arkv1.ScriptsFilter_Modify{
								Modify: &arkv1.ModifyScripts{
									AddScripts:    []string{testScript3},
									RemoveScripts: []string{testScript2},
								},
							},
						},
					},
				},
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{testScript3}, resp.GetScripts().GetAdded())
		require.ElementsMatch(t, []string{testScript2}, resp.GetScripts().GetRemoved())
		require.ElementsMatch(t, []string{testScript1, testScript3}, resp.GetScripts().GetAll())
	})

	t.Run("overwrite with invalid scripts returns InvalidArgument", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse]("test-sub", []string{testScript1})
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{
							Change: &arkv1.ScriptsFilter_Overwrite{
								Overwrite: &arkv1.OverwriteScripts{
									Scripts: []string{"invalidhex"},
								},
							},
						},
					},
				},
			},
		)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("modify with invalid add scripts returns InvalidArgument", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse]("test-sub", []string{testScript1})
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{
							Change: &arkv1.ScriptsFilter_Modify{
								Modify: &arkv1.ModifyScripts{
									AddScripts: []string{"notvalid"},
								},
							},
						},
					},
				},
			},
		)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("modify with invalid remove scripts returns InvalidArgument", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse]("test-sub", []string{testScript1})
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{
							Change: &arkv1.ScriptsFilter_Modify{
								Modify: &arkv1.ModifyScripts{
									RemoveScripts: []string{"notvalid"},
								},
							},
						},
					},
				},
			},
		)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("modify add only", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse]("test-sub", []string{testScript1})
		svc.scriptSubsHandler.pushListener(listener)

		resp, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{
							Change: &arkv1.ScriptsFilter_Modify{
								Modify: &arkv1.ModifyScripts{
									AddScripts: []string{testScript2},
								},
							},
						},
					},
				},
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{testScript2}, resp.GetScripts().GetAdded())
		require.Empty(t, resp.GetScripts().GetRemoved())
		require.ElementsMatch(t, []string{testScript1, testScript2}, resp.GetScripts().GetAll())
	})

	t.Run("modify remove only", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse](
			"test-sub", []string{testScript1, testScript2},
		)
		svc.scriptSubsHandler.pushListener(listener)

		resp, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{
							Change: &arkv1.ScriptsFilter_Modify{
								Modify: &arkv1.ModifyScripts{
									RemoveScripts: []string{testScript2},
								},
							},
						},
					},
				},
			},
		)
		require.NoError(t, err)
		require.Empty(t, resp.GetScripts().GetAdded())
		require.ElementsMatch(t, []string{testScript2}, resp.GetScripts().GetRemoved())
		require.ElementsMatch(t, []string{testScript1}, resp.GetScripts().GetAll())
	})

	t.Run("overwrite with empty scripts clears all", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse](
			"test-sub", []string{testScript1, testScript2},
		)
		svc.scriptSubsHandler.pushListener(listener)

		resp, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{
							Change: &arkv1.ScriptsFilter_Overwrite{
								Overwrite: &arkv1.OverwriteScripts{
									Scripts: []string{},
								},
							},
						},
					},
				},
			},
		)
		require.NoError(t, err)
		require.Empty(t, resp.GetScripts().GetAll())
	})

	t.Run("modify with empty add and remove returns InvalidArgument", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse]("test-sub", []string{testScript1})
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{
							Change: &arkv1.ScriptsFilter_Modify{
								Modify: &arkv1.ModifyScripts{},
							},
						},
					},
				},
			},
		)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("unknown subscription_id overwrite returns NotFound", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "nonexistent-id",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{
							Change: &arkv1.ScriptsFilter_Overwrite{
								Overwrite: &arkv1.OverwriteScripts{
									Scripts: []string{testScript1},
								},
							},
						},
					},
				},
			},
		)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("unknown subscription_id modify returns NotFound", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "nonexistent-id",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{
							Change: &arkv1.ScriptsFilter_Modify{
								Modify: &arkv1.ModifyScripts{
									AddScripts: []string{testScript1},
								},
							},
						},
					},
				},
			},
		)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("modify remove unknown subscription_id returns NotFound", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "nonexistent-id",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{
							Change: &arkv1.ScriptsFilter_Modify{
								Modify: &arkv1.ModifyScripts{
									RemoveScripts: []string{testScript1},
								},
							},
						},
					},
				},
			},
		)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("adding duplicate scripts is idempotent", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse]("test-sub", []string{testScript1})
		svc.scriptSubsHandler.pushListener(listener)

		resp, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Scripts{
						Scripts: &arkv1.ScriptsFilter{
							Change: &arkv1.ScriptsFilter_Modify{
								Modify: &arkv1.ModifyScripts{
									AddScripts: []string{testScript1, testScript2},
								},
							},
						},
					},
				},
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{testScript1, testScript2}, resp.GetScripts().GetAll())
	})
}

func TestTxFilter(t *testing.T) {
	t.Parallel()

	const hasExtension = "has(tx.extension)"
	const hasPacket42 = "has(tx.extension) && hasPacket(tx.extension, 0x42)"

	t.Run("GetSubscription initial tx filter", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stream := newMockGetSubscriptionServer(ctx)

		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetSubscription(
				&arkv1.GetSubscriptionRequest{
					Filter: overwriteTxFilter(hasExtension),
				},
				stream,
			)
		}()

		msg := stream.recv(t, time.Second)
		subId := msg.GetSubscriptionStarted().GetSubscriptionId()
		require.NotEmpty(t, subId)

		require.ElementsMatch(t, []string{hasExtension}, svc.scriptSubsHandler.getTxFilters(subId))

		cancel()
		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("GetSubscription did not return")
		}
	})

	t.Run("GetSubscription rejects invalid CEL on init", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		stream := newMockGetSubscriptionServer(context.Background())

		err := svc.GetSubscription(
			&arkv1.GetSubscriptionRequest{
				Filter: overwriteTxFilter("not a valid cel"),
			},
			stream,
		)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("UpdateSubscription Overwrite tx filters", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-overwrite", nil)
		svc.scriptSubsHandler.pushListener(listener)

		resp, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-overwrite",
				Filter:         overwriteTxFilter(hasExtension, hasPacket42),
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(
			t, []string{hasExtension, hasPacket42}, resp.GetTxs().GetAll(),
		)

		// Overwrite again with a single expression.
		resp, err = svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-overwrite",
				Filter:         overwriteTxFilter(hasExtension),
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{hasExtension}, resp.GetTxs().GetAll())
	})

	t.Run("UpdateSubscription Modify add and remove", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-modify", nil)
		svc.scriptSubsHandler.pushListener(listener)

		resp, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-modify",
				Filter:         modifyTxFilter([]string{hasExtension, hasPacket42}, nil),
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{hasExtension, hasPacket42}, resp.GetTxs().GetAll())
		require.ElementsMatch(t, []string{hasExtension, hasPacket42}, resp.GetTxs().GetAdded())

		resp, err = svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-modify",
				Filter:         modifyTxFilter(nil, []string{hasPacket42}),
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{hasExtension}, resp.GetTxs().GetAll())
		require.ElementsMatch(t, []string{hasPacket42}, resp.GetTxs().GetRemoved())
	})

	t.Run("UpdateSubscription rejects invalid CEL", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-bad", nil)
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-bad",
				Filter:         overwriteTxFilter("&&&"),
			},
		)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())

		// Invalid expr must not mutate listener state.
		require.Empty(t, svc.scriptSubsHandler.getTxFilters("sub-bad"))
	})

	t.Run("UpdateSubscription rejects missing change", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-empty", nil)
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-empty",
				Filter: &arkv1.SubscriptionFilter{
					Filter: &arkv1.SubscriptionFilter_Txs{Txs: &arkv1.TxFilter{}},
				},
			},
		)
		require.Error(t, err)
		st, _ := status.FromError(err)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("listenToTxEvents dispatches on tx filter match only", func(t *testing.T) {
		t.Parallel()
		eventsCh := make(chan application.TransactionEvent, 1)
		svc := newTestIndexerServiceWithEvents(eventsCh)
		go svc.listenToTxEvents()

		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-tx-only", nil)
		svc.scriptSubsHandler.pushListener(listener)
		require.NoError(
			t, svc.scriptSubsHandler.addTxFilters("sub-tx-only", []string{hasExtension}),
		)

		eventsCh <- application.TransactionEvent{
			TxData: application.TxData{
				Txid: "matching-tx",
				Tx: buildTxHexWithPackets(t, extension.UnknownPacket{
					PacketType: 0x42, Data: []byte{0x01},
				}),
			},
		}

		select {
		case ev := <-listener.ch:
			require.Equal(t, "matching-tx", ev.GetEvent().GetTxid())
		case <-time.After(time.Second):
			t.Fatal("listener did not receive tx-filter match")
		}

		eventsCh <- application.TransactionEvent{
			TxData: application.TxData{Txid: "no-ext", Tx: buildTxHexEmpty(t)},
		}
		select {
		case ev := <-listener.ch:
			t.Fatalf("listener received unexpected event: %s", ev.GetEvent().GetTxid())
		case <-time.After(150 * time.Millisecond):
		}
	})

	t.Run("listenToTxEvents OR semantics", func(t *testing.T) {
		// Asserts that a listener with both scripts and tx filters receives:
		//   - events whose tx matches the filter even if no script matches
		//   - events whose vtxos involve a watched script even if tx does not match
		//   - both-match events exactly once (no duplication)
		//   - neither-match events are dropped
		// testScript1 = "5120" + testPubKey1, so a vtxo with this PubKey
		// produces vtxoScript == testScript1 in listenToTxEvents.
		const testPubKey1 = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

		setup := func(t *testing.T) (
			chan application.TransactionEvent, *listener[*arkv1.GetSubscriptionResponse],
		) {
			t.Helper()
			eventsCh := make(chan application.TransactionEvent, 4)
			svc := newTestIndexerServiceWithEvents(eventsCh)
			go svc.listenToTxEvents()

			listener := newListener[*arkv1.GetSubscriptionResponse](
				"sub-or", []string{testScript1},
			)
			svc.scriptSubsHandler.pushListener(listener)
			require.NoError(
				t, svc.scriptSubsHandler.addTxFilters("sub-or", []string{hasExtension}),
			)
			return eventsCh, listener
		}

		t.Run("script match without tx match", func(t *testing.T) {
			t.Parallel()
			eventsCh, listener := setup(t)
			// Tx has no extension; vtxo matches testScript1.
			eventsCh <- application.TransactionEvent{
				TxData: application.TxData{Txid: "script-only", Tx: buildTxHexEmpty(t)},
				SpendableVtxos: []domain.Vtxo{{
					PubKey: testPubKey1,
				}},
			}
			select {
			case ev := <-listener.ch:
				require.Equal(t, "script-only", ev.GetEvent().GetTxid())
			case <-time.After(time.Second):
				t.Fatal("listener did not receive script-only event")
			}
		})

		t.Run("tx match without script match", func(t *testing.T) {
			t.Parallel()
			eventsCh, listener := setup(t)
			eventsCh <- application.TransactionEvent{
				TxData: application.TxData{Txid: "tx-only", Tx: buildTxHexWithPackets(t,
					extension.UnknownPacket{PacketType: 0x01, Data: []byte{0x02}},
				)},
			}
			select {
			case ev := <-listener.ch:
				require.Equal(t, "tx-only", ev.GetEvent().GetTxid())
			case <-time.After(time.Second):
				t.Fatal("listener did not receive tx-only event")
			}
		})

		t.Run("both match dispatches exactly once", func(t *testing.T) {
			t.Parallel()
			eventsCh, listener := setup(t)
			eventsCh <- application.TransactionEvent{
				TxData: application.TxData{Txid: "both", Tx: buildTxHexWithPackets(t,
					extension.UnknownPacket{PacketType: 0x01, Data: []byte{0x02}},
				)},
				SpendableVtxos: []domain.Vtxo{{PubKey: testPubKey1}},
			}
			select {
			case ev := <-listener.ch:
				require.Equal(t, "both", ev.GetEvent().GetTxid())
			case <-time.After(time.Second):
				t.Fatal("listener did not receive both-match event")
			}
			// Confirm no duplicate is delivered.
			select {
			case ev := <-listener.ch:
				t.Fatalf("unexpected duplicate event: %s", ev.GetEvent().GetTxid())
			case <-time.After(150 * time.Millisecond):
			}
		})

		t.Run("neither match is dropped", func(t *testing.T) {
			t.Parallel()
			eventsCh, listener := setup(t)
			eventsCh <- application.TransactionEvent{
				TxData: application.TxData{Txid: "neither", Tx: buildTxHexEmpty(t)},
			}
			select {
			case ev := <-listener.ch:
				t.Fatalf("unexpected event: %s", ev.GetEvent().GetTxid())
			case <-time.After(150 * time.Millisecond):
			}
		})
	})

	t.Run("listenToTxEvents script match when tx is unparseable", func(t *testing.T) {
		t.Parallel()
		// Verifies that bad event.Tx bytes don't break the script-match path.
		const testPubKey1 = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

		eventsCh := make(chan application.TransactionEvent, 1)
		svc := newTestIndexerServiceWithEvents(eventsCh)
		go svc.listenToTxEvents()

		listener := newListener[*arkv1.GetSubscriptionResponse](
			"sub-bad-tx", []string{testScript1},
		)
		svc.scriptSubsHandler.pushListener(listener)
		// Even a listener with a tx filter set should still get the event via script.
		require.NoError(
			t, svc.scriptSubsHandler.addTxFilters("sub-bad-tx", []string{hasExtension}),
		)

		eventsCh <- application.TransactionEvent{
			TxData:         application.TxData{Txid: "bad", Tx: "not-hex"},
			SpendableVtxos: []domain.Vtxo{{PubKey: testPubKey1}},
		}
		select {
		case ev := <-listener.ch:
			require.Equal(t, "bad", ev.GetEvent().GetTxid())
		case <-time.After(time.Second):
			t.Fatal("listener did not receive event when tx is unparseable")
		}
	})

	t.Run("UpdateSubscription Modify-Add invalid CEL leaves state untouched", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-atomic", nil)
		svc.scriptSubsHandler.pushListener(listener)
		require.NoError(t, svc.scriptSubsHandler.addTxFilters(
			"sub-atomic", []string{hasExtension},
		))

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-atomic",
				Filter: modifyTxFilter(
					[]string{hasPacket42, "&&& invalid"},
					[]string{hasExtension},
				),
			},
		)
		require.Error(t, err)
		st, _ := status.FromError(err)
		require.Equal(t, codes.InvalidArgument, st.Code())

		// Pre-existing filter still set, requested adds not applied, removes not applied.
		require.ElementsMatch(
			t, []string{hasExtension}, svc.scriptSubsHandler.getTxFilters("sub-atomic"),
		)
	})

	t.Run("UpdateSubscription Modify-Remove of unknown expression is idempotent", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-rm", nil)
		svc.scriptSubsHandler.pushListener(listener)
		require.NoError(t, svc.scriptSubsHandler.addTxFilters("sub-rm", []string{hasExtension}))

		resp, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-rm",
				Filter:         modifyTxFilter(nil, []string{"never-added"}),
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{hasExtension}, resp.GetTxs().GetAll())
	})

	t.Run("addTxFilters is idempotent for duplicate expressions", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-dup", nil)
		svc.scriptSubsHandler.pushListener(listener)

		require.NoError(t, svc.scriptSubsHandler.addTxFilters("sub-dup", []string{hasExtension}))
		require.NoError(t, svc.scriptSubsHandler.addTxFilters("sub-dup", []string{hasExtension}))
		require.ElementsMatch(
			t, []string{hasExtension}, svc.scriptSubsHandler.getTxFilters("sub-dup"),
		)
	})

	t.Run("matchesTx does not invoke getTx when no filters set", func(t *testing.T) {
		t.Parallel()
		listener := newListener[*arkv1.GetSubscriptionResponse]("no-filters", nil)
		called := false
		result := listener.matchesTx(func() *wire.MsgTx {
			called = true
			return nil
		})
		require.False(t, result)
		require.False(
			t, called,
			"getTx should not be invoked when listener has no tx filters",
		)
	})

	t.Run("addTxFilters rejects over-cap input", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-cap", nil)
		svc.scriptSubsHandler.pushListener(listener)

		// Build a slate of unique expressions just over the cap.
		exprs := make([]string, MaxTxFiltersPerListener+1)
		for i := range exprs {
			exprs[i] = fmt.Sprintf("hasPacket(tx.extension, %d)", i)
		}
		err := svc.scriptSubsHandler.addTxFilters("sub-cap", exprs)
		require.ErrorIs(t, err, ErrTxFiltersLimitExceeded)
		require.Empty(t, svc.scriptSubsHandler.getTxFilters("sub-cap"))
	})

	t.Run("addTxFilters enforces cap across multiple calls", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-cap-2", nil)
		svc.scriptSubsHandler.pushListener(listener)

		// Fill exactly to the cap.
		first := make([]string, MaxTxFiltersPerListener)
		for i := range first {
			first[i] = fmt.Sprintf("hasPacket(tx.extension, %d)", i)
		}
		require.NoError(t, svc.scriptSubsHandler.addTxFilters("sub-cap-2", first))
		require.Len(t, svc.scriptSubsHandler.getTxFilters("sub-cap-2"), MaxTxFiltersPerListener)

		// Adding a new distinct expression must be rejected.
		err := svc.scriptSubsHandler.addTxFilters("sub-cap-2", []string{
			"hasPacket(tx.extension, 9999)",
		})
		require.ErrorIs(t, err, ErrTxFiltersLimitExceeded)
		require.Len(t, svc.scriptSubsHandler.getTxFilters("sub-cap-2"), MaxTxFiltersPerListener)

		// But re-adding an existing expression should still work (idempotent;
		// doesn't grow the set).
		require.NoError(t, svc.scriptSubsHandler.addTxFilters("sub-cap-2", []string{first[0]}))
		require.Len(t, svc.scriptSubsHandler.getTxFilters("sub-cap-2"), MaxTxFiltersPerListener)
	})

	t.Run("overwriteTxFilters rejects over-cap input", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-ow-cap", nil)
		svc.scriptSubsHandler.pushListener(listener)
		require.NoError(t, svc.scriptSubsHandler.addTxFilters("sub-ow-cap", []string{hasExtension}))

		exprs := make([]string, MaxTxFiltersPerListener+1)
		for i := range exprs {
			exprs[i] = fmt.Sprintf("hasPacket(tx.extension, %d)", i)
		}
		err := svc.scriptSubsHandler.overwriteTxFilters("sub-ow-cap", exprs)
		require.ErrorIs(t, err, ErrTxFiltersLimitExceeded)
		// pre-existing filter unchanged
		require.ElementsMatch(
			t, []string{hasExtension},
			svc.scriptSubsHandler.getTxFilters("sub-ow-cap"),
		)
	})

	t.Run("not-found maps to gRPC NotFound via sentinel error", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "missing",
				Filter:         overwriteTxFilter(hasExtension),
			},
		)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.NotFound, st.Code())
	})
}

func newTestIndexerServiceWithEvents(
	eventsCh <-chan application.TransactionEvent,
) *indexerService {
	svc := newTestIndexerService()
	svc.eventsCh = eventsCh
	return svc
}
