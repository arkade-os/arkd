package handlers

import (
	"context"
	"testing"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
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
				&arkv1.GetSubscriptionRequest{Scripts: []string{testScript1}},
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
			&arkv1.GetSubscriptionRequest{Scripts: []string{"notahex"}},
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
				&arkv1.GetSubscriptionRequest{Scripts: []string{testScript1}},
				stream,
			)
		}()

		// Receive the SubscriptionStartedEvent to get the subscription ID.
		msg := stream.recv(t, time.Second)
		subId := msg.GetSubscriptionStarted().GetSubscriptionId()
		require.NotEmpty(t, subId)

		// Update scripts: add testScript2 via UpdateSubscriptionScripts.
		resp, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: subId,
				ScriptsChange: &arkv1.UpdateSubscriptionScriptsRequest_Modify{
					Modify: &arkv1.ModifyScripts{
						AddScripts: []string{testScript2},
					},
				},
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{testScript1, testScript2}, resp.GetAllScripts())

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
				&arkv1.GetSubscriptionRequest{Scripts: []string{testScript1}},
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

func TestUpdateSubscriptionScripts(t *testing.T) {
	t.Parallel()

	t.Run("missing subscription_id", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		_, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{},
		)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing scripts_change", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		_, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: "some-id",
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

		resp, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: "test-sub",
				ScriptsChange: &arkv1.UpdateSubscriptionScriptsRequest_Overwrite{
					Overwrite: &arkv1.OverwriteScripts{
						Scripts: []string{testScript2, testScript3},
					},
				},
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{testScript2, testScript3}, resp.GetAllScripts())
	})

	t.Run("modify adds and removes scripts", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse](
			"test-sub", []string{testScript1, testScript2},
		)
		svc.scriptSubsHandler.pushListener(listener)

		resp, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: "test-sub",
				ScriptsChange: &arkv1.UpdateSubscriptionScriptsRequest_Modify{
					Modify: &arkv1.ModifyScripts{
						AddScripts:    []string{testScript3},
						RemoveScripts: []string{testScript2},
					},
				},
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{testScript3}, resp.GetScriptsAdded())
		require.ElementsMatch(t, []string{testScript2}, resp.GetScriptsRemoved())
		require.ElementsMatch(t, []string{testScript1, testScript3}, resp.GetAllScripts())
	})

	t.Run("overwrite with invalid scripts returns InvalidArgument", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse]("test-sub", []string{testScript1})
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: "test-sub",
				ScriptsChange: &arkv1.UpdateSubscriptionScriptsRequest_Overwrite{
					Overwrite: &arkv1.OverwriteScripts{
						Scripts: []string{"invalidhex"},
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

		_, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: "test-sub",
				ScriptsChange: &arkv1.UpdateSubscriptionScriptsRequest_Modify{
					Modify: &arkv1.ModifyScripts{
						AddScripts: []string{"notvalid"},
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

		_, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: "test-sub",
				ScriptsChange: &arkv1.UpdateSubscriptionScriptsRequest_Modify{
					Modify: &arkv1.ModifyScripts{
						RemoveScripts: []string{"notvalid"},
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

		resp, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: "test-sub",
				ScriptsChange: &arkv1.UpdateSubscriptionScriptsRequest_Modify{
					Modify: &arkv1.ModifyScripts{
						AddScripts: []string{testScript2},
					},
				},
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{testScript2}, resp.GetScriptsAdded())
		require.Empty(t, resp.GetScriptsRemoved())
		require.ElementsMatch(t, []string{testScript1, testScript2}, resp.GetAllScripts())
	})

	t.Run("modify remove only", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse](
			"test-sub", []string{testScript1, testScript2},
		)
		svc.scriptSubsHandler.pushListener(listener)

		resp, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: "test-sub",
				ScriptsChange: &arkv1.UpdateSubscriptionScriptsRequest_Modify{
					Modify: &arkv1.ModifyScripts{
						RemoveScripts: []string{testScript2},
					},
				},
			},
		)
		require.NoError(t, err)
		require.Empty(t, resp.GetScriptsAdded())
		require.ElementsMatch(t, []string{testScript2}, resp.GetScriptsRemoved())
		require.ElementsMatch(t, []string{testScript1}, resp.GetAllScripts())
	})

	t.Run("overwrite with empty scripts clears all", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse](
			"test-sub", []string{testScript1, testScript2},
		)
		svc.scriptSubsHandler.pushListener(listener)

		resp, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: "test-sub",
				ScriptsChange: &arkv1.UpdateSubscriptionScriptsRequest_Overwrite{
					Overwrite: &arkv1.OverwriteScripts{
						Scripts: []string{},
					},
				},
			},
		)
		require.NoError(t, err)
		require.Empty(t, resp.GetAllScripts())
	})

	t.Run("modify with empty add and remove returns InvalidArgument", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		listener := newListener[*arkv1.GetSubscriptionResponse]("test-sub", []string{testScript1})
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: "test-sub",
				ScriptsChange: &arkv1.UpdateSubscriptionScriptsRequest_Modify{
					Modify: &arkv1.ModifyScripts{},
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

		_, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: "nonexistent-id",
				ScriptsChange: &arkv1.UpdateSubscriptionScriptsRequest_Overwrite{
					Overwrite: &arkv1.OverwriteScripts{
						Scripts: []string{testScript1},
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

		_, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: "nonexistent-id",
				ScriptsChange: &arkv1.UpdateSubscriptionScriptsRequest_Modify{
					Modify: &arkv1.ModifyScripts{
						AddScripts: []string{testScript1},
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

		_, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: "nonexistent-id",
				ScriptsChange: &arkv1.UpdateSubscriptionScriptsRequest_Modify{
					Modify: &arkv1.ModifyScripts{
						RemoveScripts: []string{testScript1},
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

		resp, err := svc.UpdateSubscriptionScripts(context.Background(),
			&arkv1.UpdateSubscriptionScriptsRequest{
				SubscriptionId: "test-sub",
				ScriptsChange: &arkv1.UpdateSubscriptionScriptsRequest_Modify{
					Modify: &arkv1.ModifyScripts{
						AddScripts: []string{testScript1, testScript2},
					},
				},
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{testScript1, testScript2}, resp.GetAllScripts())
	})
}
