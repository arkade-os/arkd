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

	t.Run("unknown subscription_id returns NotFound", func(t *testing.T) {
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
}
