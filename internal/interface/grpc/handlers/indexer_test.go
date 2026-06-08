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
	"github.com/btcsuite/btcd/btcutil/psbt"
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

// Cursor pagination is continued via the auth_token, not by re-submitting the
// intent proof, so combining an intent with a page_token must be rejected before
// the request reaches the application service.
func TestGetVtxoChainRejectsPageTokenWithIntent(t *testing.T) {
	svc := newTestIndexerService()

	_, err := svc.GetVtxoChain(context.Background(), &arkv1.GetVtxoChainRequest{
		Auth:      &arkv1.GetVtxoChainRequest_Intent{Intent: &arkv1.IndexerIntent{}},
		PageToken: "some-token",
	})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, err.Error(), "page_token is not supported with intent")
}

// seedTxFilters installs the given CEL expressions on a listener for test
// fixtures. The handler's applyFilter is the production code path; this
// helper exists so tests can populate state without going through the full
// SubscriptionFilter plumbing.
func seedTxFilters(
	t *testing.T, svc *indexerService, id string, exprs ...string,
) {
	t.Helper()
	filters, err := compileTxFilters(exprs)
	require.NoError(t, err)
	require.NoError(t, svc.scriptSubsHandler.installTxFilters(id, filters))
}

func scriptsAddFilter(scripts ...string) *arkv1.SubscriptionFilter {
	return &arkv1.SubscriptionFilter{
		Scripts: &arkv1.ScriptFilter{Add: scripts},
	}
}

func txExpressionsFilter(exprs ...string) *arkv1.SubscriptionFilter {
	return &arkv1.SubscriptionFilter{
		Expressions: exprs,
	}
}

// buildTxBase64WithPackets builds a tx carrying the given ARK OP_RETURN
// extension packets and returns it as a base64-encoded PSBT, matching the
// shape that the production producer puts in TransactionEvent.Tx for
// commitment and ark txs.
func buildTxBase64WithPackets(t *testing.T, pkts ...extension.Packet) string {
	t.Helper()
	ext, err := extension.NewExtensionFromPackets(pkts...)
	require.NoError(t, err)
	out, err := ext.TxOut()
	require.NoError(t, err)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}})
	tx.AddTxOut(out)
	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	b64, err := ptx.B64Encode()
	require.NoError(t, err)
	return b64
}

// buildTxBase64Empty builds a tx with one dummy input and no outputs,
// base64-encoded as a PSBT.
func buildTxBase64Empty(t *testing.T) string {
	t.Helper()
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}})
	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	b64, err := ptx.B64Encode()
	require.NoError(t, err)
	return b64
}

// buildTxHexWithPackets builds the same tx as buildTxBase64WithPackets but
// hex-encoded as a raw signed tx, matching the shape used for sweep txs in
// production. Retained to exercise the hex fallback path in parseTxOnce.
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
					Filter: scriptsAddFilter(testScript1),
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
				Filter: scriptsAddFilter("notahex"),
			},
			stream,
		)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("new flow ignores scripts.remove on creation", func(t *testing.T) {
		t.Parallel()
		// On stream creation there is nothing to remove yet. A populated (even
		// invalid) scripts.remove must be ignored without erroring or wiping
		// the freshly-added scripts.
		svc := newTestIndexerService()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stream := newMockGetSubscriptionServer(ctx)

		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetSubscription(
				&arkv1.GetSubscriptionRequest{
					Filter: &arkv1.SubscriptionFilter{
						Scripts: &arkv1.ScriptFilter{
							Add:    []string{testScript1},
							Remove: []string{"bad-hex"},
						},
					},
				},
				stream,
			)
		}()

		msg := stream.recv(t, time.Second)
		subId := msg.GetSubscriptionStarted().GetSubscriptionId()
		require.NotEmpty(t, subId)

		require.ElementsMatch(
			t, []string{testScript1}, svc.scriptSubsHandler.getTopics(subId),
		)

		cancel()
		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("GetSubscription did not return")
		}
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
					Filter: scriptsAddFilter(testScript1),
				},
				stream,
			)
		}()

		// Receive the SubscriptionStartedEvent to get the subscription ID.
		msg := stream.recv(t, time.Second)
		subId := msg.GetSubscriptionStarted().GetSubscriptionId()
		require.NotEmpty(t, subId)

		// Update scripts: add testScript2 via UpdateSubscription.
		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: subId,
				Filter:         scriptsAddFilter(testScript2),
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(
			t, []string{testScript1, testScript2},
			svc.scriptSubsHandler.getTopics(subId),
		)

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
					Filter: scriptsAddFilter(testScript1),
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

	t.Run("empty SubscriptionFilter leaves scripts untouched", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse](
			"sub-noop", []string{testScript1},
		)
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-noop",
				Filter:         &arkv1.SubscriptionFilter{},
			},
		)
		require.NoError(t, err)
		// Scripts field is nil so scripts are untouched. Expressions are
		// overwritten with the empty list, which is a no-op when none were set.
		// The expressions-wipe case is covered by TestTxFilter.
		require.ElementsMatch(
			t, []string{testScript1}, svc.scriptSubsHandler.getTopics("sub-noop"),
		)
		require.Empty(t, svc.scriptSubsHandler.getTxFilters("sub-noop"))
	})

	t.Run("empty ScriptFilter clears all scripts", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse](
			"sub-clear", []string{testScript1, testScript2},
		)
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-clear",
				Filter: &arkv1.SubscriptionFilter{
					Scripts: &arkv1.ScriptFilter{},
				},
			},
		)
		require.NoError(t, err)
		require.Empty(t, svc.scriptSubsHandler.getTopics("sub-clear"))
	})

	t.Run("scripts add and remove applied together", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse](
			"test-sub", []string{testScript1, testScript2},
		)
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter: &arkv1.SubscriptionFilter{
					Scripts: &arkv1.ScriptFilter{
						Add:    []string{testScript3},
						Remove: []string{testScript2},
					},
				},
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(
			t, []string{testScript1, testScript3},
			svc.scriptSubsHandler.getTopics("test-sub"),
		)
	})

	t.Run("invalid script in add returns InvalidArgument", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("test-sub", []string{testScript1})
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter: &arkv1.SubscriptionFilter{
					Scripts: &arkv1.ScriptFilter{Add: []string{"notvalid"}},
				},
			},
		)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
		require.ElementsMatch(
			t, []string{testScript1}, svc.scriptSubsHandler.getTopics("test-sub"),
		)
	})

	t.Run("invalid script in remove returns InvalidArgument", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("test-sub", []string{testScript1})
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter: &arkv1.SubscriptionFilter{
					Scripts: &arkv1.ScriptFilter{Remove: []string{"notvalid"}},
				},
			},
		)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("scripts add only", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("test-sub", []string{testScript1})
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter:         scriptsAddFilter(testScript2),
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(
			t, []string{testScript1, testScript2},
			svc.scriptSubsHandler.getTopics("test-sub"),
		)
	})

	t.Run("scripts remove only", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse](
			"test-sub", []string{testScript1, testScript2},
		)
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter: &arkv1.SubscriptionFilter{
					Scripts: &arkv1.ScriptFilter{Remove: []string{testScript2}},
				},
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(
			t, []string{testScript1}, svc.scriptSubsHandler.getTopics("test-sub"),
		)
	})

	t.Run("unknown subscription_id with scripts returns NotFound", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "nonexistent-id",
				Filter:         scriptsAddFilter(testScript1),
			},
		)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("unknown subscription_id with remove returns NotFound", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "nonexistent-id",
				Filter: &arkv1.SubscriptionFilter{
					Scripts: &arkv1.ScriptFilter{Remove: []string{testScript1}},
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

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "test-sub",
				Filter:         scriptsAddFilter(testScript1, testScript2),
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(
			t, []string{testScript1, testScript2},
			svc.scriptSubsHandler.getTopics("test-sub"),
		)
	})

	t.Run("expressions and scripts.add applied in one call", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("combo", nil)
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "combo",
				Filter: &arkv1.SubscriptionFilter{
					Expressions: []string{"has(tx.extension)"},
					Scripts:     &arkv1.ScriptFilter{Add: []string{testScript1}},
				},
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(
			t, []string{"has(tx.extension)"},
			svc.scriptSubsHandler.getTxFilters("combo"),
		)
		require.ElementsMatch(
			t, []string{testScript1}, svc.scriptSubsHandler.getTopics("combo"),
		)
	})

	t.Run("invalid scripts.add does not mutate expressions", func(t *testing.T) {
		// Regression: a SubscriptionFilter carrying valid expressions and an
		// invalid script in scripts.add must not overwrite the pre-existing
		// expressions before failing. All inputs are validated up front.
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-atom", nil)
		svc.scriptSubsHandler.pushListener(listener)
		seedTxFilters(t, svc, "sub-atom", "has(tx.extension)")

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-atom",
				Filter: &arkv1.SubscriptionFilter{
					Expressions: []string{"hasPacket(tx.extension, 0x42)"},
					Scripts:     &arkv1.ScriptFilter{Add: []string{"bad-hex"}},
				},
			},
		)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())

		// Expressions untouched: still the original single entry.
		require.ElementsMatch(
			t, []string{"has(tx.extension)"},
			svc.scriptSubsHandler.getTxFilters("sub-atom"),
		)
		require.Empty(t, svc.scriptSubsHandler.getTopics("sub-atom"))
	})

	t.Run("invalid scripts.remove does not mutate expressions or add", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse](
			"sub-atom2", []string{testScript1},
		)
		svc.scriptSubsHandler.pushListener(listener)
		seedTxFilters(t, svc, "sub-atom2", "has(tx.extension)")

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-atom2",
				Filter: &arkv1.SubscriptionFilter{
					Expressions: []string{"hasPacket(tx.extension, 0x42)"},
					Scripts: &arkv1.ScriptFilter{
						Add:    []string{testScript2},
						Remove: []string{"bad-hex"},
					},
				},
			},
		)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())

		require.ElementsMatch(
			t, []string{"has(tx.extension)"},
			svc.scriptSubsHandler.getTxFilters("sub-atom2"),
		)
		require.ElementsMatch(
			t, []string{testScript1}, svc.scriptSubsHandler.getTopics("sub-atom2"),
		)
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
					Filter: txExpressionsFilter(hasExtension),
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
				Filter: txExpressionsFilter("not a valid cel"),
			},
			stream,
		)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("UpdateSubscription overwrites tx filters", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-overwrite", nil)
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-overwrite",
				Filter:         txExpressionsFilter(hasExtension, hasPacket42),
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(
			t, []string{hasExtension, hasPacket42},
			svc.scriptSubsHandler.getTxFilters("sub-overwrite"),
		)

		// A second call with a single expression overwrites the first set.
		_, err = svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-overwrite",
				Filter:         txExpressionsFilter(hasExtension),
			},
		)
		require.NoError(t, err)
		require.ElementsMatch(
			t, []string{hasExtension},
			svc.scriptSubsHandler.getTxFilters("sub-overwrite"),
		)
	})

	t.Run("UpdateSubscription with empty expressions wipes them", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-wipe", nil)
		svc.scriptSubsHandler.pushListener(listener)
		seedTxFilters(t, svc, "sub-wipe", hasExtension, hasPacket42)

		// Filter has no expressions field set: literal overwrite clears them.
		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-wipe",
				Filter:         &arkv1.SubscriptionFilter{},
			},
		)
		require.NoError(t, err)
		require.Empty(t, svc.scriptSubsHandler.getTxFilters("sub-wipe"))
	})

	t.Run("UpdateSubscription rejects invalid CEL", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-bad", nil)
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-bad",
				Filter:         txExpressionsFilter("&&&"),
			},
		)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())

		// Invalid expr must not mutate listener state.
		require.Empty(t, svc.scriptSubsHandler.getTxFilters("sub-bad"))
	})

	t.Run("UpdateSubscription invalid CEL leaves existing filters untouched", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-atomic", nil)
		svc.scriptSubsHandler.pushListener(listener)
		seedTxFilters(t, svc, "sub-atomic", hasExtension)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-atomic",
				Filter:         txExpressionsFilter(hasPacket42, "&&& invalid"),
			},
		)
		require.Error(t, err)
		st, _ := status.FromError(err)
		require.Equal(t, codes.InvalidArgument, st.Code())
		require.ElementsMatch(
			t, []string{hasExtension}, svc.scriptSubsHandler.getTxFilters("sub-atomic"),
		)
	})

	t.Run("listenToTxEvents dispatches on tx filter match only", func(t *testing.T) {
		t.Parallel()
		eventsCh := make(chan application.TransactionEvent, 1)
		t.Cleanup(func() { close(eventsCh) })
		svc := newTestIndexerServiceWithEvents(eventsCh)
		go svc.listenToTxEvents()

		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-tx-only", nil)
		svc.scriptSubsHandler.pushListener(listener)
		seedTxFilters(t, svc, "sub-tx-only", hasExtension)

		eventsCh <- application.TransactionEvent{
			TxData: application.TxData{
				Txid: "matching-tx",
				Tx: buildTxBase64WithPackets(t, extension.UnknownPacket{
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
			TxData: application.TxData{Txid: "no-ext", Tx: buildTxBase64Empty(t)},
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
			t.Cleanup(func() { close(eventsCh) })
			svc := newTestIndexerServiceWithEvents(eventsCh)
			go svc.listenToTxEvents()

			listener := newListener[*arkv1.GetSubscriptionResponse](
				"sub-or", []string{testScript1},
			)
			svc.scriptSubsHandler.pushListener(listener)
			seedTxFilters(t, svc, "sub-or", hasExtension)
			return eventsCh, listener
		}

		t.Run("script match without tx match", func(t *testing.T) {
			t.Parallel()
			eventsCh, listener := setup(t)
			// Tx has no extension; vtxo matches testScript1.
			eventsCh <- application.TransactionEvent{
				TxData: application.TxData{Txid: "script-only", Tx: buildTxBase64Empty(t)},
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
				TxData: application.TxData{Txid: "tx-only", Tx: buildTxBase64WithPackets(t,
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
				TxData: application.TxData{Txid: "both", Tx: buildTxBase64WithPackets(t,
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
				TxData: application.TxData{Txid: "neither", Tx: buildTxBase64Empty(t)},
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
		t.Cleanup(func() { close(eventsCh) })
		svc := newTestIndexerServiceWithEvents(eventsCh)
		go svc.listenToTxEvents()

		listener := newListener[*arkv1.GetSubscriptionResponse](
			"sub-bad-tx", []string{testScript1},
		)
		svc.scriptSubsHandler.pushListener(listener)
		// Even a listener with a tx filter set should still get the event via script.
		seedTxFilters(t, svc, "sub-bad-tx", hasExtension)

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

	t.Run("UpdateSubscription dedupes duplicate expressions", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-dup", nil)
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-dup",
				Filter:         txExpressionsFilter(hasExtension, hasExtension),
			},
		)
		require.NoError(t, err)
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

	t.Run("old-flow disconnect keeps listener alive if only tx filters set", func(t *testing.T) {
		t.Parallel()
		// Regression for the cleanup path that previously only checked
		// scripts: a listener with tx filters but no scripts should be put
		// on the timeout window, not destroyed, on disconnect.
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-old-tx", nil)
		svc.scriptSubsHandler.pushListener(listener)
		seedTxFilters(t, svc, "sub-old-tx", hasExtension)

		ctx, cancel := context.WithCancel(context.Background())
		stream := newMockGetSubscriptionServer(ctx)
		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetSubscription(
				&arkv1.GetSubscriptionRequest{SubscriptionId: "sub-old-tx"},
				stream,
			)
		}()

		// Wait briefly for the handler to enter its loop, then disconnect.
		time.Sleep(50 * time.Millisecond)
		cancel()
		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("GetSubscription did not return")
		}

		// Listener should still be present (timeout-scheduled), not removed.
		_, err := svc.scriptSubsHandler.getListenerChannel("sub-old-tx")
		require.NoError(t, err)
		require.ElementsMatch(
			t, []string{hasExtension},
			svc.scriptSubsHandler.getTxFilters("sub-old-tx"),
		)
	})

	t.Run("UpdateSubscription Overwrite over-cap returns InvalidArgument", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-cap-grpc", nil)
		svc.scriptSubsHandler.pushListener(listener)

		exprs := make([]string, MaxTxFiltersPerListener+1)
		for i := range exprs {
			exprs[i] = fmt.Sprintf("hasPacket(tx.extension, %d)", i)
		}
		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "sub-cap-grpc",
				Filter:         txExpressionsFilter(exprs...),
			},
		)
		require.Error(t, err)
		st, _ := status.FromError(err)
		require.Equal(t, codes.InvalidArgument, st.Code())
		require.Empty(t, svc.scriptSubsHandler.getTxFilters("sub-cap-grpc"))
	})

	t.Run("listenToTxEvents routes per-listener (filter scoping)", func(t *testing.T) {
		t.Parallel()
		// Two listeners with disjoint tx filters; an event that matches A's
		// filter should not reach B.
		eventsCh := make(chan application.TransactionEvent, 2)
		t.Cleanup(func() { close(eventsCh) })
		svc := newTestIndexerServiceWithEvents(eventsCh)
		go svc.listenToTxEvents()

		listenerA := newListener[*arkv1.GetSubscriptionResponse]("a", nil)
		svc.scriptSubsHandler.pushListener(listenerA)
		seedTxFilters(
			t, svc, "a", "has(tx.extension) && hasPacket(tx.extension, 0x42)",
		)

		listenerB := newListener[*arkv1.GetSubscriptionResponse]("b", nil)
		svc.scriptSubsHandler.pushListener(listenerB)
		seedTxFilters(
			t, svc, "b", "has(tx.extension) && hasPacket(tx.extension, 0x07)",
		)

		// Tx carries packet 0x42 — only A should match.
		eventsCh <- application.TransactionEvent{
			TxData: application.TxData{Txid: "for-a", Tx: buildTxBase64WithPackets(t,
				extension.UnknownPacket{PacketType: 0x42, Data: []byte{0xaa}},
			)},
		}
		select {
		case ev := <-listenerA.ch:
			require.Equal(t, "for-a", ev.GetEvent().GetTxid())
		case <-time.After(time.Second):
			t.Fatal("listener A did not receive event")
		}
		select {
		case ev := <-listenerB.ch:
			t.Fatalf("listener B unexpectedly received: %s", ev.GetEvent().GetTxid())
		case <-time.After(150 * time.Millisecond):
		}
	})

	t.Run("listenToTxEvents parses hex-encoded raw tx as fallback", func(t *testing.T) {
		t.Parallel()
		// Sweep txs go on the wire as hex-encoded raw txs (not PSBTs). Confirm
		// the parser falls back from PSBT parse failure to hex decoding so
		// tx filters still match sweep events.
		eventsCh := make(chan application.TransactionEvent, 1)
		t.Cleanup(func() { close(eventsCh) })
		svc := newTestIndexerServiceWithEvents(eventsCh)
		go svc.listenToTxEvents()

		listener := newListener[*arkv1.GetSubscriptionResponse]("sub-hex", nil)
		svc.scriptSubsHandler.pushListener(listener)
		seedTxFilters(t, svc, "sub-hex", hasExtension)

		eventsCh <- application.TransactionEvent{
			TxData: application.TxData{
				Txid: "hex-sweep",
				Tx: buildTxHexWithPackets(t, extension.UnknownPacket{
					PacketType: 0x42, Data: []byte{0x01},
				}),
			},
		}
		select {
		case ev := <-listener.ch:
			require.Equal(t, "hex-sweep", ev.GetEvent().GetTxid())
		case <-time.After(time.Second):
			t.Fatal("listener did not receive event for hex-encoded tx")
		}
	})

	t.Run("not-found maps to gRPC NotFound via sentinel error", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		_, err := svc.UpdateSubscription(context.Background(),
			&arkv1.UpdateSubscriptionRequest{
				SubscriptionId: "missing",
				Filter:         txExpressionsFilter(hasExtension),
			},
		)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("UnsubscribeForScripts keeps listener with tx filters", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse](
			"sub-keep", []string{testScript1},
		)
		svc.scriptSubsHandler.pushListener(listener)
		seedTxFilters(t, svc, "sub-keep", hasExtension)

		_, err := svc.UnsubscribeForScripts(context.Background(),
			&arkv1.UnsubscribeForScriptsRequest{SubscriptionId: "sub-keep"},
		)
		require.NoError(t, err)

		// Scripts are cleared but the listener and its tx filters survive.
		require.Empty(t, svc.scriptSubsHandler.getTopics("sub-keep"))
		require.ElementsMatch(
			t, []string{hasExtension}, svc.scriptSubsHandler.getTxFilters("sub-keep"),
		)
		_, err = svc.scriptSubsHandler.getListenerChannel("sub-keep")
		require.NoError(t, err)
	})

	t.Run("UnsubscribeForScripts removes listener without tx filters", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()
		listener := newListener[*arkv1.GetSubscriptionResponse](
			"sub-drop", []string{testScript1},
		)
		svc.scriptSubsHandler.pushListener(listener)

		_, err := svc.UnsubscribeForScripts(context.Background(),
			&arkv1.UnsubscribeForScriptsRequest{SubscriptionId: "sub-drop"},
		)
		require.NoError(t, err)

		_, err = svc.scriptSubsHandler.getListenerChannel("sub-drop")
		require.ErrorIs(t, err, ErrSubscriptionNotFound)
	})

	t.Run("UnsubscribeForScripts unknown subscription returns NotFound", func(t *testing.T) {
		t.Parallel()
		svc := newTestIndexerService()

		// Empty scripts path goes through removeAllTopics.
		_, err := svc.UnsubscribeForScripts(context.Background(),
			&arkv1.UnsubscribeForScriptsRequest{SubscriptionId: "missing"},
		)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.NotFound, st.Code())

		// Non-empty scripts path goes through removeTopics.
		_, err = svc.UnsubscribeForScripts(context.Background(),
			&arkv1.UnsubscribeForScriptsRequest{
				SubscriptionId: "missing",
				Scripts:        []string{testScript1},
			},
		)
		require.Error(t, err)
		st, ok = status.FromError(err)
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
