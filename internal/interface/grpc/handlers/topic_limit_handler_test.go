package handlers

import (
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	arkdErrors "github.com/arkade-os/arkd/pkg/errors"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// The broker's limits are only useful if a client can tell a limit breach from
// anything else. These exercise the handler layer rather than the broker,
// because both bugs they cover lived entirely in the mapping: the broker
// returned the right sentinel and the handler threw the meaning away.
func TestTopicLimitReachesTheClient(t *testing.T) {
	// parseScripts rejects anything that is not a real P2TR script before the
	// limit is ever consulted, so these must be genuine curve points.
	overLimitScripts := func(t *testing.T) []string {
		t.Helper()
		scripts := make([]string, 0, MaxTopicsPerListener+1)
		for range MaxTopicsPerListener + 1 {
			key, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			scripts = append(
				scripts, "5120"+hex.EncodeToString(schnorr.SerializePubKey(key.PubKey())),
			)
		}
		return scripts
	}

	requireTopicsLimit := func(t *testing.T, err error, wantGot int) {
		t.Helper()
		require.Error(t, err)

		var arkErr arkdErrors.Error
		require.True(
			t, stderrors.As(err, &arkErr),
			"expected a structured error, got %T: %v", err, err,
		)
		require.Equal(t, arkdErrors.TOPICS_LIMIT_EXCEEDED.Name, arkErr.CodeName())
		require.Equal(t, codes.InvalidArgument, arkErr.GrpcCode())
		require.Equal(t, strconv.Itoa(MaxTopicsPerListener), arkErr.Metadata()["max_topics"])
		require.Equal(t, strconv.Itoa(wantGot), arkErr.Metadata()["got_topics"])
	}

	// Regression: applyFilter routed addTopics through subscriptionErr, which
	// only knows about a missing subscription, so a limit breach surfaced as
	// codes.Internal.
	t.Run("UpdateSubscription over the topic limit reports the limit", func(t *testing.T) {
		svc := newTestIndexerService(t)
		svc.scriptSubsHandler.pushListener(
			newListener[*arkv1.GetSubscriptionResponse]("sub-topics", nil),
		)

		scripts := overLimitScripts(t)
		_, err := svc.UpdateSubscription(t.Context(), &arkv1.UpdateSubscriptionRequest{
			SubscriptionId: "sub-topics",
			Filter: &arkv1.SubscriptionFilter{
				Scripts: &arkv1.ScriptFilter{Add: scripts},
			},
		})

		requireTopicsLimit(t, err, len(scripts))
	})

	t.Run("SubscribeForScripts over the topic limit reports the limit", func(t *testing.T) {
		svc := newTestIndexerService(t)

		scripts := overLimitScripts(t)
		_, err := svc.SubscribeForScripts(
			t.Context(), &arkv1.SubscribeForScriptsRequest{Scripts: scripts},
		)

		requireTopicsLimit(t, err, len(scripts))
	})

	// A missing subscription must keep reporting NotFound. The fix must not
	// turn every failure into a limit error.
	t.Run("unknown subscription still reports not found", func(t *testing.T) {
		svc := newTestIndexerService(t)

		_, err := svc.UpdateSubscription(t.Context(), &arkv1.UpdateSubscriptionRequest{
			SubscriptionId: "does-not-exist",
			Filter: &arkv1.SubscriptionFilter{
				Scripts: &arkv1.ScriptFilter{Add: []string{testScript1}},
			},
		})

		require.Error(t, err)
		var arkErr arkdErrors.Error
		require.True(t, stderrors.As(err, &arkErr))
		require.Equal(t, arkdErrors.SUBSCRIPTION_NOT_FOUND.Name, arkErr.CodeName())
	})
}

// Regression: UpdateStreamTopics mapped every mutation failure to NotFound, so
// a topic limit breach was indistinguishable from an unknown stream id.
func TestUpdateStreamTopicsLimitReachesTheClient(t *testing.T) {
	overLimitTopics := func() []string {
		topics := make([]string, 0, MaxTopicsPerListener+1)
		for i := range MaxTopicsPerListener + 1 {
			topics = append(topics, fmt.Sprintf("topic-%d", i))
		}
		return topics
	}

	requireTopicsLimit := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err)

		var arkErr arkdErrors.Error
		require.True(
			t, stderrors.As(err, &arkErr),
			"expected a structured error, got %T: %v", err, err,
		)
		require.Equal(t, arkdErrors.TOPICS_LIMIT_EXCEEDED.Name, arkErr.CodeName())
		require.Equal(t, codes.InvalidArgument, arkErr.GrpcCode())
	}

	newStream := func(t *testing.T, id string) *handler {
		t.Helper()
		h := &handler{
			eventsListenerHandler:       newBroker[*arkv1.GetEventStreamResponse](),
			transactionsListenerHandler: newBroker[*arkv1.GetTransactionsStreamResponse](),
		}
		require.NoError(t, h.eventsListenerHandler.pushListener(
			newListener[*arkv1.GetEventStreamResponse](id, nil),
		))
		return h
	}

	t.Run("overwrite over the topic limit reports the limit", func(t *testing.T) {
		h := newStream(t, "stream-1")

		_, err := h.UpdateStreamTopics(t.Context(), &arkv1.UpdateStreamTopicsRequest{
			StreamId: "stream-1",
			TopicsChange: &arkv1.UpdateStreamTopicsRequest_Overwrite{
				Overwrite: &arkv1.OverwriteTopics{Topics: overLimitTopics()},
			},
		})

		requireTopicsLimit(t, err)
	})

	t.Run("add over the topic limit reports the limit", func(t *testing.T) {
		h := newStream(t, "stream-2")

		_, err := h.UpdateStreamTopics(t.Context(), &arkv1.UpdateStreamTopicsRequest{
			StreamId: "stream-2",
			TopicsChange: &arkv1.UpdateStreamTopicsRequest_Modify{
				Modify: &arkv1.ModifyTopics{AddTopics: overLimitTopics()},
			},
		})

		requireTopicsLimit(t, err)
	})

	t.Run("unknown stream still reports not found", func(t *testing.T) {
		h := newStream(t, "stream-3")

		_, err := h.UpdateStreamTopics(t.Context(), &arkv1.UpdateStreamTopicsRequest{
			StreamId: "no-such-stream",
			TopicsChange: &arkv1.UpdateStreamTopicsRequest_Modify{
				Modify: &arkv1.ModifyTopics{AddTopics: []string{"topic-1"}},
			},
		})

		require.Error(t, err)
		var arkErr arkdErrors.Error
		require.True(t, stderrors.As(err, &arkErr))
		require.Equal(t, arkdErrors.SUBSCRIPTION_NOT_FOUND.Name, arkErr.CodeName())
		require.Equal(t, codes.NotFound, arkErr.GrpcCode())
	})
}
