package handlers

import (
	"errors"
	"fmt"
	"testing"

	arkdErrors "github.com/arkade-os/arkd/pkg/errors"
	"github.com/stretchr/testify/require"
)

func makeTopics(n int) []string {
	topics := make([]string, 0, n)
	for i := range n {
		topics = append(topics, fmt.Sprintf("topic-%d", i))
	}
	return topics
}

func TestBrokerLimits(t *testing.T) {
	t.Run("pushListener rejects a listener built over the topic limit", func(t *testing.T) {
		broker := newBroker[string]()

		l := newListener[string]("over", makeTopics(MaxTopicsPerListener+1))
		err := broker.pushListener(l)
		requireCode(t, err, arkdErrors.TOPICS_LIMIT_EXCEEDED.Name)
		require.NotContains(t, broker.getListenersCopy(), "over")

		// Exactly at the limit is allowed: the cap is a maximum, not a bound.
		l = newListener[string]("at", makeTopics(MaxTopicsPerListener))
		require.NoError(t, broker.pushListener(l))
		require.Contains(t, broker.getListenersCopy(), "at")
	})

	t.Run("addTopics rejects growth past the topic limit", func(t *testing.T) {
		broker := newBroker[string]()
		require.NoError(t, broker.pushListener(
			newListener[string]("sub", makeTopics(MaxTopicsPerListener)),
		))

		err := broker.addTopics("sub", []string{"one-too-many"})
		requireCode(t, err, arkdErrors.TOPICS_LIMIT_EXCEEDED.Name)

		// The rejected add must not have partially applied.
		require.Len(t, broker.getTopics("sub"), MaxTopicsPerListener)
		require.NotContains(t, broker.getTopics("sub"), "one-too-many")
	})

	// Re-subscribing to topics already held is a no-op, so it must not be
	// refused just because current+incoming would exceed the limit.
	t.Run("addTopics counts the merged set, not the sum", func(t *testing.T) {
		broker := newBroker[string]()
		topics := makeTopics(MaxTopicsPerListener)
		require.NoError(t, broker.pushListener(newListener[string]("sub", topics)))

		require.NoError(t, broker.addTopics("sub", topics))
		require.Len(t, broker.getTopics("sub"), MaxTopicsPerListener)
	})

	t.Run("overwriteTopics rejects a set over the topic limit", func(t *testing.T) {
		broker := newBroker[string]()
		require.NoError(t, broker.pushListener(newListener[string]("sub", []string{"a"})))

		err := broker.overwriteTopics("sub", makeTopics(MaxTopicsPerListener+1))
		requireCode(t, err, arkdErrors.TOPICS_LIMIT_EXCEEDED.Name)

		// The listener keeps the set it had.
		require.Equal(t, []string{"a"}, broker.getTopics("sub"))

		require.NoError(t, broker.overwriteTopics("sub", makeTopics(MaxTopicsPerListener)))
		require.Len(t, broker.getTopics("sub"), MaxTopicsPerListener)
	})

	t.Run("removeAllTopics is never refused by the limit", func(t *testing.T) {
		broker := newBroker[string]()
		require.NoError(t, broker.pushListener(
			newListener[string]("sub", makeTopics(MaxTopicsPerListener)),
		))

		require.NoError(t, broker.removeAllTopics("sub"))
		require.Empty(t, broker.getTopics("sub"))
	})

	t.Run("pushListener rejects past the listener limit", func(t *testing.T) {
		broker := newBroker[string]()
		for i := range MaxListeners {
			require.NoError(t, broker.pushListener(
				newListener[string](fmt.Sprintf("sub-%d", i), nil),
			))
		}
		require.Len(t, broker.getListenersCopy(), MaxListeners)

		err := broker.pushListener(newListener[string]("one-too-many", nil))
		requireCode(t, err, arkdErrors.SUBSCRIPTIONS_LIMIT_EXCEEDED.Name)
		require.NotContains(t, broker.getListenersCopy(), "one-too-many")

		// Freeing a slot lets a new subscription in again.
		broker.removeListener("sub-0")
		require.NoError(t, broker.pushListener(newListener[string]("one-too-many", nil)))
	})

	// Replacing an id already registered does not grow the set, so a full
	// broker must still accept it rather than lock the holder out.
	t.Run("replacing an existing id is allowed at the listener limit", func(t *testing.T) {
		broker := newBroker[string]()
		for i := range MaxListeners {
			require.NoError(t, broker.pushListener(
				newListener[string](fmt.Sprintf("sub-%d", i), nil),
			))
		}

		replacement := newListener[string]("sub-0", []string{"fresh"})
		require.NoError(t, broker.pushListener(replacement))
		require.Len(t, broker.getListenersCopy(), MaxListeners)
		require.Equal(t, []string{"fresh"}, broker.getTopics("sub-0"))
	})

	t.Run("limit errors are distinguishable from a missing subscription", func(t *testing.T) {
		broker := newBroker[string]()

		err := broker.addTopics("nope", []string{"a"})
		requireCode(t, err, arkdErrors.SUBSCRIPTION_NOT_FOUND.Name)
	})
}

func requireCode(t *testing.T, err error, name string) {
	t.Helper()
	var arkErr arkdErrors.Error
	require.True(t, errors.As(err, &arkErr), "expected a structured error, got %T: %v", err, err)
	require.Equal(t, name, arkErr.CodeName())
}
