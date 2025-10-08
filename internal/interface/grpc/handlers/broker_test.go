package handlers

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBroker(t *testing.T) {
	t.Parallel()

	t.Run("newBroker", func(t *testing.T) {
		broker := newBroker[string]()
		require.NotNil(t, broker)
		require.NotNil(t, broker.lock)
		require.NotNil(t, broker.listeners)
		require.Empty(t, broker.listeners)
	})

	t.Run("newListener", func(t *testing.T) {
		topics := []string{"topic1", "topic2", "TOPIC3"}
		listener := newListener[string]("test-id", topics)

		require.NotNil(t, listener)
		require.Equal(t, "test-id", listener.id)
		require.NotNil(t, listener.ch)
		require.NotNil(t, listener.topics)
		require.Len(t, listener.topics, 3)

		// check topics are formatted correctly
		require.Contains(t, listener.topics, "topic1")
		require.Contains(t, listener.topics, "topic2")
		require.Contains(t, listener.topics, "topic3") // should be lowercase
	})

	t.Run("includesAny", func(t *testing.T) {
		topics := []string{"topic1", "topic2"}
		listener := newListener[string]("test-id", topics)

		// empty list should return true
		require.True(t, listener.includesAny([]string{}))

		// matching topic should return true
		require.True(t, listener.includesAny([]string{"topic1"}))
		require.True(t, listener.includesAny([]string{"topic2"}))
		require.True(t, listener.includesAny([]string{"TOPIC1"})) // case insensitive

		// non-matching topic should return false
		require.False(t, listener.includesAny([]string{"topic3"}))
		require.False(t, listener.includesAny([]string{"other"}))
	})

	t.Run("pushListener", func(t *testing.T) {
		broker := newBroker[string]()
		listener := newListener[string]("test-id", []string{"topic1"})

		broker.pushListener(listener)

		listeners := broker.getListenersCopy()
		require.Len(t, listeners, 1)
		require.Equal(t, listener, listeners["test-id"])
	})

	t.Run("removeListener", func(t *testing.T) {
		broker := newBroker[string]()
		listener := newListener[string]("test-id", []string{"topic1"})
		broker.pushListener(listener)

		listeners := broker.getListenersCopy()
		require.Len(t, listeners, 1)
		require.Equal(t, listener, listeners["test-id"])

		broker.removeListener("test-id")

		listeners = broker.getListenersCopy()
		require.Empty(t, listeners)

		require.NotPanics(t, func() {
			broker.removeListener("non-existent")
		})
	})

	t.Run("getListenerChannel", func(t *testing.T) {
		broker := newBroker[string]()
		listener := newListener[string]("test-id", []string{"topic1"})
		broker.pushListener(listener)

		ch, err := broker.getListenerChannel("test-id")
		require.NoError(t, err)
		require.Equal(t, listener.ch, ch)

		ch, err = broker.getListenerChannel("non-existent")
		require.Error(t, err)
		require.Nil(t, ch)
		require.ErrorContains(t, err, "subscription non-existent not found")
	})

	t.Run("getTopics", func(t *testing.T) {
		broker := newBroker[string]()
		topics := []string{"topic1", "topic2", "TOPIC3"}
		listener := newListener[string]("test-id", topics)
		broker.pushListener(listener)

		result := broker.getTopics("test-id")
		require.Len(t, result, 3)
		require.Contains(t, result, "topic1")
		require.Contains(t, result, "topic2")
		require.Contains(t, result, "topic3") // should be lowercase, topic has been formatted

		require.Nil(t, broker.getTopics("non-existent"))
	})

	t.Run("addTopics", func(t *testing.T) {
		broker := newBroker[string]()
		listener := newListener[string]("test-id", []string{"topic1"})
		broker.pushListener(listener)

		newTopics := []string{"topic2", "TOPIC3", "topic1"}
		err := broker.addTopics("test-id", newTopics)
		require.NoError(t, err)

		// add to an existing listener
		topics := broker.getTopics("test-id")
		require.Len(t, topics, 3)
		require.Contains(t, topics, "topic1")
		require.Contains(t, topics, "topic2")
		require.Contains(t, topics, "topic3")

		// add to a non-existent listener
		err = broker.addTopics("non-existent", []string{"topic1"})
		require.Error(t, err)
		require.ErrorContains(t, err, "subscription non-existent not found")
	})

	t.Run("removeTopics", func(t *testing.T) {
		broker := newBroker[string]()
		topics := []string{"topic1", "topic2", "topic3"}
		listener := newListener[string]("test-id", topics)
		broker.pushListener(listener)

		topicsToRemove := []string{"topic2", "TOPIC3", "topic-not-exists"}
		err := broker.removeTopics("test-id", topicsToRemove)
		require.NoError(t, err)

		result := broker.getTopics("test-id")
		require.Len(t, result, 1)
		require.Contains(t, result, "topic1")
		require.NotContains(t, result, "topic2")
		require.NotContains(t, result, "topic3")

		err = broker.removeTopics("non-existent", []string{"topic1"})
		require.Error(t, err)
		require.ErrorContains(t, err, "subscription non-existent not found")
	})

	t.Run("removeAllTopics", func(t *testing.T) {
		broker := newBroker[string]()
		topics := []string{"topic1", "topic2", "topic3"}
		listener := newListener[string]("test-id", topics)
		broker.pushListener(listener)

		err := broker.removeAllTopics("test-id")
		require.NoError(t, err)

		result := broker.getTopics("test-id")
		require.Empty(t, result)

		err = broker.removeAllTopics("non-existent")
		require.Error(t, err)
		require.ErrorContains(t, err, "subscription non-existent not found")
	})

	t.Run("timeout management", func(t *testing.T) {
		t.Run("startTimeout", func(t *testing.T) {
			broker := newBroker[string]()
			listener := newListener[string]("test-id", []string{"topic1"})
			broker.pushListener(listener)
			broker.startTimeout("test-id", 100*time.Millisecond)

			// wait for timeout to trigger, check if listener is removed
			time.Sleep(150 * time.Millisecond)
			listeners := broker.getListenersCopy()
			require.Len(t, listeners, 0)
		})

		t.Run("stopTimeout", func(t *testing.T) {
			broker := newBroker[string]()
			listener := newListener[string]("test-id", []string{"topic1"})
			broker.pushListener(listener)

			broker.startTimeout("test-id", 100*time.Millisecond)
			broker.stopTimeout("test-id")

			// wait to ensure timeout doesn't trigger
			time.Sleep(150 * time.Millisecond)
			listeners := broker.getListenersCopy()
			require.Len(t, listeners, 1) // should still exist
		})

		t.Run("concurrent timeout with several listeners", func(t *testing.T) {
			const nbListeners = 10
			broker := newBroker[string]()

			var wg sync.WaitGroup

			// start timeouts for all listeners concurrently
			wg.Add(nbListeners)
			for i := range nbListeners {
				go func(id int) {
					listener := newListener[string](
						fmt.Sprintf("listener-%d", i),
						[]string{"topic1"},
					)
					broker.pushListener(listener)
					defer wg.Done()
					broker.startTimeout(fmt.Sprintf("listener-%d", i), 50*time.Millisecond)
				}(i)
			}
			wg.Wait()

			// wait for all timeouts to trigger
			time.Sleep(100 * time.Millisecond)

			// all listeners should be removed
			listeners := broker.getListenersCopy()
			require.Len(t, listeners, 0)
		})
	})

	t.Run("getListenersCopy", func(t *testing.T) {
		broker := newBroker[string]()

		copy := broker.getListenersCopy()
		require.Empty(t, copy)

		listener1 := newListener[string]("id1", []string{"topic1"})
		listener2 := newListener[string]("id2", []string{"topic2"})

		broker.pushListener(listener1)
		broker.pushListener(listener2)

		copy = broker.getListenersCopy()
		require.Len(t, copy, 2)
		require.Equal(t, listener1, copy["id1"])
		require.Equal(t, listener2, copy["id2"])

		// Modifying copy should not affect original
		delete(copy, "id1")
		listeners := broker.getListenersCopy()
		require.Len(t, listeners, 2)
		require.Equal(t, listener1, listeners["id1"])
		require.Equal(t, listener2, listeners["id2"])
	})

	t.Run("hasListeners", func(t *testing.T) {
		broker := newBroker[string]()
		require.False(t, broker.hasListeners())
		listener := newListener[string]("test-id", []string{"topic1"})
		broker.pushListener(listener)
		require.True(t, broker.hasListeners())
	})

	t.Run("formatTopic", func(t *testing.T) {
		require.Equal(t, "topic", formatTopic("TOPIC"))
		require.Equal(t, "topic", formatTopic(" Topic "))
		require.Equal(t, "topic", formatTopic("  TOPIC  "))
		require.Equal(t, "my topic", formatTopic("  My Topic  "))

		require.Equal(t, "", formatTopic(""))
		require.Equal(t, "", formatTopic("   "))
		require.Equal(t, "a", formatTopic("A"))
	})

	t.Run("send message to channel", func(t *testing.T) {
		broker := newBroker[string]()
		listener := newListener[string]("test-id", []string{"topic1"})
		broker.pushListener(listener)

		ch, err := broker.getListenerChannel("test-id")
		require.NoError(t, err)

		// test sending to channel
		go func() {
			ch <- "test message"
		}()

		select {
		case msg := <-ch:
			require.Equal(t, "test message", msg)
		case <-time.After(100 * time.Millisecond):
			require.Fail(t, "timeout waiting for message")
		}
	})

	t.Run("concurrent operations", func(t *testing.T) {
		const nbListeners = 20
		broker := newBroker[string]()
		var wg sync.WaitGroup
		wg.Add(nbListeners * 2)

		ch := make(chan string, nbListeners)

		// add listeners concurrently
		go func() {
			for i := range nbListeners {
				go func(id int) {
					defer wg.Done()
					listnerId := fmt.Sprintf("id-%d", id)
					listener := newListener[string](listnerId, []string{"topic1"})
					broker.pushListener(listener)
					ch <- listnerId
				}(i)
			}
		}()

		// remove listeners concurrently
		go func() {
			for i := range nbListeners {
				go func(id int) {
					defer wg.Done()
					listenerId := <-ch
					broker.removeListener(listenerId)
				}(i)
			}
		}()

		wg.Wait()
		listeners := broker.getListenersCopy()
		require.Empty(t, listeners)
	})
}
