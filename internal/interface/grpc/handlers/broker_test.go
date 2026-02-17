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

	t.Run("removeListener closes done channel", func(t *testing.T) {
		broker := newBroker[string]()
		l := newListener[string]("test-id", []string{"topic1"})
		broker.pushListener(l)

		// done must not be closed yet
		select {
		case <-l.done:
			require.Fail(t, "done closed before removeListener")
		default:
		}

		broker.removeListener("test-id")

		// done must be closed after removal
		select {
		case <-l.done:
		default:
			require.Fail(t, "done not closed after removeListener")
		}
	})

	t.Run("closeDone is idempotent", func(t *testing.T) {
		l := newListener[string]("test-id", []string{"topic1"})
		require.NotPanics(t, func() {
			l.closeDone()
			l.closeDone()
			l.closeDone()
		})
	})

	t.Run("send after remove does not panic or block", func(t *testing.T) {
		// Reproduces the core race: fanout gets a listener copy, then
		// the listener is removed (closing done), then the fanout
		// attempts to send. The done guard (plus non-blocking default)
		// ensures the send never panics or blocks. If the buffered
		// channel has space, Go's select may pick either the done or
		// send case — both are safe; a stale message in the buffer is
		// harmless and gets GC'd with the channel.
		broker := newBroker[string]()
		l := newListener[string]("test-id", []string{"topic1"})
		broker.pushListener(l)

		// Simulate fanout: grab a snapshot reference
		snap := broker.getListenersCopy()
		ref := snap["test-id"]

		// Client disconnects — listener removed, done closed
		broker.removeListener("test-id")

		// Fanout goroutine tries to send using the done guard —
		// must complete without panic or blocking.
		done := make(chan struct{})
		require.NotPanics(t, func() {
			go func() {
				defer close(done)
				select {
				case <-ref.done:
				case ref.ch <- "msg":
				default:
				}
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				require.Fail(t, "send blocked after removal")
			}
		})
	})

	t.Run("non-blocking send drops message when channel is full", func(t *testing.T) {
		l := newListener[string]("test-id", []string{"topic1"})

		// Fill the buffered channel to capacity
		for range cap(l.ch) {
			l.ch <- "fill"
		}

		// Simulate the non-blocking fanout send pattern (with default clause).
		// Must not block — the message is silently dropped.
		sent := false
		require.NotPanics(t, func() {
			select {
			case <-l.done:
			case l.ch <- "overflow":
				sent = true
			default:
				// dropped — expected when channel is full
			}
		})
		require.False(t, sent, "message should have been dropped, not sent")
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

	t.Run("overwriteTopics", func(t *testing.T) {
		broker := newBroker[string]()
		topics := []string{"topic1", "topic2", "topic3"}
		listener := newListener[string]("test-id", topics)
		broker.pushListener(listener)

		err := broker.overwriteTopics("test-id", []string{"topic4", "topic5"})
		require.NoError(t, err)

		result := broker.getTopics("test-id")
		require.Len(t, result, 2)
		require.Contains(t, result, "topic4")
		require.Contains(t, result, "topic5")
		require.NotContains(t, result, "topic1")
		require.NotContains(t, result, "topic2")
		require.NotContains(t, result, "topic3")

		err = broker.overwriteTopics("test-id", []string{})
		require.NoError(t, err)
		result = broker.getTopics("test-id")
		require.Len(t, result, 0)
		require.NotContains(t, result, "topic1")
		require.NotContains(t, result, "topic2")
		require.NotContains(t, result, "topic3")
		require.NotContains(t, result, "topic4")
		require.NotContains(t, result, "topic5")

		err = broker.overwriteTopics("non-existent", []string{"topic4", "topic5"})
		require.Error(t, err)
		require.ErrorContains(t, err, "subscription non-existent not found")
	})

	t.Run("concurrent topic modifications", func(t *testing.T) {
		broker := newBroker[string]()
		listenerId := "concurrent-test-id"
		listener := newListener[string](listenerId, []string{})
		broker.pushListener(listener)

		topics := []string{"t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10"}

		const goroutines = 50
		const iterations = 100

		var wg sync.WaitGroup
		wg.Add(goroutines)
		// do a mix of add, remove, overwrite operations concurrently
		for g := 0; g < goroutines; g++ {
			go func(id int) {
				defer wg.Done()
				for i := 0; i < iterations; i++ {
					switch (id + i) % 3 {
					case 0:
						_ = broker.addTopics(listenerId, []string{topics[(id+i)%len(topics)]})
					case 1:
						_ = broker.removeTopics(listenerId, []string{topics[(id+i)%len(topics)]})
					case 2:
						_ = broker.overwriteTopics(listenerId, []string{topics[(id+i)%len(topics)]})
					}
					// also exercise read path
					_ = broker.getTopics(listenerId)
				}
			}(g)
		}
		wg.Wait()

		// check all returned topics must be from the expected set
		final := broker.getTopics(listenerId)
		require.NotNil(t, final)
		allowed := make(map[string]struct{}, len(topics))
		for _, t := range topics {
			allowed[formatTopic(t)] = struct{}{}
		}
		for _, ft := range final {
			_, ok := allowed[ft]
			require.True(t, ok, "unexpected topic: %s", ft)
		}
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
