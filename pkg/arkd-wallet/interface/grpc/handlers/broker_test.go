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
		listener := newListener[string]("test-id")

		require.NotNil(t, listener)
		require.Equal(t, "test-id", listener.id)
		require.NotNil(t, listener.ch)
	})

	t.Run("pushListener", func(t *testing.T) {
		broker := newBroker[string]()
		listener := newListener[string]("test-id")

		broker.pushListener(listener)

		listeners := broker.getListenersCopy()
		require.Len(t, listeners, 1)
		require.Equal(t, listener, listeners["test-id"])
	})

	t.Run("removeListener", func(t *testing.T) {
		broker := newBroker[string]()
		listener := newListener[string]("test-id")
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
		listener := newListener[string]("test-id")
		broker.pushListener(listener)

		ch, err := broker.getListenerChannel("test-id")
		require.NoError(t, err)
		require.Equal(t, listener.ch, ch)

		ch, err = broker.getListenerChannel("non-existent")
		require.Error(t, err)
		require.Nil(t, ch)
		require.ErrorContains(t, err, "subscription non-existent not found")
	})

	t.Run("getListenersCopy", func(t *testing.T) {
		broker := newBroker[string]()

		copy := broker.getListenersCopy()
		require.Empty(t, copy)

		listener1 := newListener[string]("id1")
		listener2 := newListener[string]("id2")

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

	t.Run("send message to channel", func(t *testing.T) {
		broker := newBroker[string]()
		listener := newListener[string]("test-id")
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
					listener := newListener[string](listnerId)
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
