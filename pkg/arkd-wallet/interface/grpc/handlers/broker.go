package handlers

import (
	"fmt"
	"maps"
	"sync"
)

type listener[T any] struct {
	id string
	ch chan T
}

func newListener[T any](id string) *listener[T] {
	return &listener[T]{
		id: id,
		ch: make(chan T, 100),
	}
}

// broker is a simple utility struct to manage subscriptions.
// it is used to send events to multiple listeners.
// it is thread safe and can be used to send events to multiple listeners.
type broker[T any] struct {
	lock      *sync.RWMutex
	listeners map[string]*listener[T]
}

func newBroker[T any]() *broker[T] {
	return &broker[T]{
		lock:      &sync.RWMutex{},
		listeners: make(map[string]*listener[T], 0),
	}
}

func (h *broker[T]) pushListener(l *listener[T]) {
	h.lock.Lock()
	defer h.lock.Unlock()

	h.listeners[l.id] = l
}

func (h *broker[T]) removeListener(id string) {
	h.lock.Lock()
	defer h.lock.Unlock()

	if _, ok := h.listeners[id]; !ok {
		return
	}
	delete(h.listeners, id)
}

func (h *broker[T]) getListenerChannel(id string) (chan T, error) {
	h.lock.RLock()
	defer h.lock.RUnlock()

	listener, ok := h.listeners[id]
	if !ok {
		return nil, fmt.Errorf("subscription %s not found", id)
	}
	return listener.ch, nil
}

func (h *broker[T]) getListenersCopy() map[string]*listener[T] {
	h.lock.RLock()
	defer h.lock.RUnlock()

	listenersCopy := make(map[string]*listener[T], len(h.listeners))
	maps.Copy(listenersCopy, h.listeners)
	return listenersCopy
}
