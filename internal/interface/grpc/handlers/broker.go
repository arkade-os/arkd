package handlers

import (
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"
)

type listener[T any] struct {
	id           string
	topics       map[string]struct{}
	ch           chan T
	timeoutTimer *time.Timer
	lock         *sync.RWMutex
}

func newListener[T any](id string, topics []string) *listener[T] {
	topicsMap := make(map[string]struct{})
	for _, topic := range topics {
		topicsMap[formatTopic(topic)] = struct{}{}
	}
	return &listener[T]{
		id:     id,
		topics: topicsMap,
		ch:     make(chan T, 100),
		lock:   &sync.RWMutex{},
	}
}

func (l *listener[T]) includesAny(topics []string) bool {
	l.lock.RLock()
	defer l.lock.RUnlock()
	if len(topics) == 0 {
		return true
	}

	for _, topic := range topics {
		formattedTopic := formatTopic(topic)
		if _, ok := l.topics[formattedTopic]; ok {
			return true
		}
	}
	return false
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

	listener, ok := h.listeners[id]
	if !ok {
		return
	}
	if listener.timeoutTimer != nil {
		listener.timeoutTimer.Stop()
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

func (h *broker[T]) getTopics(id string) []string {
	h.lock.RLock()
	defer h.lock.RUnlock()

	listener, ok := h.listeners[id]
	if !ok {
		return nil
	}
	listener.lock.Lock()
	defer listener.lock.Unlock()

	topics := make([]string, 0, len(listener.topics))
	for topic := range listener.topics {
		topics = append(topics, topic)
	}
	return topics
}

func (h *broker[T]) addTopics(id string, topics []string) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	listener, ok := h.listeners[id]
	if !ok {
		return fmt.Errorf("subscription %s not found", id)
	}

	listener.lock.Lock()
	defer listener.lock.Unlock()

	for _, topic := range topics {
		listener.topics[formatTopic(topic)] = struct{}{}
	}
	return nil
}

func (h *broker[T]) removeTopics(id string, topics []string) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	listener, ok := h.listeners[id]
	if !ok {
		return fmt.Errorf("subscription %s not found", id)
	}

	listener.lock.Lock()
	defer listener.lock.Unlock()

	for _, topic := range topics {
		delete(listener.topics, formatTopic(topic))
	}
	return nil
}

func (h *broker[T]) removeAllTopics(id string) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	listener, ok := h.listeners[id]
	if !ok {
		return fmt.Errorf("subscription %s not found", id)
	}

	listener.lock.Lock()
	defer listener.lock.Unlock()

	listener.topics = make(map[string]struct{})
	return nil
}

func (h *broker[T]) overwriteTopics(id string, topics []string) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	listener, ok := h.listeners[id]
	if !ok {
		return fmt.Errorf("subscription %s not found", id)
	}

	listener.lock.Lock()
	defer listener.lock.Unlock()

	newTopics := make(map[string]struct{}, len(topics))
	for _, topic := range topics {
		newTopics[formatTopic(topic)] = struct{}{}
	}

	listener.topics = newTopics
	return nil
}

func (h *broker[T]) startTimeout(id string, timeout time.Duration) {
	// stop any existing timeout on this listener
	h.stopTimeout(id)

	h.lock.Lock()
	defer h.lock.Unlock()
	_, ok := h.listeners[id]
	if !ok {
		return
	}

	h.listeners[id].timeoutTimer = time.AfterFunc(timeout, func() {
		h.lock.Lock()
		defer h.lock.Unlock()

		listener, ok := h.listeners[id]
		if !ok {
			return
		}
		if listener.timeoutTimer != nil {
			listener.timeoutTimer.Stop()
		}
		delete(h.listeners, id)
	})
}

func (h *broker[T]) stopTimeout(id string) {
	h.lock.Lock()
	defer h.lock.Unlock()

	if _, ok := h.listeners[id]; !ok {
		return
	}

	if h.listeners[id].timeoutTimer != nil {
		h.listeners[id].timeoutTimer.Stop()
		h.listeners[id].timeoutTimer = nil
	}
}

func (h *broker[T]) getListenersCopy() map[string]*listener[T] {
	h.lock.RLock()
	defer h.lock.RUnlock()

	listenersCopy := make(map[string]*listener[T], len(h.listeners))
	maps.Copy(listenersCopy, h.listeners)
	return listenersCopy
}

func (h *broker[T]) hasListeners() bool {
	h.lock.RLock()
	defer h.lock.RUnlock()
	return len(h.listeners) > 0
}

func formatTopic(topic string) string {
	return strings.Trim(strings.ToLower(topic), " ")
}
