package handlers

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type listener[T any] struct {
	id            string
	topics        map[string]struct{}
	ch            chan T
	stopTimeoutCh chan struct{}
}

func newListener[T any](id string, topics []string) *listener[T] {
	topicsMap := make(map[string]struct{})
	for _, topic := range topics {
		topicsMap[formatTopic(topic)] = struct{}{}
	}
	return &listener[T]{
		id:            id,
		topics:        topicsMap,
		ch:            make(chan T, 1000),
		stopTimeoutCh: make(chan struct{}),
	}
}

func (l *listener[T]) includesAny(topics []string) bool {
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
	lock      *sync.Mutex
	listeners map[string]*listener[T]
}

func newBroker[T any]() *broker[T] {
	return &broker[T]{
		lock:      &sync.Mutex{},
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
	if listener.stopTimeoutCh != nil {
		close(listener.stopTimeoutCh)
	}
	delete(h.listeners, id)
}

func (h *broker[T]) getListenerChannel(id string) (chan T, error) {
	h.lock.Lock()
	defer h.lock.Unlock()

	listener, ok := h.listeners[id]
	if !ok {
		return nil, fmt.Errorf("subscription %s not found", id)
	}
	return listener.ch, nil
}

func (h *broker[T]) getTopics(id string) []string {
	h.lock.Lock()
	defer h.lock.Unlock()

	listener, ok := h.listeners[id]
	if !ok {
		return nil
	}

	topics := make([]string, 0, len(listener.topics))
	for topic := range listener.topics {
		topics = append(topics, topic)
	}
	return topics
}

func (h *broker[T]) addTopics(id string, topics []string) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	if _, ok := h.listeners[id]; !ok {
		return fmt.Errorf("subscription %s not found", id)
	}

	for _, topic := range topics {
		h.listeners[id].topics[formatTopic(topic)] = struct{}{}
	}
	return nil
}

func (h *broker[T]) removeTopics(id string, topics []string) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	if _, ok := h.listeners[id]; !ok {
		return fmt.Errorf("subscription %s not found", id)
	}

	for _, topic := range topics {
		delete(h.listeners[id].topics, formatTopic(topic))
	}
	return nil
}

func (h *broker[T]) removeAllTopics(id string) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	if _, ok := h.listeners[id]; !ok {
		return fmt.Errorf("subscription %s not found", id)
	}

	h.listeners[id].topics = make(map[string]struct{})
	return nil
}

func (h *broker[T]) startTimeout(id string, timeout time.Duration) {
	h.lock.Lock()
	defer h.lock.Unlock()

	if _, ok := h.listeners[id]; !ok {
		return
	}

	h.listeners[id].stopTimeoutCh = make(chan struct{})

	go func() {
		select {
		case <-h.listeners[id].stopTimeoutCh:
			return
		case <-time.After(timeout):
			h.removeListener(id)
		}
	}()
}

func (h *broker[T]) stopTimeout(id string) {
	h.lock.Lock()
	defer h.lock.Unlock()

	if _, ok := h.listeners[id]; !ok {
		return
	}

	h.listeners[id].stopTimeoutCh <- struct{}{}
	close(h.listeners[id].stopTimeoutCh)
	h.listeners[id].stopTimeoutCh = nil
}

func formatTopic(topic string) string {
	return strings.Trim(strings.ToLower(topic), " ")
}
