package utils

import (
	"sync"
)

type Broadcaster[T any] struct {
	mu        *sync.RWMutex
	listeners map[chan T]struct{}
	closed    bool
}

func NewBroadcaster[T any]() *Broadcaster[T] {
	return &Broadcaster[T]{
		mu:        &sync.RWMutex{},
		listeners: make(map[chan T]struct{}),
	}
}

func (l *Broadcaster[T]) Subscribe(buf int) <-chan T {
	if buf == 0 {
		buf = 64
	}
	ch := make(chan T, buf)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		close(ch)
		return ch
	}
	l.listeners[ch] = struct{}{}
	return ch
}

func (l *Broadcaster[T]) Unsubscribe(ch <-chan T) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for c := range l.listeners {
		if (<-chan T)(c) == ch {
			delete(l.listeners, c)
			close(c)
			break
		}
	}
}

func (l *Broadcaster[T]) Publish(v T) int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	listenersToRemove := make([]chan T, 0)
	for ch := range l.listeners {
		select {
		case ch <- v:
		default:
			listenersToRemove = append(listenersToRemove, ch)
		}
	}

	if len(listenersToRemove) > 0 {
		go func() {
			l.remove(listenersToRemove)
		}()
	}
	return len(listenersToRemove)
}

func (l *Broadcaster[T]) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	for ch := range l.listeners {
		close(ch)
	}
	l.listeners = nil
	l.closed = true
}

func (l *Broadcaster[T]) remove(chs []chan T) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ch := range chs {
		if _, ok := l.listeners[ch]; !ok {
			continue
		}
		close(ch)
		delete(l.listeners, ch)
	}
}
