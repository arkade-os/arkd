package mempool_explorer

import (
	"sync"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
	log "github.com/sirupsen/logrus"
)

type listeners struct {
	mu        *sync.RWMutex
	listeners map[chan types.OnchainAddressEvent]int
	index     int
}

func newListeners() *listeners {
	return &listeners{
		mu:        &sync.RWMutex{},
		listeners: make(map[chan types.OnchainAddressEvent]int),
		index:     0,
	}
}

func (l *listeners) add(ch chan types.OnchainAddressEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.listeners[ch] = l.index
	l.index++
}

func (l *listeners) broadcast(event types.OnchainAddressEvent) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	listenersToRemove := make([]chan types.OnchainAddressEvent, 0)
	chIds := make([]int, 0)
	for ch, id := range l.listeners {
		select {
		case ch <- event:
		default:
			listenersToRemove = append(listenersToRemove, ch)
			chIds = append(chIds, id)
		}
	}
	if len(listenersToRemove) > 0 {
		go func() {
			l.remove(listenersToRemove)
			log.WithFields(log.Fields{
				"ids":   chIds,
				"event": event,
			}).Warn("failed to send event to one or more listeners listener and they've been removed")
		}()
	}
}

func (l *listeners) clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ch := range l.listeners {
		close(ch)
	}
	l.listeners = make(map[chan types.OnchainAddressEvent]int)
}

func (l *listeners) remove(chs []chan types.OnchainAddressEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ch := range chs {
		close(ch)
		delete(l.listeners, ch)
	}
}
