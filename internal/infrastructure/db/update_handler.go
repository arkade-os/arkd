package db

import (
	"sync"

	"github.com/arkade-os/arkd/internal/core/domain"
)

type eventHandler[T domain.Round | domain.OffchainTx] struct {
	lock    *sync.RWMutex
	handler func(data T)
}

func newEventHandler[T domain.Round | domain.OffchainTx]() *eventHandler[T] {
	return &eventHandler[T]{lock: &sync.RWMutex{}}
}

func (u *eventHandler[T]) set(handler func(data T)) {
	u.lock.Lock()
	defer u.lock.Unlock()
	if u.handler != nil {
		return
	}
	u.handler = handler
}

func (u *eventHandler[T]) dispatch(data T) {
	u.lock.RLock()
	defer u.lock.RUnlock()
	if u.handler == nil {
		return
	}
	u.handler(data)
}

type updateHandler[T domain.Settings] struct {
	lock    *sync.RWMutex
	handler func(data T, changelog []string)
}

func newUpdateHandler[T domain.Settings]() *updateHandler[T] {
	return &updateHandler[T]{lock: &sync.RWMutex{}}
}

func (u *updateHandler[T]) set(handler func(data T, changelog []string)) {
	u.lock.Lock()
	defer u.lock.Unlock()
	if u.handler != nil {
		return
	}
	u.handler = handler
}

func (u *updateHandler[T]) dispatch(data T, changelog []string) {
	u.lock.RLock()
	defer u.lock.RUnlock()
	if u.handler == nil {
		return
	}
	u.handler(data, changelog)
}
