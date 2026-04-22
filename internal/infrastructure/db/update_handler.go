package db

import (
	"sync"

	"github.com/arkade-os/arkd/internal/core/domain"
)

type updateHandler[T domain.Round | domain.OffchainTx] struct {
	lock    *sync.RWMutex
	handler func(data T)
}

func newUpdateHandler[T domain.Round | domain.OffchainTx]() *updateHandler[T] {
	return &updateHandler[T]{lock: &sync.RWMutex{}}
}

func (u *updateHandler[T]) set(handler func(data T)) {
	u.lock.Lock()
	defer u.lock.Unlock()
	if u.handler != nil {
		return
	}
	u.handler = handler
}

func (u *updateHandler[T]) dispatch(data T) {
	u.lock.RLock()
	defer u.lock.RUnlock()
	if u.handler == nil {
		return
	}
	go u.handler(data)
}
