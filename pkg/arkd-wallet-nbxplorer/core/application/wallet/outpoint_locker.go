package wallet

import (
	"context"
	"sync"
	"time"

	"github.com/btcsuite/btcd/wire"
)

// outpointLocker defines local utility service letting to lock outpoints for a given duration
type outpointLocker interface {
	Lock(ctx context.Context, outpoints ...wire.OutPoint) error
	Get(ctx context.Context) (map[wire.OutPoint]struct{}, error)
}

type inmemoryOutpointLocker struct {
	lockFor         time.Duration
	lockedOutpoints map[wire.OutPoint]time.Time
	mu              sync.Mutex
}

func newInmemoryOutpointLocker(lockFor time.Duration) outpointLocker {
	return &inmemoryOutpointLocker{
		lockFor:         lockFor,
		lockedOutpoints: make(map[wire.OutPoint]time.Time),
		mu:              sync.Mutex{},
	}
}

func (l *inmemoryOutpointLocker) Lock(ctx context.Context, outpoints ...wire.OutPoint) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	lockedUntil := now.Add(l.lockFor)

	for _, outpoint := range outpoints {
		l.lockedOutpoints[outpoint] = lockedUntil
	}

	return nil
}

func (l *inmemoryOutpointLocker) Get(ctx context.Context) (map[wire.OutPoint]struct{}, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	lockedOutpoints := make(map[wire.OutPoint]struct{})
	for outpoint, lockedUntil := range l.lockedOutpoints {
		if time.Now().After(lockedUntil) {
			delete(l.lockedOutpoints, outpoint)
			continue
		}

		lockedOutpoints[outpoint] = struct{}{}
	}

	return lockedOutpoints, nil
}
