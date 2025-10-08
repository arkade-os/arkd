package wallet

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/wire"
)

type outpointLocker struct {
	lockExpiry      time.Duration
	lockedOutpoints map[wire.OutPoint]time.Time
	locker          sync.Mutex
}

func newOutpointLocker(lockFor time.Duration) *outpointLocker {
	return &outpointLocker{
		lockExpiry:      lockFor,
		lockedOutpoints: make(map[wire.OutPoint]time.Time),
		locker:          sync.Mutex{},
	}
}

func (l *outpointLocker) lock(ctx context.Context, outpoints ...wire.OutPoint) error {
	if len(outpoints) == 0 {
		return nil
	}

	lockedOutpoints, err := l.get(ctx)
	if err != nil {
		return err
	}

	l.locker.Lock()
	defer l.locker.Unlock()

	now := time.Now()
	lockedUntil := now.Add(l.lockExpiry)

	for _, outpoint := range outpoints {
		if _, isLocked := lockedOutpoints[outpoint]; isLocked {
			return fmt.Errorf("outpoint %s is already locked", outpoint)
		}
	}

	for _, outpoint := range outpoints {
		l.lockedOutpoints[outpoint] = lockedUntil
	}

	return nil
}

func (l *outpointLocker) get(_ context.Context) (map[wire.OutPoint]struct{}, error) {
	l.locker.Lock()
	defer l.locker.Unlock()

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
