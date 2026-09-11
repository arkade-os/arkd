package application

import (
	"context"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
)

// batchProjectionTimeout bounds the wait for a finished batch's projection, so
// one that never arrives delays the next batch rather than stopping the loop.
const batchProjectionTimeout = 30 * time.Second

// batchSessionManager tracks the batches this process finished, and whether the
// projection of each has been written.
//
// The event store dispatches the projection handler in its own goroutine, so
// saving a batch's events returns before its rows land. The db service calls
// the batch update handler only once those writes have returned, which is what
// markProjected records.
type batchSessionManager struct {
	lock sync.Mutex
	// inflightBatches maps a finished batch's id to whether its projection has
	// been written. Absent means this process is not waiting on that batch.
	inflightBatches map[string]bool
	updated         chan struct{}
}

func newBatchSessionManager() *batchSessionManager {
	return &batchSessionManager{
		inflightBatches: make(map[string]bool),
		updated:         make(chan struct{}),
	}
}

// track records that the batch's events have been saved, so its projection is
// on its way. A batch that did not end writes no vtxo rows and never projects,
// so nothing is tracked for it. Only a batch this process finished is waited
// on: after a restart the cache still holds the previous process's batch,
// projected before this one started.
func (m *batchSessionManager) track(round *domain.Round) {
	if round == nil || !round.IsEnded() {
		return
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	if _, tracked := m.inflightBatches[round.Id]; !tracked {
		m.inflightBatches[round.Id] = false
	}
}

// markProjected records that the batch's projection has been written, and wakes
// whoever is waiting for it. A batch nothing is waiting on is ignored, so a
// sweep projecting one that finished long ago adds nothing to the map.
func (m *batchSessionManager) markProjected(batchId string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	projected, tracked := m.inflightBatches[batchId]
	if !tracked || projected {
		return
	}

	m.inflightBatches[batchId] = true
	close(m.updated)
	m.updated = make(chan struct{})
}

// waitForProjection blocks until the batch's projection has been written and
// reports whether it was. One already projected, or never tracked, returns at
// once. It gives up on the timeout or on ctx, so neither the round loop nor
// shutdown is held up. The batch stops being tracked however this ends, since
// the wait is the only thing that cares about it.
func (m *batchSessionManager) waitForProjection(
	ctx context.Context, batchId string, timeout time.Duration,
) bool {
	defer m.forget(batchId)

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		m.lock.Lock()
		projected, tracked := m.inflightBatches[batchId]
		updated := m.updated
		m.lock.Unlock()

		if projected || !tracked {
			return true
		}

		select {
		case <-updated:
		case <-timer.C:
			return false
		case <-ctx.Done():
			return false
		}
	}
}

func (m *batchSessionManager) forget(batchId string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	delete(m.inflightBatches, batchId)
}
