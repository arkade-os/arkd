package application

import (
	"context"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
)

// batchProjectionTimeout bounds the wait for a finished batch's projection, so
// one that never arrives delays the next batch rather than stopping the loop.
// A var so a test driving startRound does not wait it out.
var batchProjectionTimeout = 30 * time.Second

// batchSessionManager tracks the batches this process finished, and whether the
// projection of each has been written.
//
// The event store dispatches the projection handler in its own goroutine, so
// saving a batch's events returns before its rows land. The db service calls
// the batch update handler only once those writes have returned, which is what
// markProjected records.
type batchSessionManager struct {
	// registrations is held for the whole of a registration, and taken
	// exclusively while a finished batch's claims are released. A registration
	// in flight holds the release back, so its inputs are still claimed when it
	// pushes; one that starts after the release reads a projection that has
	// already landed. Between them there is no moment where an input a batch
	// settled is refused by neither.
	registrations sync.RWMutex

	lock sync.Mutex
	// inflightBatches maps a finished batch's id to whether its projection has
	// been written. Absent means this process is not waiting on that batch.
	inflightBatches map[string]bool
	updated         chan struct{}
}

// beginRegistration marks a registration as in flight, and endRegistration
// marks it done. They bracket everything from the first read of an input to the
// push that claims it.
func (m *batchSessionManager) beginRegistration() {
	m.registrations.RLock()
}

func (m *batchSessionManager) endRegistration() {
	m.registrations.RUnlock()
}

// holdRegistrations waits for the registrations in flight and keeps new ones out
// until resumeRegistrations. The claims of a finished batch are released in
// between, which is the one moment a registration must not run through.
func (m *batchSessionManager) holdRegistrations() {
	m.registrations.Lock()
}

func (m *batchSessionManager) resumeRegistrations() {
	m.registrations.Unlock()
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

// waitForProjections blocks until every tracked batch's projection has been
// written and returns the batches for which the cache can be cleared. It gives up on
// the timeout or on ctx, so neither the round loop nor shutdown is held up, and
// returns what did project by then: a batch still missing its projection stays
// tracked, without holding back the batches around it.
// Returns nil early if no batches are inflight.
func (m *batchSessionManager) waitForProjections(
	ctx context.Context, timeout time.Duration,
) []string {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	m.lock.Lock()
	if len(m.inflightBatches) == 0 {
		m.lock.Unlock()
		return nil
	}
	m.lock.Unlock()

	projected := make([]string, 0)
	for {
		m.lock.Lock()
		done, pending := m.forgetProjected()
		updated := m.updated
		m.lock.Unlock()

		projected = append(projected, done...)
		if !pending {
			return projected
		}

		select {
		case <-updated:
		case <-timer.C:
			return projected
		case <-ctx.Done():
			return projected
		}
	}
}

// forgetProjected stops tracking the projected batches, returns them, and
// reports whether any is still missing its projection. The caller holds the
// lock.
func (m *batchSessionManager) forgetProjected() ([]string, bool) {
	pending := false
	done := make([]string, 0, len(m.inflightBatches))
	for batchId, projected := range m.inflightBatches {
		if projected {
			done = append(done, batchId)
			delete(m.inflightBatches, batchId)
			continue
		}
		pending = true
	}
	return done, pending
}
