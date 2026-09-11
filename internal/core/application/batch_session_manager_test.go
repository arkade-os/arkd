package application

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/stretchr/testify/require"
)

// The projection of a finished batch is written by a handler the event store
// dispatches in its own goroutine, so startRound has to wait for it before it
// releases the batch's intent claims. These pin the two halves of that: the
// wait itself, and the handler that ends it.
func TestBatchSessionManager(t *testing.T) {
	t.Run("waitForProjection", func(t *testing.T) {
		t.Run("returns at once when the batch is already projected", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))
			m.markProjected(projectedRoundId)

			start := time.Now()
			require.True(t, m.waitForProjection(context.Background(), projectedRoundId, 5*time.Second))
			require.Less(t, time.Since(start), time.Second)
		})

		t.Run("waits until the batch is projected", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))

			waited := make(chan bool, 1)
			go func() { waited <- m.waitForProjection(context.Background(), projectedRoundId, 5*time.Second) }()
			requireBlocked(t, waited)

			m.markProjected(projectedRoundId)
			select {
			case ok := <-waited:
				require.True(t, ok)
			case <-time.After(5 * time.Second):
				require.FailNow(t, "the wait did not end when the round was projected")
			}
		})

		// Every round event projects, not just the last one, so a wait must
		// only end on the round it was asked about.
		t.Run("another batch being projected does not end the wait", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))

			waited := make(chan bool, 1)
			go func() { waited <- m.waitForProjection(context.Background(), projectedRoundId, 5*time.Second) }()

			m.track(endedRoundWithId(t, "another-round"))
			m.markProjected("another-round")
			requireBlocked(t, waited)

			m.markProjected(projectedRoundId)
			require.True(t, <-waited)
		})

		t.Run("gives up on the timeout", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))

			start := time.Now()
			require.False(
				t, m.waitForProjection(context.Background(), projectedRoundId, 100*time.Millisecond),
				"a projection that never arrives must not stall the round loop",
			)
			require.Less(t, time.Since(start), 5*time.Second)
		})

		t.Run("gives up when the context is cancelled", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))
			ctx, cancel := context.WithCancel(context.Background())

			waited := make(chan bool, 1)
			go func() { waited <- m.waitForProjection(ctx, projectedRoundId, time.Minute) }()
			requireBlocked(t, waited)

			cancel()
			select {
			case ok := <-waited:
				require.False(t, ok, "shutdown must not be held up by the wait")
			case <-time.After(5 * time.Second):
				require.FailNow(t, "the wait did not end when the context was cancelled")
			}
		})

		// The reason for a map: several batches can be in flight, and each wait
		// ends on its own batch.
		t.Run("tracks batches independently", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))
			m.track(endedRoundWithId(t, "other-batch"))

			first := make(chan bool, 1)
			go func() {
				first <- m.waitForProjection(context.Background(), projectedRoundId, 5*time.Second)
			}()
			second := make(chan bool, 1)
			go func() {
				second <- m.waitForProjection(context.Background(), "other-batch", 5*time.Second)
			}()
			requireBlocked(t, first)
			requireBlocked(t, second)

			m.markProjected("other-batch")
			require.True(t, <-second)
			requireBlocked(t, first, "the other batch's projection must not end this wait")

			m.markProjected(projectedRoundId)
			require.True(t, <-first)
		})

		// The map holds the batches in flight, so a finished wait leaves nothing
		// behind and a sweep of a batch long gone adds nothing.
		t.Run("stops tracking a batch once its wait ends", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))
			m.markProjected(projectedRoundId)
			require.True(
				t, m.waitForProjection(context.Background(), projectedRoundId, time.Second),
			)
			requireNotTracked(t, m, projectedRoundId)

			m.track(endedRound(t))
			require.False(
				t, m.waitForProjection(context.Background(), projectedRoundId, 50*time.Millisecond),
			)
			requireNotTracked(t, m, projectedRoundId, "a wait that gave up leaves nothing behind")

			m.markProjected(projectedRoundId)
			requireNotTracked(t, m, projectedRoundId, "a batch nothing waits on is not tracked")
		})

		t.Run("releases every waiter", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))

			var wg sync.WaitGroup
			results := make([]bool, concurrentWaiters)
			for i := range results {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					results[i] = m.waitForProjection(context.Background(), projectedRoundId, 5*time.Second)
				}(i)
			}

			m.markProjected(projectedRoundId)
			wg.Wait()
			for i, ok := range results {
				require.True(t, ok, "waiter %d was not released", i)
			}
		})

		// A round that failed writes no vtxo rows and never marks, so expecting
		// it would leave a wait nothing could end.
		t.Run("tracks nothing for a batch that did not end", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(startedRoundOf(t))

			start := time.Now()
			require.True(t, m.waitForProjection(context.Background(), projectedRoundId, 5*time.Second))
			require.Less(t, time.Since(start), time.Second)
		})

		// Every event of a round projects, so the same round is marked again
		// when it is later swept. That must not churn the wakeup.
		t.Run("marking the same batch again changes nothing", func(t *testing.T) {
			m := newBatchSessionManager()
			m.track(endedRound(t))
			m.markProjected(projectedRoundId)

			m.lock.Lock()
			before := m.updated
			m.lock.Unlock()

			m.markProjected(projectedRoundId)

			m.lock.Lock()
			after, projected := m.updated, m.inflightBatches[projectedRoundId]
			m.lock.Unlock()

			require.True(t, projected, "the batch stays projected")
			require.True(t, before == after, "a repeat mark must not wake the waiters again")
		})

		// A round finished by a previous process is still in the cache after a
		// restart. Its projection was written before this process started, so
		// waiting for it here would stall every restart.
		t.Run("does not wait for a batch it never tracked", func(t *testing.T) {
			m := newBatchSessionManager()

			start := time.Now()
			require.True(t, m.waitForProjection(context.Background(), projectedRoundId, 5*time.Second))
			require.Less(t, time.Since(start), time.Second)
		})
	})

	// The db service dispatches the batch update handler only after the
	// projection writes have returned, which is why the handler is where the
	// round is marked.
	t.Run("the batch update handler marks a finished batch", func(t *testing.T) {
		svc, rm := newProjectionTestService(t)
		svc.batchSessions.track(endedRound(t))

		rm.batchHandler(sweptRound(t))

		require.True(
			t, svc.batchSessions.waitForProjection(context.Background(), projectedRoundId, time.Second),
			"a finished round must be marked projected",
		)
	})

	// The point of the wait: startRound must not release the finished batch's
	// intent claims until its spent marks are readable. Releasing first leaves
	// a window in which neither guard holds and a settled vtxo can be
	// registered again.
	t.Run("the next batch releases no claim before the projection lands", func(t *testing.T) {
		svc, released := newStartRoundTestService(t, endedRound(t))
		svc.batchSessions.track(endedRound(t))

		go func() {
			// startRound is driven with only the stores it touches before the
			// release, so recover keeps a later nil from failing the suite on
			// something this case does not assert.
			defer func() { _ = recover() }()
			svc.startRound()
		}()

		// Long enough to be meaningful against a wait bounded at 30s.
		select {
		case <-released:
			require.FailNow(t, "the claims were released before the projection landed")
		case <-time.After(200 * time.Millisecond):
		}

		svc.batchSessions.markProjected(projectedRoundId)
		select {
		case <-released:
		case <-time.After(5 * time.Second):
			require.FailNow(t, "the claims were never released after the projection landed")
		}
	})

	t.Run("an unfinished batch is not marked", func(t *testing.T) {
		svc, rm := newProjectionTestService(t)
		svc.batchSessions.track(endedRound(t))

		rm.batchHandler(startedRound(t))

		require.False(
			t, svc.batchSessions.waitForProjection(context.Background(), projectedRoundId, 100*time.Millisecond),
			"only the projection of a finished batch releases the next one",
		)
	})
}

// concurrentWaiters is the number of racing waiters used to check that marking
// a round releases all of them, not just one.
const concurrentWaiters = 8

const projectedRoundId = "projected-round-id"

// newProjectionTestService wires the real handler registration against a mock
// that captures the batch handler, so the test drives the same closure the db
// service calls. The channels are buffered because the handler publishes to
// them before it returns.
func newProjectionTestService(t *testing.T) (*service, *mockedRepoManager) {
	t.Helper()

	rm := &mockedRepoManager{}
	svc := &service{
		repoManager:         rm,
		batchSessions:       newBatchSessionManager(),
		eventsCh:            make(chan []domain.Event, 8),
		transactionEventsCh: make(chan TransactionEvent, 8),
		indexerTxEventsCh:   make(chan TransactionEvent, 8),
		wg:                  &sync.WaitGroup{},
		offchainTxMu:        &sync.Mutex{},
	}
	svc.registerEventHandlers()
	require.NotNil(t, rm.batchHandler, "the batch update handler must be registered")

	return svc, rm
}

// sweptRound is a finished batch that was then swept. The sweep is what the
// handler reads as its last event, which is the branch that returns without
// touching the stores a fuller round would need.
func sweptRound(t *testing.T) domain.Round {
	t.Helper()

	round := domain.NewRoundFromEvents(append(endedRoundEvents(), domain.BatchSwept{
		RoundEvent: domain.RoundEvent{Id: projectedRoundId, Type: domain.EventTypeBatchSwept},
		Txid:       "sweeptxid",
		FullySwept: true,
	}))
	require.True(t, round.IsEnded())
	return *round
}

func startedRoundOf(t *testing.T) *domain.Round {
	t.Helper()

	round := startedRound(t)
	return &round
}

func startedRound(t *testing.T) domain.Round {
	t.Helper()

	round := domain.NewRoundFromEvents([]domain.Event{domain.RoundStarted{
		RoundEvent: domain.RoundEvent{Id: projectedRoundId, Type: domain.EventTypeRoundStarted},
		Timestamp:  1767225600,
	}})
	require.False(t, round.IsEnded())
	return *round
}

func endedRoundEvents() []domain.Event {
	return []domain.Event{
		domain.RoundStarted{
			RoundEvent: domain.RoundEvent{Id: projectedRoundId, Type: domain.EventTypeRoundStarted},
			Timestamp:  1767225600,
		},
		domain.RoundFinalizationStarted{
			RoundEvent: domain.RoundEvent{
				Id:   projectedRoundId,
				Type: domain.EventTypeRoundFinalizationStarted,
			},
			CommitmentTxid: "commitmenttxid",
		},
		domain.RoundFinalized{
			RoundEvent: domain.RoundEvent{Id: projectedRoundId, Type: domain.EventTypeRoundFinalized},
			Timestamp:  1767225600,
		},
	}
}

// newStartRoundTestService builds a service holding round in its cache, with
// stubs for the stores startRound touches on its way to releasing the finished
// batch's claims. The returned channel is closed by that release.
func newStartRoundTestService(t *testing.T, round *domain.Round) (*service, <-chan struct{}) {
	t.Helper()

	released := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	wallet := &mockedWallet{}
	svc := &service{
		wallet:        wallet,
		batchSessions: newBatchSessionManager(),
		cache: startRoundTestStore{
			round:    round,
			released: released,
		},
		ctx: ctx,
		wg:  &sync.WaitGroup{},
	}
	svc.wg.Add(1)

	return svc, released
}

// startRoundTestStore serves the finished round and records the release of its
// claims. Every other store startRound touches before that point either
// tolerates an error or is a no-op, so they are stubbed as such.
type startRoundTestStore struct {
	ports.LiveStore
	round    *domain.Round
	released chan struct{}
}

func (s startRoundTestStore) Settings() ports.SettingsStore {
	return testSettingsStore{settings: &ports.Settings{
		Settings: domain.Settings{SessionDuration: time.Minute},
	}}
}

func (s startRoundTestStore) CurrentRound() ports.CurrentRoundStore {
	return startRoundTestCurrentRound{round: s.round}
}

func (s startRoundTestStore) Intents() ports.IntentStore {
	return startRoundTestIntents{released: s.released}
}

func (s startRoundTestStore) ForfeitTxs() ports.ForfeitTxsStore {
	return startRoundTestForfeitTxs{}
}

func (s startRoundTestStore) ConfirmationSessions() ports.ConfirmationSessionsStore {
	return startRoundTestConfirmations{}
}

func (s startRoundTestStore) TreeSigingSessions() ports.TreeSigningSessionsStore {
	return startRoundTestTreeSigning{}
}

func (s startRoundTestStore) BoardingInputs() ports.BoardingInputsStore {
	return startRoundTestBoardingInputs{}
}

type startRoundTestCurrentRound struct {
	ports.CurrentRoundStore
	round *domain.Round
}

func (c startRoundTestCurrentRound) Get(context.Context) (*domain.Round, error) {
	return c.round, nil
}

// Upsert refuses, which stops startRound once it has passed the release this
// case is about, without it creating a round the stubs cannot serve.
func (c startRoundTestCurrentRound) Upsert(
	context.Context, func(*domain.Round) *domain.Round,
) error {
	return fmt.Errorf("no round is created in this test")
}

type startRoundTestIntents struct {
	ports.IntentStore
	released chan struct{}
}

func (i startRoundTestIntents) DeleteVtxos(context.Context) error {
	close(i.released)
	return nil
}

func (i startRoundTestIntents) ViewAll(
	context.Context, []string,
) ([]ports.TimedIntent, error) {
	return nil, fmt.Errorf("no intents in this test")
}

// The stores startRound resets alongside the claims. Each is a no-op: this case
// is about when the claims are released, not what else the reset does.
type startRoundTestForfeitTxs struct{ ports.ForfeitTxsStore }

func (startRoundTestForfeitTxs) Reset(context.Context) error { return nil }

type startRoundTestConfirmations struct {
	ports.ConfirmationSessionsStore
}

func (startRoundTestConfirmations) Reset(context.Context) error { return nil }

type startRoundTestTreeSigning struct{ ports.TreeSigningSessionsStore }

func (startRoundTestTreeSigning) Delete(context.Context, string) error { return nil }

type startRoundTestBoardingInputs struct{ ports.BoardingInputsStore }

func (startRoundTestBoardingInputs) DeleteSignatures(context.Context, string) error { return nil }

// endedRound is a finished batch as startRound finds it in the cache.
func endedRound(t *testing.T) *domain.Round {
	t.Helper()

	round := domain.NewRoundFromEvents(endedRoundEvents())
	require.True(t, round.IsEnded())
	return round
}

// requireBlocked fails unless the wait is still running.
func requireBlocked(t *testing.T, waited <-chan bool, msg ...string) {
	t.Helper()

	reason := "the wait ended before the batch was projected"
	if len(msg) > 0 {
		reason = msg[0]
	}
	select {
	case <-waited:
		require.FailNow(t, reason)
	case <-time.After(100 * time.Millisecond):
	}
}

// requireNotTracked fails if the batch is still in flight.
func requireNotTracked(t *testing.T, m *batchSessionManager, batchId string, msg ...string) {
	t.Helper()

	m.lock.Lock()
	_, tracked := m.inflightBatches[batchId]
	m.lock.Unlock()

	reason := "the batch must stop being tracked"
	if len(msg) > 0 {
		reason = msg[0]
	}
	require.False(t, tracked, reason)
}

// endedRoundWithId is endedRound under another id, for the cases that need two
// batches in flight.
func endedRoundWithId(t *testing.T, id string) *domain.Round {
	t.Helper()

	events := endedRoundEvents()
	for i, event := range events {
		switch e := event.(type) {
		case domain.RoundStarted:
			e.Id = id
			events[i] = e
		case domain.RoundFinalizationStarted:
			e.Id = id
			events[i] = e
		case domain.RoundFinalized:
			e.Id = id
			events[i] = e
		}
	}
	round := domain.NewRoundFromEvents(events)
	require.True(t, round.IsEnded())
	require.Equal(t, id, round.Id)
	return round
}
