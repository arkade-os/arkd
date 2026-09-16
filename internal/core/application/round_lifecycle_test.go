package application

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/stretchr/testify/require"
)

// These tests ensure that at startRound the cache is cleared only for projected batches and for
// batches that did not end.
func TestStartRound(t *testing.T) {
	// A batch that never projects is waited out in every case here, so the wait
	// is shortened to keep these quick.
	oldTimeout := batchProjectionTimeout
	batchProjectionTimeout = 50 * time.Millisecond
	t.Cleanup(func() { batchProjectionTimeout = oldTimeout })

	t.Run("cache not cleared for an inflight batch", func(t *testing.T) {
		const inflightId = "inflight-batch"

		svc, released := newRoundLifecycleTestService(t, endedRoundWithId(t, inflightId))
		svc.batchSessions.track(endedRoundWithId(t, inflightId))

		runStartRound(svc)

		require.Empty(
			t, released.batches(),
			"claims must be held while nothing records the batch's inputs as spent",
		)
	})

	// A batch this process never tracked belongs to a previous one. Nothing here
	// can tell a projection that landed before this process started from one
	// that failed and was never retried, and clearing the cache on that guess
	// would drop the claims of inputs nothing records as spent: a double spend
	// for as long as the process lives. The claims are kept and cleared by hand.
	t.Run("cache not cleared if batch is not tracked", func(t *testing.T) {
		const previousId = "previous-process-batch"

		svc, released := newRoundLifecycleTestService(t, endedRoundWithId(t, previousId))

		runStartRound(svc)

		require.Empty(
			t, released.batches(),
			"a batch this process never tracked is not known to have been projected",
		)
	})

	t.Run("cache cleared if batch is projected", func(t *testing.T) {
		const batchId = "batch"

		svc, released := newRoundLifecycleTestService(t, endedRoundWithId(t, batchId))

		svc.batchSessions.track(endedRoundWithId(t, batchId))
		svc.batchSessions.markProjected(batchId)
		runStartRound(svc)
		require.Equal(t, []string{batchId}, released.batches())
	})

	t.Run("cache cleared if batches are batches while others are inflight", func(t *testing.T) {
		const inflightId, firstId, secondId = "inflight-batch", "first-batch", "second-batch"

		svc, released := newRoundLifecycleTestService(t, endedRoundWithId(t, inflightId))

		svc.batchSessions.track(endedRoundWithId(t, inflightId))
		svc.batchSessions.track(endedRoundWithId(t, firstId))
		svc.batchSessions.markProjected(firstId)
		runStartRound(svc)
		require.Equal(t, []string{firstId}, released.batches())

		svc.batchSessions.track(endedRoundWithId(t, secondId))
		svc.batchSessions.markProjected(secondId)
		runStartRound(svc)

		require.Equal(
			t, []string{firstId, secondId}, released.batches(),
			"a batch still missing its projection must not hold back the ones after it",
		)
	})

	// An aborted or failed round is never saved to the cache as failed, so
	// startRound finds it at the last stage it reached.
	t.Run("cache cleared if batch was aborted", func(t *testing.T) {
		const abortedId = "aborted-batch"

		svc, released := newRoundLifecycleTestService(
			t, unendedRoundWithId(t, abortedId, domain.RoundRegistrationStage),
		)

		runStartRound(svc)
		require.Equal(t, []string{abortedId}, released.batches())
	})

	t.Run("cache cleared if batch failed while others are inflight", func(t *testing.T) {
		const inflightId, failedId = "inflight-batch", "failed-batch"

		svc, released := newRoundLifecycleTestService(
			t, unendedRoundWithId(t, failedId, domain.RoundFinalizationStage),
		)

		svc.batchSessions.track(endedRoundWithId(t, inflightId))
		runStartRound(svc)
		require.Equal(t, []string{failedId}, released.batches())
	})
}

// runStartRound drives startRound far enough to reach the release. It carries on
// afterwards into stores this file does not stub, so recover keeps what happens
// past the release out of these cases.
func runStartRound(svc *service) {
	defer func() { _ = recover() }()

	svc.wg.Add(1)
	svc.startRound()
}

func newRoundLifecycleTestService(
	t *testing.T, round *domain.Round,
) (*service, *releasedBatches) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	released := &releasedBatches{}
	return &service{
		wallet:        &mockedWallet{},
		batchSessions: newBatchSessionManager(),
		cache: roundLifecycleTestStore{
			startRoundTestStore: startRoundTestStore{round: round},
			intents:             releasingIntentStore{released: released},
		},
		ctx: ctx,
		wg:  &sync.WaitGroup{},
	}, released
}

// releasedBatches records the batches whose claims were released, in order.
type releasedBatches struct {
	lock sync.Mutex
	ids  []string
}

func (r *releasedBatches) add(roundId string) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.ids = append(r.ids, roundId)
}

func (r *releasedBatches) batches() []string {
	r.lock.Lock()
	defer r.lock.Unlock()

	return append([]string(nil), r.ids...)
}

// roundLifecycleTestStore is startRoundTestStore with an intent store that
// records which batches were released rather than only that one was.
type roundLifecycleTestStore struct {
	startRoundTestStore
	intents ports.IntentStore
}

func (s roundLifecycleTestStore) Intents() ports.IntentStore {
	return s.intents
}

type releasingIntentStore struct {
	ports.IntentStore
	released *releasedBatches
}

func (i releasingIntentStore) DeleteVtxos(_ context.Context, roundId string) error {
	i.released.add(roundId)
	return nil
}

// unendedRoundWithId is a round under id that stopped at stage without ending,
// as the cache keeps a round that aborted or failed.
func unendedRoundWithId(t *testing.T, id string, stage domain.RoundStage) *domain.Round {
	t.Helper()

	events := []domain.Event{domain.RoundStarted{
		RoundEvent: domain.RoundEvent{Id: id, Type: domain.EventTypeRoundStarted},
		Timestamp:  1767225600,
	}}
	if stage == domain.RoundFinalizationStage {
		events = append(events, domain.RoundFinalizationStarted{
			RoundEvent: domain.RoundEvent{
				Id:   id,
				Type: domain.EventTypeRoundFinalizationStarted,
			},
			CommitmentTxid: "commitmenttxid",
		})
	}
	round := domain.NewRoundFromEvents(events)
	require.False(t, round.IsEnded())
	require.Equal(t, int(stage), round.Stage.Code)
	return round
}
