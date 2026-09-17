package db

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
	ctx := t.Context()

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name          string
			batchSwept    bool
			vtxosSwept    bool
			expectedSwept bool
		}{
			{
				// The state a shutdown between the two writes of a sweep leaves.
				name:          "reconcile swept batch and unswept vtxos",
				batchSwept:    true,
				vtxosSwept:    false,
				expectedSwept: true,
			},
			{
				name:          "nothing to do for swept batch with swept vtxos",
				batchSwept:    true,
				vtxosSwept:    true,
				expectedSwept: true,
			},
			{
				// The vtxos of a batch not fully swept are legitimately unswept.
				name:          "nothing to do for unswept batch",
				batchSwept:    false,
				vtxosSwept:    false,
				expectedSwept: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Opens the store while it is still empty, with nothing to reconcile.
				svc := newProjectionTestService(t, t.TempDir())

				_, outpoints := seedBatch(t, svc, tt.batchSwept)
				if tt.vtxosSwept {
					require.NoError(
						t, svc.Markers().SweepVtxoOutpoints(ctx, outpoints, sweptAtFixture),
					)
				}
				requireSwept(t, svc, outpoints, tt.vtxosSwept)

				require.NoError(t, svc.Open())
				requireSwept(t, svc, outpoints, tt.expectedSwept)

				// The swept insert ignores duplicates, so opening again over a
				// reconciled store must neither fail nor change anything.
				require.NoError(t, svc.Open())
				requireSwept(t, svc, outpoints, tt.expectedSwept)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name        string
			setup       func(svc *service)
			errContains string
		}{
			{
				name:        "closed service",
				setup:       func(svc *service) { svc.Close() },
				errContains: "failed to get swept batches",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				svc := newProjectionTestService(t, t.TempDir()).(*service)
				tt.setup(svc)

				require.ErrorContains(t, svc.Open(), tt.errContains)
			})
		}
	})
}

func TestClose(t *testing.T) {
	tests := []struct {
		name string
		// hold puts work in flight that Close must wait for and returns what lets
		// it finish. Without it Close runs on an idle service.
		hold  func(t *testing.T, svc *service) (release func())
		calls int
	}{
		{
			name: "no inflight updates",
			// Try to call Close many times to ensure it's all good.
			calls: 3,
		},
		{
			name:  "inflight round projection update",
			calls: 1,
			hold: func(t *testing.T, svc *service) func() {
				entered, release := make(chan struct{}), make(chan struct{})
				svc.roundStore = &blockingRoundStore{
					RoundRepository: svc.roundStore,
					entered:         entered,
					release:         release,
				}

				// Saving through the event store runs the handler NewService
				// registered, which parks on the round write.
				events := startedRoundEvents()
				roundId := events[0].(domain.RoundStarted).Id
				require.NoError(t, svc.Events().Save(
					t.Context(), domain.RoundTopic, roundId, events,
				))

				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					require.FailNow(t, "the round projection update never started")
				}
				return func() { close(release) }
			},
		},
		{
			name:  "inflight offchain tx projection update",
			calls: 1,
			hold: func(t *testing.T, svc *service) func() {
				entered, release := make(chan struct{}), make(chan struct{})
				svc.offchainTxStore = &blockingOffchainTxStore{
					OffchainTxRepository: svc.offchainTxStore,
					entered:              entered,
					release:              release,
				}

				// Saving through the event store runs the handler NewService
				// registered, which parks on the offchain tx write.
				arkTxid := randomString(t, 32)
				checkpointTxid := randomString(t, 32)
				events := []domain.Event{
					domain.OffchainTxRequested{
						OffchainTxEvent: domain.OffchainTxEvent{
							Id: arkTxid, Type: domain.EventTypeOffchainTxRequested,
						},
						ArkTx:                 randomTx(t),
						UnsignedCheckpointTxs: map[string]string{checkpointTxid: randomTx(t)},
						StartingTimestamp:     sweptAtFixture,
					},
				}
				require.NoError(t, svc.Events().Save(
					t.Context(), domain.OffchainTxTopic, arkTxid, events,
				))

				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					require.FailNow(t, "the offchain tx projection update never started")
				}
				return func() { close(release) }
			},
		},
		{
			name:  "inflight sweep projection update",
			calls: 1,
			hold: func(t *testing.T, svc *service) func() {
				// The vtxos have to exist for their swept mark to be written.
				commitmentTxid := randomString(t, 32)
				vtxos := []domain.Vtxo{
					newBatchVtxo(t, commitmentTxid),
					newBatchVtxo(t, commitmentTxid),
				}
				require.NoError(t, svc.Vtxos().AddVtxos(t.Context(), vtxos))
				outpoints := []domain.Outpoint{vtxos[0].Outpoint, vtxos[1].Outpoint}

				sweep := newBlockingMarkerStore(svc.markerStore)
				svc.markerStore = sweep

				// The round row lands and the swept insert parks: the gap between
				// the two writes of a sweep projection.
				events := sweptRoundEvents(t, commitmentTxid, outpoints)
				roundId := events[0].(domain.RoundStarted).Id
				require.NoError(t, svc.Events().Save(
					t.Context(), domain.RoundTopic, roundId, events,
				))

				select {
				case <-sweep.entered:
				case <-time.After(5 * time.Second):
					require.FailNow(t, "the sweep projection never reached the swept insert")
				}
				return func() {
					close(sweep.release)
					<-sweep.done
					// Without the drain the stores are already closed here, the
					// insert fails and the batch is left swept with unmarked vtxos.
					require.NoError(t, sweep.err, "the swept insert must land on an open store")
				}
			},
		},
		{
			name:  "inflight registered event handler update",
			calls: 1,
			hold: func(t *testing.T, svc *service) func() {
				entered, release := make(chan struct{}), make(chan struct{})
				svc.RegisterBatchUpdateHandler(func(domain.Round) {
					close(entered)
					<-release
				})

				events := startedRoundEvents()
				roundId := events[0].(domain.RoundStarted).Id
				require.NoError(t, svc.Events().Save(
					t.Context(), domain.RoundTopic, roundId, events,
				))

				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					require.FailNow(t, "the update never dispatched to its subscriber")
				}
				return func() { close(release) }
			},
		},
		{
			name:  "inflight open",
			calls: 1,
			hold: func(t *testing.T, svc *service) func() {
				// A swept batch with unmarked vtxos takes Open to the swept insert,
				// where the blocking store parks it.
				seedBatch(t, svc, true)
				sweep := newBlockingMarkerStore(svc.markerStore)
				svc.markerStore = sweep

				opened := make(chan error, 1)
				go func() { opened <- svc.Open() }()

				select {
				case <-sweep.entered:
				case <-time.After(5 * time.Second):
					require.FailNow(t, "Open never reached the swept insert")
				}
				return func() {
					close(sweep.release)
					require.NoError(t, <-opened)
					require.NoError(t, sweep.err, "the swept insert must land on an open store")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newProjectionTestService(t, t.TempDir()).(*service)

			release := func() {}
			if tt.hold != nil {
				release = tt.hold(t, svc)
			}

			closed := make(chan struct{})
			go func() {
				defer close(closed)
				svc.Close()
			}()

			if tt.hold != nil {
				select {
				case <-closed:
					require.FailNow(t, "Close returned while work was still in flight")
				case <-time.After(100 * time.Millisecond):
				}
			}
			release()

			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				require.FailNow(t, "Close did not return")
			}

			for i := 1; i < tt.calls; i++ {
				require.NotPanics(t, svc.Close)
			}

			// The stores are closed, so the reconciliation can't read them.
			require.Error(t, svc.Open())
		})
	}
}

// blockingRoundStore holds the first projection write open, so a test can put
// an update in flight and keep it there.
type blockingRoundStore struct {
	domain.RoundRepository
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingRoundStore) AddOrUpdateRound(ctx context.Context, round domain.Round) error {
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return b.RoundRepository.AddOrUpdateRound(ctx, round)
}

// blockingOffchainTxStore holds the first write of an offchain tx projection
// open, so a test can put that update in flight and keep it there.
type blockingOffchainTxStore struct {
	domain.OffchainTxRepository
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingOffchainTxStore) AddOrUpdateOffchainTx(
	ctx context.Context, offchainTx *domain.OffchainTx,
) error {
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return b.OffchainTxRepository.AddOrUpdateOffchainTx(ctx, offchainTx)
}

func startedRoundEvents() []domain.Event {
	return []domain.Event{
		domain.RoundStarted{
			RoundEvent: domain.RoundEvent{
				Id:   "reconcile-lifecycle-round",
				Type: domain.EventTypeRoundStarted,
			},
			Timestamp: sweptAtFixture,
		},
	}
}

// blockingMarkerStore parks the swept insert, the second write of a sweep
// projection, so a test can hold an update between its two writes. err keeps
// what the real store answered once released, and done is closed after that.
type blockingMarkerStore struct {
	domain.MarkerRepository
	entered chan struct{}
	release chan struct{}
	done    chan struct{}
	once    sync.Once
	err     error
}

func newBlockingMarkerStore(repo domain.MarkerRepository) *blockingMarkerStore {
	return &blockingMarkerStore{
		MarkerRepository: repo,
		entered:          make(chan struct{}),
		release:          make(chan struct{}),
		done:             make(chan struct{}),
	}
}

func (b *blockingMarkerStore) SweepVtxoOutpoints(
	ctx context.Context, outpoints []domain.Outpoint, sweptAt int64,
) error {
	parked := false
	b.once.Do(func() {
		parked = true
		close(b.entered)
		<-b.release
	})
	err := b.MarkerRepository.SweepVtxoOutpoints(ctx, outpoints, sweptAt)
	if parked {
		b.err = err
		close(b.done)
	}
	return err
}

// sweptRoundEvents is the history of a batch that ended and was then fully
// swept, so the projection takes the sweep path: the round row first, then the
// swept mark of every leaf.
func sweptRoundEvents(
	t *testing.T, commitmentTxid string, leaves []domain.Outpoint,
) []domain.Event {
	t.Helper()

	id := randomString(t, 32)
	return []domain.Event{
		domain.RoundStarted{
			RoundEvent: domain.RoundEvent{Id: id, Type: domain.EventTypeRoundStarted},
			Timestamp:  sweptAtFixture,
		},
		domain.RoundFinalizationStarted{
			RoundEvent: domain.RoundEvent{
				Id:   id,
				Type: domain.EventTypeRoundFinalizationStarted,
			},
			VtxoTree:       tree.FlatTxTree{{Txid: randomString(t, 32), Tx: randomTx(t)}},
			CommitmentTxid: commitmentTxid,
			CommitmentTx:   randomTx(t),
		},
		domain.RoundFinalized{
			RoundEvent:        domain.RoundEvent{Id: id, Type: domain.EventTypeRoundFinalized},
			FinalCommitmentTx: randomTx(t),
			Timestamp:         sweptAtFixture,
		},
		domain.BatchSwept{
			RoundEvent: domain.RoundEvent{Id: id, Type: domain.EventTypeBatchSwept},
			LeafVtxos:  leaves,
			Txid:       randomString(t, 32),
			Tx:         randomTx(t),
			FullySwept: true,
		},
	}
}
