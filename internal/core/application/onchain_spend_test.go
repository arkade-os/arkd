package application

import (
	"context"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The mainnet vtxo that motivated onchain spend tracking: unrolled and confirmed
// at height 960277, then spent onchain at 964276, while arkd kept reporting it
// unspent because a spend of a watched output produces no new UTXO to notice.
const (
	unrolledVtxoTxid = "4ba63c204f39841e3a7c98e458586307cf6d33bbed9a9a520c827ab043f32701"
	spendingTxid     = "0e85af9b9c0fe73b82cd59a46b333cd312b830706cf82dda856c81d0d09e1f72"
	replacementTxid  = "1111111111111111111111111111111111111111111111111111111111111111"
)

func outpoint(txid string, vout uint32) domain.Outpoint {
	return domain.Outpoint{Txid: txid, VOut: vout}
}

func spendOf(out domain.Outpoint, by string, confirmations uint32) ports.Spend {
	return ports.Spend{Outpoint: out, SpendingTxid: by, Confirmations: confirmations}
}

func TestApplyOnchainSpends(t *testing.T) {
	out := outpoint(unrolledVtxoTxid, 0)

	newService := func(
		t *testing.T, stored []domain.Vtxo,
	) (*service, *mockedVtxoRepo) {
		t.Helper()
		vtxos := &mockedVtxoRepo{}
		vtxos.On("GetVtxos", mock.Anything, mock.Anything).Return(stored, nil)
		rm := &mockedRepoManager{}
		rm.On("Vtxos").Return(vtxos)
		return &service{repoManager: rm}, vtxos
	}

	t.Run("records an unrolled vtxo spent onchain", func(t *testing.T) {
		svc, vtxos := newService(t, []domain.Vtxo{{Outpoint: out, Unrolled: true}})
		vtxos.On("MarkVtxosOnchainSpent", mock.Anything, mock.Anything).Return(nil)

		require.NoError(t, svc.applyOnchainSpends(
			context.Background(), []ports.Spend{spendOf(out, spendingTxid, 3)},
		))

		vtxos.AssertCalled(
			t, "MarkVtxosOnchainSpent", mock.Anything,
			map[domain.Outpoint]string{out: spendingTxid},
		)
	})

	// A mempool spend is recorded exactly like a confirmed one. Waiting for a
	// confirmation would leave arkd building batches around an input its owner
	// has already broadcast a conflicting spend for; the reconcile loop is what
	// undoes a spend that never confirms.
	t.Run("records an unconfirmed spend", func(t *testing.T) {
		svc, vtxos := newService(t, []domain.Vtxo{{Outpoint: out, Unrolled: true}})
		vtxos.On("MarkVtxosOnchainSpent", mock.Anything, mock.Anything).Return(nil)

		require.NoError(t, svc.applyOnchainSpends(
			context.Background(), []ports.Spend{spendOf(out, spendingTxid, 0)},
		))

		vtxos.AssertCalled(
			t, "MarkVtxosOnchainSpent", mock.Anything,
			map[domain.Outpoint]string{out: spendingTxid},
		)
	})

	// The wallet watches boarding scripts as well as vtxo scripts, so most
	// notified spends refer to outputs that are not unrolled vtxos at all.
	t.Run("ignores a vtxo that was never unrolled", func(t *testing.T) {
		svc, vtxos := newService(t, []domain.Vtxo{{Outpoint: out}})

		require.NoError(t, svc.applyOnchainSpends(
			context.Background(), []ports.Spend{spendOf(out, spendingTxid, 1)},
		))

		vtxos.AssertNotCalled(t, "MarkVtxosOnchainSpent", mock.Anything, mock.Anything)
	})

	// This is the case that must never be overwritten: the vtxo was spent inside
	// the Ark and then unrolled, which is the fraud/sweep path. Its ArkTxid is
	// what the sweeper resolves as a checkpoint tx.
	t.Run("ignores a vtxo already spent offchain", func(t *testing.T) {
		svc, vtxos := newService(t, []domain.Vtxo{{
			Outpoint: out, Unrolled: true, Spent: true,
			SpentBy: "checkpointtxid", ArkTxid: "arktxid",
		}})

		require.NoError(t, svc.applyOnchainSpends(
			context.Background(), []ports.Spend{spendOf(out, spendingTxid, 1)},
		))

		vtxos.AssertNotCalled(t, "MarkVtxosOnchainSpent", mock.Anything, mock.Anything)
	})

	t.Run("ignores a vtxo settled in a batch", func(t *testing.T) {
		svc, vtxos := newService(t, []domain.Vtxo{{
			Outpoint: out, Unrolled: true, Spent: true, SettledBy: "commitmenttxid",
		}})

		require.NoError(t, svc.applyOnchainSpends(
			context.Background(), []ports.Spend{spendOf(out, spendingTxid, 1)},
		))

		vtxos.AssertNotCalled(t, "MarkVtxosOnchainSpent", mock.Anything, mock.Anything)
	})

	// Re-notification of a spend already recorded must not churn updated_at,
	// which drives the indexer's change feed.
	t.Run("skips a spend already recorded", func(t *testing.T) {
		svc, vtxos := newService(t, []domain.Vtxo{{
			Outpoint: out, Unrolled: true, Spent: true, SpentBy: spendingTxid,
		}})

		require.NoError(t, svc.applyOnchainSpends(
			context.Background(), []ports.Spend{spendOf(out, spendingTxid, 6)},
		))

		vtxos.AssertNotCalled(t, "MarkVtxosOnchainSpent", mock.Anything, mock.Anything)
	})

	// RBF: the replacement becomes the spender, so spent_by has to follow it.
	t.Run("re-points an onchain spend when the spender is replaced", func(t *testing.T) {
		svc, vtxos := newService(t, []domain.Vtxo{{
			Outpoint: out, Unrolled: true, Spent: true, SpentBy: spendingTxid,
		}})
		vtxos.On("MarkVtxosOnchainSpent", mock.Anything, mock.Anything).Return(nil)

		require.NoError(t, svc.applyOnchainSpends(
			context.Background(), []ports.Spend{spendOf(out, replacementTxid, 0)},
		))

		vtxos.AssertCalled(
			t, "MarkVtxosOnchainSpent", mock.Anything,
			map[domain.Outpoint]string{out: replacementTxid},
		)
	})

	t.Run("no spends is a no-op", func(t *testing.T) {
		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		svc := &service{repoManager: rm}

		require.NoError(t, svc.applyOnchainSpends(context.Background(), nil))

		rm.AssertNotCalled(t, "Vtxos")
		vtxos.AssertNotCalled(t, "MarkVtxosOnchainSpent", mock.Anything, mock.Anything)
	})
}

func TestRetractStaleOnchainSpends(t *testing.T) {
	out := outpoint(unrolledVtxoTxid, 0)
	recorded := []domain.Vtxo{{
		Outpoint: out, Unrolled: true, Spent: true, SpentBy: spendingTxid,
	}}

	newService := func(
		t *testing.T, unspent map[domain.Outpoint]struct{}, unspentErr error,
	) (*service, *mockedVtxoRepo) {
		t.Helper()
		vtxos := &mockedVtxoRepo{}
		rm := &mockedRepoManager{}
		rm.On("Vtxos").Return(vtxos)
		scanner := &mockedScanner{unspent: unspent, unspentErr: unspentErr}
		return &service{repoManager: rm, scanner: scanner}, vtxos
	}

	t.Run("retracts a spend whose outpoint is unspent again", func(t *testing.T) {
		svc, vtxos := newService(t, map[domain.Outpoint]struct{}{out: {}}, nil)
		vtxos.On("UnmarkVtxosOnchainSpent", mock.Anything, mock.Anything).Return(nil)

		svc.retractStaleOnchainSpends(context.Background(), recorded)

		vtxos.AssertCalled(
			t, "UnmarkVtxosOnchainSpent", mock.Anything, []domain.Outpoint{out},
		)
	})

	// The critical safety property. An outpoint missing from the unspent set is
	// ambiguous: it may be genuinely spent, or its script may have fallen out of
	// the wallet's tracking. Retracting on absence would mark a live vtxo
	// unspent-then-spent at random and, worse, could clear a real spend. Only
	// positive presence retracts.
	t.Run("does not retract on absence from the unspent set", func(t *testing.T) {
		svc, vtxos := newService(t, map[domain.Outpoint]struct{}{}, nil)

		svc.retractStaleOnchainSpends(context.Background(), recorded)

		vtxos.AssertNotCalled(t, "UnmarkVtxosOnchainSpent", mock.Anything, mock.Anything)
	})

	t.Run("does not retract when the unspent lookup fails", func(t *testing.T) {
		svc, vtxos := newService(t, nil, status.Error(codes.Unavailable, "wallet down"))

		svc.retractStaleOnchainSpends(context.Background(), recorded)

		vtxos.AssertNotCalled(t, "UnmarkVtxosOnchainSpent", mock.Anything, mock.Anything)
	})

	t.Run("nothing recorded is a no-op", func(t *testing.T) {
		svc, vtxos := newService(t, map[domain.Outpoint]struct{}{out: {}}, nil)

		svc.retractStaleOnchainSpends(context.Background(), nil)

		vtxos.AssertNotCalled(t, "UnmarkVtxosOnchainSpent", mock.Anything, mock.Anything)
	})
}

func TestReconcileOnchainSpendsOnce(t *testing.T) {
	out := outpoint(unrolledVtxoTxid, 0)

	t.Run("backfills a spend that predates onchain tracking", func(t *testing.T) {
		vtxos := &mockedVtxoRepo{}
		vtxos.On("GetUnrolledUnspentVtxos", mock.Anything).
			Return([]domain.Vtxo{{Outpoint: out, Unrolled: true}}, nil)
		vtxos.On("GetOnchainSpentVtxos", mock.Anything).Return([]domain.Vtxo{}, nil)
		vtxos.On("GetVtxos", mock.Anything, mock.Anything).
			Return([]domain.Vtxo{{Outpoint: out, Unrolled: true}}, nil)
		vtxos.On("MarkVtxosOnchainSpent", mock.Anything, mock.Anything).Return(nil)
		rm := &mockedRepoManager{}
		rm.On("Vtxos").Return(vtxos)

		svc := &service{
			repoManager: rm,
			scanner: &mockedScanner{
				spends: []ports.Spend{spendOf(out, spendingTxid, 4)},
			},
		}

		svc.reconcileOnchainSpendsOnce(context.Background(), nil)

		vtxos.AssertCalled(
			t, "MarkVtxosOnchainSpent", mock.Anything,
			map[domain.Outpoint]string{out: spendingTxid},
		)
	})

	// An arkd-wallet predating this feature answers Unimplemented. arkd must
	// degrade to "not tracking onchain spends" instead of erroring every tick,
	// because operators run the two as separate containers and can upgrade them
	// independently.
	t.Run("degrades when the wallet does not implement GetSpends", func(t *testing.T) {
		vtxos := &mockedVtxoRepo{}
		vtxos.On("GetUnrolledUnspentVtxos", mock.Anything).
			Return([]domain.Vtxo{{Outpoint: out, Unrolled: true}}, nil)
		vtxos.On("GetOnchainSpentVtxos", mock.Anything).Return([]domain.Vtxo{}, nil)
		rm := &mockedRepoManager{}
		rm.On("Vtxos").Return(vtxos)

		svc := &service{
			repoManager: rm,
			scanner: &mockedScanner{
				spendsErr: status.Error(codes.Unimplemented, "unknown method GetSpends"),
			},
		}

		require.NotPanics(t, func() {
			svc.reconcileOnchainSpendsOnce(context.Background(), nil)
		})
		vtxos.AssertNotCalled(t, "MarkVtxosOnchainSpent", mock.Anything, mock.Anything)
	})

	t.Run("skips the wallet entirely when there is nothing to check", func(t *testing.T) {
		vtxos := &mockedVtxoRepo{}
		vtxos.On("GetUnrolledUnspentVtxos", mock.Anything).Return([]domain.Vtxo{}, nil)
		vtxos.On("GetOnchainSpentVtxos", mock.Anything).Return([]domain.Vtxo{}, nil)
		rm := &mockedRepoManager{}
		rm.On("Vtxos").Return(vtxos)

		scanner := &mockedScanner{
			spendsErr: status.Error(codes.Internal, "must not be called"),
		}
		svc := &service{repoManager: rm, scanner: scanner}

		require.NotPanics(t, func() {
			svc.reconcileOnchainSpendsOnce(context.Background(), nil)
		})
		vtxos.AssertNotCalled(t, "MarkVtxosOnchainSpent", mock.Anything, mock.Anything)
	})
}

// TestReconcileFirstPassIsUnwindowed guards the backfill of vtxos spent before
// this tracking existed. Periodic passes only need to cover what push
// notifications could have missed, so they window the query to keep it cheap —
// but applying that window to the first pass would make a spend older than
// reconcileLookback permanently invisible, leaving a vtxo usable whose onchain
// outpoint is gone.
func TestReconcileFirstPassIsUnwindowed(t *testing.T) {
	out := outpoint(unrolledVtxoTxid, 0)

	vtxos := &mockedVtxoRepo{}
	vtxos.On("GetUnrolledUnspentVtxos", mock.Anything).
		Return([]domain.Vtxo{{Outpoint: out, Unrolled: true}}, nil)
	vtxos.On("GetOnchainSpentVtxos", mock.Anything).Return([]domain.Vtxo{}, nil)
	vtxos.On("GetVtxos", mock.Anything, mock.Anything).
		Return([]domain.Vtxo{{Outpoint: out, Unrolled: true}}, nil)
	vtxos.On("MarkVtxosOnchainSpent", mock.Anything, mock.Anything).Return(nil)
	rm := &mockedRepoManager{}
	rm.On("Vtxos").Return(vtxos)

	// A spend far older than the rolling window: only an unwindowed query
	// reaches it.
	scanner := &mockedScanner{spends: []ports.Spend{spendOf(out, spendingTxid, 5000)}}
	ctx, cancel := context.WithCancel(context.Background())
	svc := &service{repoManager: rm, scanner: scanner, ctx: ctx}

	// A long interval means the ticker never fires; only the startup pass runs.
	go svc.reconcileOnchainSpends(time.Hour)

	require.Eventually(t, func() bool {
		return len(scanner.SpendsFrom()) > 0
	}, 2*time.Second, 10*time.Millisecond)
	cancel()

	require.Nil(t, scanner.SpendsFrom()[0], "the startup pass must not window the query")
	vtxos.AssertCalled(
		t, "MarkVtxosOnchainSpent", mock.Anything,
		map[domain.Outpoint]string{out: spendingTxid},
	)
}

func TestWatchOnchainSpends(t *testing.T) {
	out := outpoint(unrolledVtxoTxid, 0)

	vtxos := &mockedVtxoRepo{}
	vtxos.On("GetVtxos", mock.Anything, mock.Anything).
		Return([]domain.Vtxo{{Outpoint: out, Unrolled: true}}, nil)
	marked := make(chan map[domain.Outpoint]string, 1)
	vtxos.On("MarkVtxosOnchainSpent", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			marked <- args.Get(1).(map[domain.Outpoint]string)
		}).Return(nil)
	rm := &mockedRepoManager{}
	rm.On("Vtxos").Return(vtxos)

	spendCh := make(chan []ports.Spend, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc := &service{
		repoManager: rm, scanner: &mockedScanner{spendCh: spendCh}, ctx: ctx,
	}

	go svc.watchOnchainSpends()
	spendCh <- []ports.Spend{spendOf(out, spendingTxid, 0)}

	select {
	case got := <-marked:
		require.Equal(t, map[domain.Outpoint]string{out: spendingTxid}, got)
	case <-time.After(2 * time.Second):
		require.Fail(t, "timeout waiting for pushed spend to be recorded")
	}
	close(spendCh)
}
