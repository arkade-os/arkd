package db_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/stretchr/testify/require"
)

// testCollectedFees covers the aggregate that backs the admin fees page. It used
// to be a loop that loaded every round in the window in full; the semantics now
// live in SQL and have to be verified against every dialect. The total is
// whatever storage holds — batches finalized before fees were persisted read as
// zero and stay that way.
func testCollectedFees(t *testing.T, svc ports.RepoManager) {
	t.Run("test_collected_fees", func(t *testing.T) {
		ctx := context.Background()
		repo := svc.Rounds()

		// A window far in the future so these rows cannot collide with the rounds
		// the other subtests write.
		base := time.Now().Add(96 * time.Hour).Unix()
		from, to := base-1, base+1000

		type spec struct {
			id     string
			offset int64
			fees   uint64
			ended  bool
			failed bool
		}
		specs := []spec{
			{id: "fee-ok-a", offset: 10, fees: 1500, ended: true},
			{id: "fee-ok-b", offset: 20, fees: 2500, ended: true},
			{id: "fee-zero", offset: 30, fees: 0, ended: true},
			// Excluded: a failed batch collects nothing.
			{id: "fee-failed", offset: 40, fees: 9999, failed: true},
			// Excluded: not finalized yet, so its fee is not due.
			{id: "fee-pending", offset: 50, fees: 8888},
		}

		for _, s := range specs {
			require.NoError(t, repo.AddOrUpdateRound(ctx, domain.Round{
				Id:                s.id,
				StartingTimestamp: base + s.offset,
				EndingTimestamp:   base + s.offset + 5,
				Stage: domain.Stage{
					Code:   int(domain.RoundFinalizationStage),
					Ended:  s.ended,
					Failed: s.failed,
				},
				CollectedFees:      s.fees,
				VtxoTreeExpiration: 604800,
				Version:            1,
				VtxoTree:           tree.FlatTxTree{},
				Connectors:         tree.FlatTxTree{},
			}))
		}

		t.Run("sums only finalized, non-failed batches in range", func(t *testing.T) {
			total, err := repo.SumCollectedFees(ctx, from, to)
			require.NoError(t, err)
			require.Equal(t, uint64(1500+2500+0), total)
		})

		t.Run("range bounds are honoured", func(t *testing.T) {
			// Excludes fee-ok-a (offset 10) by starting after it.
			total, err := repo.SumCollectedFees(ctx, base+15, to)
			require.NoError(t, err)
			require.Equal(t, uint64(2500), total)

			// Excludes fee-ok-b (offset 20) and everything later.
			total, err = repo.SumCollectedFees(ctx, from, base+15)
			require.NoError(t, err)
			require.Equal(t, uint64(1500), total)
		})

		t.Run("a zero range is unbounded", func(t *testing.T) {
			total, err := repo.SumCollectedFees(ctx, 0, 0)
			require.NoError(t, err)
			require.GreaterOrEqual(t, total, uint64(4000),
				"an unbounded window must include at least this subtest's batches")
		})

	})
}

// testScheduledSweeps covers the aggregate that backs the admin scheduled-sweeps
// page. The due time is derived in SQL from the batch's ending timestamp and
// vtxo tree expiry, so this endpoint never touches the chain.
func testScheduledSweeps(t *testing.T, svc ports.RepoManager) {
	t.Run("test_scheduled_sweeps", func(t *testing.T) {
		ctx := context.Background()
		repo := svc.Rounds()

		base := time.Now().Add(120 * time.Hour).Unix()

		type spec struct {
			id      string
			txid    string
			endsAt  int64
			expiry  int64
			swept   bool
			ended   bool
			failed  bool
			withTre bool
		}
		specs := []spec{
			// Due last: ends at base+100, expires 900s later.
			{id: "sw-late", txid: fmt.Sprintf("%064x", 0xB1), endsAt: base + 100, expiry: 900, ended: true, withTre: true},
			// Due first: ends at base+100, expires 100s later.
			{id: "sw-early", txid: fmt.Sprintf("%064x", 0xB2), endsAt: base + 100, expiry: 100, ended: true, withTre: true},
			// Excluded: already swept.
			{id: "sw-swept", txid: fmt.Sprintf("%064x", 0xB3), endsAt: base + 100, expiry: 100, ended: true, swept: true, withTre: true},
			// Excluded: no vtxo tree, so there is nothing to sweep.
			{id: "sw-no-tree", txid: fmt.Sprintf("%064x", 0xB4), endsAt: base + 100, expiry: 100, ended: true},
		}

		for _, s := range specs {
			r := domain.Round{
				Id:                s.id,
				StartingTimestamp: base,
				EndingTimestamp:   s.endsAt,
				Stage: domain.Stage{
					Code:   int(domain.RoundFinalizationStage),
					Ended:  s.ended,
					Failed: s.failed,
				},
				Swept:              s.swept,
				CommitmentTxid:     s.txid,
				CommitmentTx:       "cHNidP8BAgQCAAAA",
				VtxoTreeExpiration: s.expiry,
				Version:            1,
				VtxoTree:           tree.FlatTxTree{},
				Connectors:         tree.FlatTxTree{},
			}
			if s.withTre {
				r.VtxoTree = tree.FlatTxTree{
					{Txid: s.id + "-root", Tx: "cHNidP8BAgQCAAAA", Children: map[uint32]string{}},
				}
			}
			require.NoError(t, repo.AddOrUpdateRound(ctx, r))
		}

		// Leaf vtxos for sw-early: only the unspent, unswept, non-preconfirmed one
		// counts toward the value at stake.
		vtxos := []domain.Vtxo{
			{
				Outpoint: domain.Outpoint{Txid: fmt.Sprintf("%064x", 0xC1), VOut: 0},
				Amount:   1000, PubKey: fmt.Sprintf("%064x", 0xD1),
				RootCommitmentTxid: fmt.Sprintf("%064x", 0xB2),
				CommitmentTxids:    []string{fmt.Sprintf("%064x", 0xB2)},
				ExpiresAt:          base + 200, CreatedAt: base,
			},
			{
				Outpoint: domain.Outpoint{Txid: fmt.Sprintf("%064x", 0xC2), VOut: 0},
				Amount:   2000, PubKey: fmt.Sprintf("%064x", 0xD1),
				RootCommitmentTxid: fmt.Sprintf("%064x", 0xB2),
				CommitmentTxids:    []string{fmt.Sprintf("%064x", 0xB2)},
				ExpiresAt:          base + 200, CreatedAt: base,
				Spent: true, SpentBy: fmt.Sprintf("%064x", 0xC9),
			},
			{
				Outpoint: domain.Outpoint{Txid: fmt.Sprintf("%064x", 0xC3), VOut: 0},
				Amount:   4000, PubKey: fmt.Sprintf("%064x", 0xD1),
				RootCommitmentTxid: fmt.Sprintf("%064x", 0xB2),
				CommitmentTxids:    []string{fmt.Sprintf("%064x", 0xB2)},
				ExpiresAt:          base + 200, CreatedAt: base,
				Preconfirmed: true,
			},
		}
		require.NoError(t, svc.Vtxos().AddVtxos(ctx, vtxos))

		byId := func(list []domain.ScheduledSweep) map[string]domain.ScheduledSweep {
			m := make(map[string]domain.ScheduledSweep, len(list))
			for _, s := range list {
				m[s.RoundId] = s
			}
			return m
		}

		t.Run("lists unswept batches that have a tree", func(t *testing.T) {
			all, err := repo.GetScheduledSweeps(ctx, 0)
			require.NoError(t, err)
			got := byId(all)

			require.Contains(t, got, "sw-early")
			require.Contains(t, got, "sw-late")
			require.NotContains(t, got, "sw-swept", "an already-swept batch is not scheduled")
			require.NotContains(t, got, "sw-no-tree", "a batch with no tree has nothing to sweep")
		})

		t.Run("derives the due time without touching the chain", func(t *testing.T) {
			all, err := repo.GetScheduledSweeps(ctx, 0)
			require.NoError(t, err)
			got := byId(all)

			require.Equal(t, base+100+100, got["sw-early"].SweepAt)
			require.Equal(t, base+100+900, got["sw-late"].SweepAt)
			require.Equal(t, fmt.Sprintf("%064x", 0xB2), got["sw-early"].CommitmentTxid)
		})

		t.Run("counts only unspent, unswept, non-preconfirmed leaves", func(t *testing.T) {
			all, err := repo.GetScheduledSweeps(ctx, 0)
			require.NoError(t, err)
			got := byId(all)

			require.Equal(t, uint64(1000), got["sw-early"].TotalAmount,
				"the spent and preconfirmed leaves must not count")
			require.Equal(t, int64(1), got["sw-early"].VtxoCount)
			require.Equal(t, uint64(0), got["sw-late"].TotalAmount)
		})

		t.Run("orders soonest due first and honours the limit", func(t *testing.T) {
			all, err := repo.GetScheduledSweeps(ctx, 0)
			require.NoError(t, err)
			require.GreaterOrEqual(t, len(all), 2)
			for i := 1; i < len(all); i++ {
				require.LessOrEqual(t, all[i-1].SweepAt, all[i].SweepAt,
					"scheduled sweeps must be ordered soonest first")
			}

			one, err := repo.GetScheduledSweeps(ctx, 1)
			require.NoError(t, err)
			require.Len(t, one, 1)
			require.Equal(t, all[0].RoundId, one[0].RoundId,
				"the limit must keep the soonest due, not an arbitrary batch")
		})
	})
}
