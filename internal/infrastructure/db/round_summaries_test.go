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

// testRoundSummaries covers the filtering, ordering and limit semantics of the
// batch listing. These used to live in the application layer; they are now
// pushed into SQL, so they have to be verified against every dialect.
func testRoundSummaries(t *testing.T, svc ports.RepoManager) {
	t.Run("test_round_summaries", func(t *testing.T) {
		ctx := context.Background()
		repo := svc.Rounds()

		// A window far in the future so these rows cannot collide with the rounds
		// the other subtests write.
		base := time.Now().Add(72 * time.Hour).Unix()
		from, to := base-1, base+1000

		type spec struct {
			id      string
			offset  int64
			failed  bool
			ended   bool
			reason  string
			intents int
			txid    string
		}
		specs := []spec{
			{id: "sum-ok-old", offset: 10, ended: true, intents: 2, txid: fmt.Sprintf("%064x", 0xA1)},
			{id: "sum-failed-mid", offset: 20, failed: true, reason: "not enough intent confirmations received"},
			{id: "sum-ok-new", offset: 30, ended: true, intents: 3, txid: fmt.Sprintf("%064x", 0xA2)},
		}

		for _, s := range specs {
			intents := make(map[string]domain.Intent, s.intents)
			for i := 0; i < s.intents; i++ {
				iid := fmt.Sprintf("%s-i%d", s.id, i)
				intents[iid] = domain.Intent{Id: iid, Proof: "p", Message: "m"}
			}
			r := domain.Round{
				Id:                 s.id,
				StartingTimestamp:  base + s.offset,
				EndingTimestamp:    base + s.offset + 5,
				Stage:              domain.Stage{Code: int(domain.RoundFinalizationStage), Ended: s.ended, Failed: s.failed},
				Intents:            intents,
				FailReason:         s.reason,
				VtxoTreeExpiration: 604800,
				Version:            1,
				VtxoTree:           tree.FlatTxTree{},
				Connectors:         tree.FlatTxTree{},
			}
			if s.txid != "" {
				r.CommitmentTxid = s.txid
				r.CommitmentTx = "cHNidP8BAgQCAAAA"
			}
			require.NoError(t, repo.AddOrUpdateRound(ctx, r))
		}

		byId := func(list []domain.RoundSummary) map[string]domain.RoundSummary {
			m := make(map[string]domain.RoundSummary, len(list))
			for _, s := range list {
				m[s.RoundId] = s
			}
			return m
		}

		t.Run("returns the listing fields without a second read", func(t *testing.T) {
			all, err := repo.GetRoundSummaries(ctx, from, to, true, true, false, 0)
			require.NoError(t, err)
			got := byId(all)
			require.Len(t, got, 3)

			ok := got["sum-ok-new"]
			require.Equal(t, fmt.Sprintf("%064x", 0xA2), ok.CommitmentTxid)
			require.Equal(t, int64(3), ok.TotalIntents)
			require.True(t, ok.Ended)
			require.False(t, ok.Failed)
			require.Empty(t, ok.FailReason)
			require.Equal(t, domain.RoundFinalizationStage.String(), ok.Stage)

			bad := got["sum-failed-mid"]
			require.True(t, bad.Failed)
			require.False(t, bad.Ended, "a failed round must not report as ended")
			require.Equal(t, "not enough intent confirmations received", bad.FailReason)
			require.Empty(t, bad.CommitmentTxid, "failed before commitment")
			require.Equal(t, int64(0), bad.TotalIntents)
		})

		t.Run("orders most recent first", func(t *testing.T) {
			all, err := repo.GetRoundSummaries(ctx, from, to, true, true, false, 0)
			require.NoError(t, err)
			require.Equal(t, []string{"sum-ok-new", "sum-failed-mid", "sum-ok-old"},
				[]string{all[0].RoundId, all[1].RoundId, all[2].RoundId})
		})

		t.Run("limit keeps the most recent", func(t *testing.T) {
			top, err := repo.GetRoundSummaries(ctx, from, to, true, true, false, 2)
			require.NoError(t, err)
			require.Len(t, top, 2)
			require.Equal(t, "sum-ok-new", top[0].RoundId)
			require.Equal(t, "sum-failed-mid", top[1].RoundId)
		})

		t.Run("only_failed narrows to failures", func(t *testing.T) {
			failed, err := repo.GetRoundSummaries(ctx, from, to, false, true, true, 0)
			require.NoError(t, err)
			require.Len(t, failed, 1)
			require.Equal(t, "sum-failed-mid", failed[0].RoundId)
		})

		t.Run("with_failed=false excludes failures", func(t *testing.T) {
			all, err := repo.GetRoundSummaries(ctx, from, to, false, true, false, 0)
			require.NoError(t, err)
			for _, s := range all {
				require.False(t, s.Failed, "round %s should have been filtered out", s.RoundId)
			}
			require.Len(t, all, 2)
		})

		t.Run("with_completed=false excludes ended rounds", func(t *testing.T) {
			all, err := repo.GetRoundSummaries(ctx, from, to, true, false, false, 0)
			require.NoError(t, err)
			got := byId(all)
			require.NotContains(t, got, "sum-ok-new")
			require.NotContains(t, got, "sum-ok-old")
			require.Contains(t, got, "sum-failed-mid")
		})

		t.Run("range bounds are respected", func(t *testing.T) {
			// Window that only covers the middle round.
			mid, err := repo.GetRoundSummaries(ctx, base+15, base+25, true, true, false, 0)
			require.NoError(t, err)
			require.Len(t, mid, 1)
			require.Equal(t, "sum-failed-mid", mid[0].RoundId)
		})

		t.Run("zero bounds mean unbounded", func(t *testing.T) {
			all, err := repo.GetRoundSummaries(ctx, 0, 0, true, true, false, 0)
			require.NoError(t, err)
			got := byId(all)
			require.Contains(t, got, "sum-ok-new")
		})
	})
}
