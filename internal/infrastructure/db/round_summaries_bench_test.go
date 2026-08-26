package db_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/internal/infrastructure/db"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/stretchr/testify/require"
)

// TestRoundSummariesScale is the guard on the listing path used by the admin
// Batches view. It is a test rather than a benchmark so CI fails if the query
// regresses back to loading every round individually.
func TestRoundSummariesScale(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scale test in short mode")
	}

	const rounds = 200
	const intentsPerRound = 4

	// Loading each round individually costs ~17s for this many rounds under
	// -race, against ~55ms for the single query. The ceiling sits far enough
	// above the real timing to absorb a slow CI runner, and far enough below
	// the regression to still catch it.
	const ceiling = 2 * time.Second

	svc := newBenchRepo(t)
	defer svc.Close()

	base := time.Now().Add(-24 * time.Hour).Unix()
	seedRounds(t, svc, rounds, intentsPerRound, base)

	ctx := context.Background()
	from, to := base-1, base+int64(rounds)+1

	var summaries []domain.RoundSummary

	t.Run("lists every round in one query", func(t *testing.T) {
		start := time.Now()
		var err error
		summaries, err = svc.Rounds().GetRoundSummaries(ctx, from, to, true, true, false, 0)
		elapsed := time.Since(start)
		require.NoError(t, err)
		require.Len(t, summaries, rounds)
		t.Logf("GetRoundSummaries over %d rounds: %s", rounds, elapsed)

		require.Less(t, elapsed, ceiling,
			"listing %d rounds took %s, over the %s ceiling: the query is likely loading each round individually again",
			rounds, elapsed, ceiling)
	})

	t.Run("summaries carry the listing fields", func(t *testing.T) {
		// Everything the listing renders must come from this one read.
		require.Equal(t, fmt.Sprintf("%064x", 1), summaries[len(summaries)-1].CommitmentTxid)
		require.Equal(t, int64(intentsPerRound), summaries[0].TotalIntents)
	})

	t.Run("orders most recent first", func(t *testing.T) {
		for i := 1; i < len(summaries); i++ {
			require.GreaterOrEqual(t, summaries[i-1].StartedAt, summaries[i].StartedAt)
		}
	})

	t.Run("limit is applied by the query", func(t *testing.T) {
		start := time.Now()
		top, err := svc.Rounds().GetRoundSummaries(ctx, from, to, true, true, false, 20)
		elapsed := time.Since(start)
		require.NoError(t, err)
		t.Logf("GetRoundSummaries limit=20 over %d rounds: %s", rounds, elapsed)

		// Exactly the limit, and the most recent ones. A limit applied in Go
		// after loading everything would still pass this, which is what the
		// ceiling is for.
		require.Len(t, top, 20)
		require.Equal(t, summaries[0].RoundId, top[0].RoundId)
		require.Less(t, elapsed, ceiling)
	})

	t.Run("only_failed is a query-level filter", func(t *testing.T) {
		failed, err := svc.Rounds().GetRoundSummaries(ctx, from, to, true, true, true, 0)
		require.NoError(t, err)
		require.Empty(t, failed)
	})
}

func BenchmarkGetRoundSummaries(b *testing.B) {
	const rounds = 500
	svc := newBenchRepo(b)
	defer svc.Close()

	base := time.Now().Add(-24 * time.Hour).Unix()
	seedRounds(b, svc, rounds, 4, base)

	ctx := context.Background()
	from, to := base-1, base+int64(rounds)+1

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.Rounds().GetRoundSummaries(ctx, from, to, true, true, false, 0); err != nil {
			b.Fatal(err)
		}
	}
}

// seedRounds writes n finalized rounds, each carrying intentsPerRound intents so
// the per-round hydration cost is realistic rather than an empty-row best case.
func seedRounds(t testing.TB, svc ports.RepoManager, n, intentsPerRound int, base int64) {
	t.Helper()
	ctx := context.Background()

	for i := 0; i < n; i++ {
		id := fmt.Sprintf("bench-round-%06d", i)
		txid := fmt.Sprintf("%064x", i+1)

		intents := make(map[string]domain.Intent, intentsPerRound)
		for j := 0; j < intentsPerRound; j++ {
			intentID := fmt.Sprintf("%s-intent-%03d", id, j)
			intents[intentID] = domain.Intent{
				Id:      intentID,
				Proof:   fmt.Sprintf("proof-%s", intentID),
				Message: fmt.Sprintf("msg-%s", intentID),
				Receivers: []domain.Receiver{{
					PubKey: fmt.Sprintf("%064x", j+1),
					Amount: 1000,
				}},
			}
		}

		round := domain.Round{
			Id:                 id,
			StartingTimestamp:  base + int64(i),
			EndingTimestamp:    base + int64(i) + 30,
			Stage:              domain.Stage{Code: int(domain.RoundFinalizationStage), Ended: true},
			Intents:            intents,
			CommitmentTxid:     txid,
			CommitmentTx:       "cHNidP8BAgQCAAAA",
			VtxoTreeExpiration: 604800,
			Version:            1,
			VtxoTree:           tree.FlatTxTree{},
			Connectors:         tree.FlatTxTree{},
		}
		require.NoError(t, svc.Rounds().AddOrUpdateRound(ctx, round))
	}
}

func newBenchRepo(t testing.TB) ports.RepoManager {
	t.Helper()
	svc, err := db.NewService(db.ServiceConfig{
		EventStoreType:   "badger",
		DataStoreType:    "sqlite",
		EventStoreConfig: []interface{}{"", nil},
		DataStoreConfig:  []interface{}{t.TempDir()},
		Settings:         validSettings(),
	}, nil)
	require.NoError(t, err)
	return svc
}
