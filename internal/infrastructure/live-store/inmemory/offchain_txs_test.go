package inmemorylivestore_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	inmemorylivestore "github.com/arkade-os/arkd/internal/infrastructure/live-store/inmemory"
	"github.com/stretchr/testify/require"
)

func TestOffChainTxStoreClaimOutpoints(t *testing.T) {
	ctx := context.Background()

	t.Run("disjoint claim succeeds and is visible via Includes", func(t *testing.T) {
		store := inmemorylivestore.NewOffChainTxStore()
		ops := []domain.Outpoint{outpoint("aa", 0), outpoint("bb", 1)}

		conflict, err := store.ClaimOutpoints(ctx, ops)
		require.NoError(t, err)
		require.Nil(t, conflict)

		for _, o := range ops {
			exists, err := store.Includes(ctx, o)
			require.NoError(t, err)
			require.True(t, exists)
		}
	})

	t.Run("conflicting claim is all-or-nothing", func(t *testing.T) {
		store := inmemorylivestore.NewOffChainTxStore()
		x, y := outpoint("cc", 0), outpoint("dd", 0)

		conflict, err := store.ClaimOutpoints(ctx, []domain.Outpoint{x})
		require.NoError(t, err)
		require.Nil(t, conflict)

		// Claiming [x, y] must fail on x and register nothing new, so y stays free.
		conflict, err = store.ClaimOutpoints(ctx, []domain.Outpoint{x, y})
		require.NoError(t, err)
		require.NotNil(t, conflict)
		require.Equal(t, x.String(), conflict.String())

		exists, err := store.Includes(ctx, y)
		require.NoError(t, err)
		require.False(t, exists, "y must not be registered when the batch conflicts on x")
	})

	t.Run("release makes an outpoint claimable again", func(t *testing.T) {
		store := inmemorylivestore.NewOffChainTxStore()
		x := outpoint("ee", 2)

		_, err := store.ClaimOutpoints(ctx, []domain.Outpoint{x})
		require.NoError(t, err)

		require.NoError(t, store.ReleaseOutpoints(ctx, []domain.Outpoint{x}))
		exists, err := store.Includes(ctx, x)
		require.NoError(t, err)
		require.False(t, exists)

		// Releasing an absent outpoint is a no-op.
		require.NoError(t, store.ReleaseOutpoints(ctx, []domain.Outpoint{outpoint("ff", 9)}))

		conflict, err := store.ClaimOutpoints(ctx, []domain.Outpoint{x})
		require.NoError(t, err)
		require.Nil(t, conflict)
	})

	// Run under -race: exactly one of N concurrent claimers of the same
	// outpoint wins, the rest see it as a conflict.
	t.Run("concurrent claimers, exactly one wins", func(t *testing.T) {
		store := inmemorylivestore.NewOffChainTxStore()
		x := outpoint("ab", 4)

		const n = 64
		var wins, conflicts int64
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				conflict, err := store.ClaimOutpoints(ctx, []domain.Outpoint{x})
				require.NoError(t, err)
				if conflict == nil {
					atomic.AddInt64(&wins, 1)
				} else {
					atomic.AddInt64(&conflicts, 1)
				}
			}()
		}
		wg.Wait()

		require.Equal(t, int64(1), wins, "exactly one claimer must win")
		require.Equal(t, int64(n-1), conflicts)
	})
}

// outpoint builds a valid domain.Outpoint from a short hex seed, padded to a
// 64-char txid so it round-trips through Outpoint.FromString on the redis path.
func outpoint(seed string, vout uint32) domain.Outpoint {
	txid := seed
	for len(txid) < 64 {
		txid += "0"
	}
	return domain.Outpoint{Txid: txid[:64], VOut: vout}
}
