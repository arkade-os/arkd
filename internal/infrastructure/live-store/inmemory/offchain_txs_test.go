package inmemorylivestore_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	inmemorylivestore "github.com/arkade-os/arkd/internal/infrastructure/live-store/inmemory"
	"github.com/stretchr/testify/require"
)

func TestOffChainTxStoreClaimOutpoints(t *testing.T) {
	ctx := context.Background()
	const ownerA, ownerB = "arktx-a", "arktx-b"

	t.Run("disjoint claim is fresh and visible via Includes", func(t *testing.T) {
		store := inmemorylivestore.NewOffChainTxStore()
		ops := []domain.Outpoint{outpoint("aa", 0), outpoint("bb", 1)}

		status, conflict, err := store.ClaimOutpoints(ctx, ownerA, ops)
		require.NoError(t, err)
		require.Nil(t, conflict)
		require.Equal(t, ports.ClaimFresh, status)

		for _, o := range ops {
			exists, err := store.Includes(ctx, o)
			require.NoError(t, err)
			require.True(t, exists)
		}
	})

	t.Run("same owner re-claim is idempotent", func(t *testing.T) {
		store := inmemorylivestore.NewOffChainTxStore()
		ops := []domain.Outpoint{outpoint("cc", 0)}

		status, _, err := store.ClaimOutpoints(ctx, ownerA, ops)
		require.NoError(t, err)
		require.Equal(t, ports.ClaimFresh, status)

		status, conflict, err := store.ClaimOutpoints(ctx, ownerA, ops)
		require.NoError(t, err)
		require.Nil(t, conflict)
		require.Equal(t, ports.ClaimAlreadyOwned, status)
	})

	t.Run("different owner conflicts, all-or-nothing", func(t *testing.T) {
		store := inmemorylivestore.NewOffChainTxStore()
		x, y := outpoint("dd", 0), outpoint("ee", 0)

		status, _, err := store.ClaimOutpoints(ctx, ownerA, []domain.Outpoint{x})
		require.NoError(t, err)
		require.Equal(t, ports.ClaimFresh, status)

		// ownerB claiming [x, y] must fail on x and register nothing, so y stays free.
		status, conflict, err := store.ClaimOutpoints(ctx, ownerB, []domain.Outpoint{x, y})
		require.NoError(t, err)
		require.Equal(t, ports.ClaimConflict, status)
		require.NotNil(t, conflict)
		require.Equal(t, x.String(), conflict.String())

		exists, err := store.Includes(ctx, y)
		require.NoError(t, err)
		require.False(t, exists, "y must not be registered when the batch conflicts on x")
	})

	t.Run("release is owner-scoped", func(t *testing.T) {
		store := inmemorylivestore.NewOffChainTxStore()
		x := outpoint("ff", 2)

		_, _, err := store.ClaimOutpoints(ctx, ownerA, []domain.Outpoint{x})
		require.NoError(t, err)

		// A different owner cannot release ownerA's claim.
		require.NoError(t, store.ReleaseOutpoints(ctx, ownerB, []domain.Outpoint{x}))
		exists, err := store.Includes(ctx, x)
		require.NoError(t, err)
		require.True(t, exists, "ownerB must not be able to release ownerA's claim")

		// The owner can, and releasing an absent outpoint is a no-op.
		require.NoError(t, store.ReleaseOutpoints(ctx, ownerA, []domain.Outpoint{x}))
		require.NoError(t, store.ReleaseOutpoints(ctx, ownerA, []domain.Outpoint{outpoint("99", 9)}))
		exists, err = store.Includes(ctx, x)
		require.NoError(t, err)
		require.False(t, exists)

		// Now free, another owner can claim it.
		status, _, err := store.ClaimOutpoints(ctx, ownerB, []domain.Outpoint{x})
		require.NoError(t, err)
		require.Equal(t, ports.ClaimFresh, status)
	})

	// Run under -race: exactly one of N distinct-owner claimers of the same
	// outpoint wins fresh, the rest conflict.
	t.Run("concurrent distinct owners, exactly one wins", func(t *testing.T) {
		store := inmemorylivestore.NewOffChainTxStore()
		x := outpoint("ab", 4)

		const n = 64
		var fresh, conflicts int64
		errs := make(chan error, n)
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			owner := ownerA + string(rune('0'+i%10)) + string(rune('a'+i/10))
			go func(owner string) {
				defer wg.Done()
				status, _, err := store.ClaimOutpoints(ctx, owner, []domain.Outpoint{x})
				if err != nil {
					errs <- err
					return
				}
				switch status {
				case ports.ClaimFresh:
					atomic.AddInt64(&fresh, 1)
				case ports.ClaimConflict:
					atomic.AddInt64(&conflicts, 1)
				}
			}(owner)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}

		require.Equal(t, int64(1), fresh, "exactly one distinct owner must win")
		require.Equal(t, int64(n-1), conflicts)
	})

	// Run under -race: N same-owner claimers of the same outpoint all succeed
	// (fresh or already-owned), never conflict.
	t.Run("concurrent same owner, none conflict", func(t *testing.T) {
		store := inmemorylivestore.NewOffChainTxStore()
		x := outpoint("cd", 5)

		const n = 64
		var conflicts int64
		errs := make(chan error, n)
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				status, _, err := store.ClaimOutpoints(ctx, ownerA, []domain.Outpoint{x})
				if err != nil {
					errs <- err
					return
				}
				if status == ports.ClaimConflict {
					atomic.AddInt64(&conflicts, 1)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}

		require.Equal(t, int64(0), conflicts, "same-owner claims must never conflict")
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
