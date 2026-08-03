package sqlitedb

import (
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

// A caller-supplied txid list looks like it bounds GetOffchainTxs but does not:
// in withheld and private exposure an empty request is backfilled from the auth
// token's whitelist, which an unbounded vtxo chain walk builds. The txid path
// batches its queries, so without trimming between batches the accumulated set
// grows with the whitelist regardless of how small each query is.
func TestTrimToScanLimit(t *testing.T) {
	t.Run("under the limit is left alone", func(t *testing.T) {
		byTxid, order := offchainTxSet(t, 10)

		got := trimToScanLimit(byTxid, order)

		require.Len(t, got, 10)
		require.Len(t, byTxid, 10)
	})

	t.Run("exactly at the limit is left alone", func(t *testing.T) {
		byTxid, order := offchainTxSet(t, domain.OffchainTxsScanLimit)

		got := trimToScanLimit(byTxid, order)

		require.Len(t, got, domain.OffchainTxsScanLimit)
		require.Len(t, byTxid, domain.OffchainTxsScanLimit)
	})

	// The survivors must be the globally highest-ranked entries, not whichever
	// batch happened to arrive first, or paging over a large whitelist would
	// return an arbitrary slice of it.
	t.Run("over the limit keeps the top ranked and prunes the map", func(t *testing.T) {
		const extra = 250
		byTxid, order := offchainTxSet(t, domain.OffchainTxsScanLimit+extra)

		got := trimToScanLimit(byTxid, order)

		require.Len(t, got, domain.OffchainTxsScanLimit)
		require.Len(t, byTxid, domain.OffchainTxsScanLimit,
			"dropped entries must not be left behind in the map")

		// offchainTxSet assigns descending timestamps, so the highest ranked are
		// the earliest indexes and the tail is what should have been dropped.
		require.Equal(t, txidFor(0), got[0])
		require.Equal(t, txidFor(domain.OffchainTxsScanLimit-1), got[len(got)-1])

		missing := 0
		for _, txid := range got {
			if _, ok := byTxid[txid]; !ok {
				missing++
			}
		}
		require.Zero(t, missing, "every surviving txid must still be in the map")

		_, dropped := byTxid[txidFor(domain.OffchainTxsScanLimit)]
		require.False(t, dropped, "the first entry past the cap must be gone")
	})

	t.Run("ordering is restored before trimming", func(t *testing.T) {
		byTxid, order := offchainTxSet(t, domain.OffchainTxsScanLimit+5)
		// Reverse so the lowest ranked entries are encountered first, the shape
		// batching produces when a later batch holds newer txs.
		for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
			order[i], order[j] = order[j], order[i]
		}

		got := trimToScanLimit(byTxid, order)

		require.Len(t, got, domain.OffchainTxsScanLimit)
		require.Equal(t, txidFor(0), got[0],
			"the newest tx must survive even when it arrived last")
	})
}

// offchainTxSet builds n folded txs with strictly descending timestamps, so
// index 0 is the highest ranked under ORDER BY starting_timestamp DESC.
func offchainTxSet(t *testing.T, n int) (map[string]*domain.OffchainTx, []string) {
	t.Helper()
	byTxid := make(map[string]*domain.OffchainTx, n)
	order := make([]string, 0, n)
	for i := range n {
		txid := txidFor(i)
		byTxid[txid] = &domain.OffchainTx{
			ArkTxid:           txid,
			StartingTimestamp: int64(n - i),
		}
		order = append(order, txid)
	}
	return byTxid, order
}

func txidFor(i int) string {
	return fmt.Sprintf("%064x", i)
}
