package application

import (
	"math"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

// TestBatchExpiryGuards covers the sites that read Vtxo.ExpiresAt directly
// rather than through IsExpired. A vtxo held in an on-chain Arkade UTXO has no
// batch and stores a zero, which is smaller than any real deadline and so wins
// every naive comparison against one.
func TestBatchExpiryGuards(t *testing.T) {
	const (
		soon = int64(2_000_000_000)
		late = int64(2_000_003_600)
	)

	t.Run("earliest batch expiry", func(t *testing.T) {
		t.Run("picks the soonest expiry and its commitment", func(t *testing.T) {
			expiry, txid, ok := earliestBatchExpiry([]domain.Vtxo{
				{ExpiresAt: late, RootCommitmentTxid: "late-batch"},
				{ExpiresAt: soon, RootCommitmentTxid: "soon-batch"},
			})

			require.True(t, ok)
			require.Equal(t, soon, expiry)
			require.Equal(t, "soon-batch", txid)
		})

		// The case this guard exists for. Without it the zero wins outright and
		// dates the resulting vtxo to the epoch, carrying the wrong commitment.
		t.Run("an onchain-kind input never wins the comparison", func(t *testing.T) {
			expiry, txid, ok := earliestBatchExpiry([]domain.Vtxo{
				{ExpiresAt: soon, RootCommitmentTxid: "soon-batch"},
				{Kind: domain.VtxoKindOnchain, ExpiresAt: 0, RootCommitmentTxid: ""},
			})

			require.True(t, ok)
			require.Equal(t, soon, expiry)
			require.Equal(t, "soon-batch", txid)
		})

		// The caller must reject this rather than pass it on. The expiry left
		// behind is MaxInt64, a far-future sentinel, and Accept only rejects an
		// expiry of zero or less, so it would be stored as if it were real.
		t.Run("only onchain-kind inputs reports nothing found", func(t *testing.T) {
			expiry, txid, ok := earliestBatchExpiry([]domain.Vtxo{
				{Kind: domain.VtxoKindOnchain},
				{Kind: domain.VtxoKindOnchain},
			})

			require.False(t, ok)
			require.Equal(t, int64(math.MaxInt64), expiry)
			require.Empty(t, txid)
		})

		t.Run("no inputs reports nothing found", func(t *testing.T) {
			expiry, txid, ok := earliestBatchExpiry(nil)

			require.False(t, ok)
			require.Equal(t, int64(math.MaxInt64), expiry)
			require.Empty(t, txid)
		})

		// A batch-backed input with a zero expiry is still a batch-backed input.
		// The report must key off the kind, not off the number being non-zero.
		t.Run("a zero expiry on a batch vtxo still counts as found", func(t *testing.T) {
			expiry, txid, ok := earliestBatchExpiry([]domain.Vtxo{
				{ExpiresAt: 0, RootCommitmentTxid: "batch"},
			})

			require.True(t, ok)
			require.Zero(t, expiry)
			require.Equal(t, "batch", txid)
		})
	})

	t.Run("settlement expiry gap", func(t *testing.T) {
		limit := time.Unix(soon, 0)

		t.Run("a vtxo expiring after the limit exceeds it", func(t *testing.T) {
			require.True(t, exceedsSettlementExpiryGap(domain.Vtxo{ExpiresAt: late}, limit))
		})

		t.Run("a vtxo expiring before the limit does not", func(t *testing.T) {
			require.False(t, exceedsSettlementExpiryGap(
				domain.Vtxo{ExpiresAt: soon - 1}, limit,
			))
		})

		// Pins the outcome, not the guard: a zero already fails this comparison,
		// so this passes with or without the early return. It is here so that
		// reversing the comparison later fails a test instead of silently
		// rejecting on-chain vtxos.
		t.Run("an onchain-kind vtxo never exceeds it", func(t *testing.T) {
			require.False(t, exceedsSettlementExpiryGap(
				domain.Vtxo{Kind: domain.VtxoKindOnchain, ExpiresAt: 0}, limit,
			))
		})
	})
}
