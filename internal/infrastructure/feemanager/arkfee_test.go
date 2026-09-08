package feemanager

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

// TestToArkFeeOffchainInputExpiry pins how a vtxo's expiry reaches the fee
// expression. OffchainInput treats the zero time as "no expiry" and omits the
// CEL variable entirely, which is the only honest representation for a vtxo with
// no batch behind it. Converting its zero ExpiresAt with time.Unix would instead
// hand the expression a 1970 deadline, which is not zero and not true.
func TestToArkFeeOffchainInputExpiry(t *testing.T) {
	const expiresAt = int64(2_000_000_000)

	t.Run("a batch vtxo carries its expiry through", func(t *testing.T) {
		got := toArkFeeOffchainInput(domain.Vtxo{
			Amount: 1000, ExpiresAt: expiresAt, CreatedAt: 1_900_000_000,
		})

		require.Equal(t, time.Unix(expiresAt, 0), got.Expiry)
		require.False(t, got.Expiry.IsZero())
	})

	t.Run("an onchain-kind vtxo carries no expiry at all", func(t *testing.T) {
		got := toArkFeeOffchainInput(domain.Vtxo{
			Kind: domain.VtxoKindOnchain, Amount: 1000, CreatedAt: 1_900_000_000,
		})

		require.True(t, got.Expiry.IsZero(), "the fee expression must see no expiry")
		require.NotEqual(t, time.Unix(0, 0), got.Expiry, "1970 is not the same as absent")
	})

	// The birth is real either way, so only the expiry is special-cased.
	t.Run("the birth is unaffected", func(t *testing.T) {
		got := toArkFeeOffchainInput(domain.Vtxo{
			Kind: domain.VtxoKindOnchain, CreatedAt: 1_900_000_000,
		})

		require.Equal(t, time.Unix(1_900_000_000, 0), got.Birth)
	})
}
