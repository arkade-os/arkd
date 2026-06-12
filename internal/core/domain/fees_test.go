package domain_test

import (
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

func TestBatchFees(t *testing.T) {
	testValidateBatchFees(t)

	testUpdateBatchFees(t)

	testNewBatchFees(t)
}

func testValidateBatchFees(t *testing.T) {
	t.Run("Validate", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			// empty programs disable fees and are valid
			empty := domain.BatchFees{}
			require.NoError(t, empty.Validate())

			fees := domain.BatchFees{
				OnchainInputFee:   "0.0",
				OffchainInputFee:  "0.0",
				OnchainOutputFee:  "0.0",
				OffchainOutputFee: "0.0",
			}
			require.NoError(t, fees.Validate())
		})

		t.Run("invalid", func(t *testing.T) {
			// syntax error
			badSyntax := domain.BatchFees{OnchainInputFee: "1 +"}
			require.Error(t, badSyntax.Validate())

			// compiles but returns the wrong type (must be a double)
			badType := domain.BatchFees{OffchainOutputFee: "true"}
			require.Error(t, badType.Validate())
		})
	})
}

func testUpdateBatchFees(t *testing.T) {
	t.Run("Update", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			fees := domain.BatchFees{}
			fee := "0.0"

			require.NoError(t, fees.Update(domain.BatchFeesUpdate{OnchainInputFee: &fee}))
			require.Equal(t, "0.0", fees.OnchainInputFee)
		})

		t.Run("invalid update leaves fees untouched", func(t *testing.T) {
			fees := domain.BatchFees{OnchainInputFee: "0.0"}
			badFee := "1 +"

			require.Error(t, fees.Update(domain.BatchFeesUpdate{OffchainOutputFee: &badFee}))
			require.Equal(t, domain.BatchFees{OnchainInputFee: "0.0"}, fees)
		})
	})
}

func testNewBatchFees(t *testing.T) {
	t.Run("NewBatchFees", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			fees, err := domain.NewBatchFees("0.0", "0.0", "0.0", "0.0")
			require.NoError(t, err)
			require.NotNil(t, fees)
		})

		t.Run("invalid", func(t *testing.T) {
			fees, err := domain.NewBatchFees("1 +", "", "", "")
			require.Error(t, err)
			require.Nil(t, fees)
		})
	})
}
