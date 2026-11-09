package domain_test

import (
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

func TestNewVtxoFilter(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			name     string
			expected domain.VtxoFilter
		}{
			{"no filters", domain.VtxoFilter{}},
			{"spendable only", domain.VtxoFilter{SpendableOnly: true}},
			{"spent only", domain.VtxoFilter{SpentOnly: true}},
			{"recoverable only", domain.VtxoFilter{RecoverableOnly: true}},
			{"pending only", domain.VtxoFilter{PendingOnly: true}},
			{"renewable only", domain.VtxoFilter{RenewableOnly: true}},
			{"after only", domain.VtxoFilter{After: 10}},
			{"before only", domain.VtxoFilter{Before: 20}},
			{"after and before", domain.VtxoFilter{After: 10, Before: 11}},
			{
				"status filter and time range",
				domain.VtxoFilter{SpendableOnly: true, After: 10, Before: 20},
			},
		}
		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				filter, err := newVtxoFilterFrom(f.expected)
				require.NoError(t, err)
				require.Equal(t, f.expected, filter)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name        string
			filter      domain.VtxoFilter
			expectedErr string
		}{
			{
				name:        "spendable and renewable",
				filter:      domain.VtxoFilter{SpendableOnly: true, RenewableOnly: true},
				expectedErr: "mutually exclusive",
			},
			{
				name:        "spent and renewable",
				filter:      domain.VtxoFilter{SpentOnly: true, RenewableOnly: true},
				expectedErr: "mutually exclusive",
			},
			{
				name:        "recoverable and renewable",
				filter:      domain.VtxoFilter{RecoverableOnly: true, RenewableOnly: true},
				expectedErr: "mutually exclusive",
			},
			{
				name:        "pending and renewable",
				filter:      domain.VtxoFilter{PendingOnly: true, RenewableOnly: true},
				expectedErr: "mutually exclusive",
			},
			{
				name:        "spendable and spent",
				filter:      domain.VtxoFilter{SpendableOnly: true, SpentOnly: true},
				expectedErr: "mutually exclusive",
			},
			{
				name:        "negative after",
				filter:      domain.VtxoFilter{After: -1},
				expectedErr: "after and before must be greater than or equal to 0",
			},
			{
				name:        "negative before",
				filter:      domain.VtxoFilter{Before: -1},
				expectedErr: "after and before must be greater than or equal to 0",
			},
			{
				name:        "before equal to after",
				filter:      domain.VtxoFilter{After: 10, Before: 10},
				expectedErr: "before must be greater than after",
			},
			{
				name:        "before less than after",
				filter:      domain.VtxoFilter{After: 20, Before: 10},
				expectedErr: "before must be greater than after",
			},
		}
		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				filter, err := newVtxoFilterFrom(f.filter)
				require.ErrorContains(t, err, f.expectedErr)
				require.Zero(t, filter)
			})
		}
	})
}

func newVtxoFilterFrom(f domain.VtxoFilter) (domain.VtxoFilter, error) {
	return domain.NewVtxoFilter(
		f.SpendableOnly, f.SpentOnly, f.RecoverableOnly, f.PendingOnly, f.RenewableOnly,
		f.After, f.Before,
	)
}
