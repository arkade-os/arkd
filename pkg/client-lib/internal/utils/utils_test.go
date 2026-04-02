package utils_test

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/stretchr/testify/require"
)

func TestFilterVtxosByExpiry(t *testing.T) {
	now := time.Now()

	const threshold int64 = 3 * 24 * 60 * 60 // 3 days in seconds

	vtxoExpiring1Day := types.VtxoWithTapTree{
		Vtxo: types.Vtxo{ExpiresAt: now.Add(24 * time.Hour)},
	}
	vtxoExpiring3Days := types.VtxoWithTapTree{
		Vtxo: types.Vtxo{ExpiresAt: now.Add(time.Duration(threshold) * time.Second)},
	}
	vtxoExpiring5Days := types.VtxoWithTapTree{
		Vtxo: types.Vtxo{ExpiresAt: now.Add(5 * 24 * time.Hour)},
	}
	vtxoAlreadyExpired := types.VtxoWithTapTree{
		Vtxo: types.Vtxo{ExpiresAt: now.Add(-1 * time.Hour)},
	}

	testCases := []struct {
		name     string
		vtxos    []types.VtxoWithTapTree
		expected []types.VtxoWithTapTree
	}{
		{
			name:     "vtxo expiring within threshold is kept",
			vtxos:    []types.VtxoWithTapTree{vtxoExpiring1Day},
			expected: []types.VtxoWithTapTree{vtxoExpiring1Day},
		},
		{
			name:     "vtxo expiring at exactly threshold boundary is kept",
			vtxos:    []types.VtxoWithTapTree{vtxoExpiring3Days},
			expected: []types.VtxoWithTapTree{vtxoExpiring3Days},
		},
		{
			name:     "vtxo expiring beyond threshold is excluded",
			vtxos:    []types.VtxoWithTapTree{vtxoExpiring5Days},
			expected: []types.VtxoWithTapTree{},
		},
		{
			name:     "already expired vtxo is kept",
			vtxos:    []types.VtxoWithTapTree{vtxoAlreadyExpired},
			expected: []types.VtxoWithTapTree{vtxoAlreadyExpired},
		},
		{
			name:     "mixed vtxos: only within-threshold ones are kept",
			vtxos:    []types.VtxoWithTapTree{vtxoExpiring1Day, vtxoExpiring5Days, vtxoAlreadyExpired},
			expected: []types.VtxoWithTapTree{vtxoExpiring1Day, vtxoAlreadyExpired},
		},
		{
			name:     "empty input returns empty result",
			vtxos:    []types.VtxoWithTapTree{},
			expected: []types.VtxoWithTapTree{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := utils.FilterVtxosByExpiry(tc.vtxos, threshold)
			require.Equal(t, tc.expected, got)
		})
	}
}
