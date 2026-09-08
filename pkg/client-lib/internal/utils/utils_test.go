package utils_test

import (
	"fmt"
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

func TestCoinSelect(t *testing.T) {
	t.Run("offchain", func(t *testing.T) {
		t.Run("with change amount", func(t *testing.T) {
			testCases := []struct {
				name            string
				vtxoAmounts     []uint64
				targetAmount    uint64
				dust            uint64
				minChangeAmount uint64
				expectedVtxos   int
				expectedChange  uint64
				expectedErr     string
			}{
				// A min change amount of 0 leaves the dust limit as the only
				// constraint on the change.
				{
					name:            "min change 0 accepts a change above dust",
					vtxoAmounts:     []uint64{1000, 1000, 1000},
					targetAmount:    500,
					dust:            330,
					minChangeAmount: 0,
					expectedVtxos:   1,
					expectedChange:  500,
				},
				{
					name:            "min change 0 selects another vtxo if the change is below dust",
					vtxoAmounts:     []uint64{1000, 1000, 1000},
					targetAmount:    800,
					dust:            330,
					minChangeAmount: 0,
					expectedVtxos:   2,
					expectedChange:  1200,
				},
				{
					name:            "min change 0 drops a change below dust if no vtxo is left",
					vtxoAmounts:     []uint64{1000},
					targetAmount:    900,
					dust:            330,
					minChangeAmount: 0,
					expectedVtxos:   1,
					expectedChange:  0,
				},
				{
					name:            "min change 0 keeps selecting vtxos until the change clears dust",
					vtxoAmounts:     []uint64{1000, 100, 100, 200},
					targetAmount:    950,
					dust:            330,
					minChangeAmount: 0,
					expectedVtxos:   4,
					expectedChange:  450,
				},
				{
					name:            "min change 0 accepts no change without selecting another vtxo",
					vtxoAmounts:     []uint64{1000, 1000},
					targetAmount:    1000,
					dust:            330,
					minChangeAmount: 0,
					expectedVtxos:   1,
					expectedChange:  0,
				},
				{
					name:            "min change 0 accepts a change of 1 sat if there is no dust limit",
					vtxoAmounts:     []uint64{1000},
					targetAmount:    999,
					dust:            0,
					minChangeAmount: 0,
					expectedVtxos:   1,
					expectedChange:  1,
				},

				// A min change amount of 1 only rules out a change of 0, which is
				// always accepted anyway, so it never binds.
				{
					name:            "min change 1 accepts a change of 1 sat",
					vtxoAmounts:     []uint64{1000},
					targetAmount:    999,
					dust:            0,
					minChangeAmount: 1,
					expectedVtxos:   1,
					expectedChange:  1,
				},
				{
					name:            "min change 1 accepts no change",
					vtxoAmounts:     []uint64{1000, 1000},
					targetAmount:    1000,
					dust:            330,
					minChangeAmount: 1,
					expectedVtxos:   1,
					expectedChange:  0,
				},
				{
					name:            "min change 1 is superseded by a higher dust limit",
					vtxoAmounts:     []uint64{1000, 1000, 1000},
					targetAmount:    800,
					dust:            330,
					minChangeAmount: 1,
					expectedVtxos:   2,
					expectedChange:  1200,
				},

				// A min change amount of 330 binds only when the dust limit is
				// lower.
				{
					name:            "min change 330 accepts a change equal to the min",
					vtxoAmounts:     []uint64{1000},
					targetAmount:    670,
					dust:            0,
					minChangeAmount: 330,
					expectedVtxos:   1,
					expectedChange:  330,
				},
				{
					name:            "min change 330 selects another vtxo if the change is below the min",
					vtxoAmounts:     []uint64{1000, 1000, 1000},
					targetAmount:    800,
					dust:            0,
					minChangeAmount: 330,
					expectedVtxos:   2,
					expectedChange:  1200,
				},

				// A min change amount of 1000 sits above the dust limit, so it is
				// the binding constraint.
				{
					name:            "min change 1000 selects another vtxo if the change is above dust but below the min",
					vtxoAmounts:     []uint64{1000, 1000, 1000},
					targetAmount:    500,
					dust:            330,
					minChangeAmount: 1000,
					expectedVtxos:   2,
					expectedChange:  1500,
				},
				{
					name:            "min change 1000 keeps selecting vtxos until the min is reached",
					vtxoAmounts:     []uint64{1000, 300, 300, 300},
					targetAmount:    900,
					dust:            330,
					minChangeAmount: 1000,
					expectedVtxos:   4,
					expectedChange:  1000,
				},
				{
					name:            "min change 1000 accepts no change",
					vtxoAmounts:     []uint64{1000, 1000},
					targetAmount:    1000,
					dust:            330,
					minChangeAmount: 1000,
					expectedVtxos:   1,
					expectedChange:  0,
				},
				{
					// the change is below both floors: it must not be silently
					// given up, since the caller asked for a min change amount.
					name:            "min change 330 fails if a change below dust cannot be lifted",
					vtxoAmounts:     []uint64{1000},
					targetAmount:    900,
					dust:            330,
					minChangeAmount: 330,
					expectedErr:     "min change amount",
				},
				{
					name:            "min change 1000 fails if the min cannot be reached",
					vtxoAmounts:     []uint64{1000},
					targetAmount:    500,
					dust:            330,
					minChangeAmount: 1000,
					expectedErr:     "min change amount",
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					vtxos := makeVtxos(tc.vtxoAmounts)
					outputs := []types.Receiver{{Amount: tc.targetAmount}}

					_, selectedVtxos, change, err := utils.CoinSelect(
						nil, vtxos, outputs, tc.dust, true, nil, tc.minChangeAmount,
					)

					if tc.expectedErr != "" {
						require.ErrorContains(t, err, tc.expectedErr)
						return
					}

					require.NoError(t, err)
					require.Len(t, selectedVtxos, tc.expectedVtxos)
					require.Equal(t, tc.expectedChange, change)
				})
			}
		})
	})
}

func makeVtxos(amounts []uint64) []types.VtxoWithTapTree {
	vtxos := make([]types.VtxoWithTapTree, 0, len(amounts))
	for i, amount := range amounts {
		vtxos = append(vtxos, types.VtxoWithTapTree{
			Vtxo: types.Vtxo{
				Outpoint: types.Outpoint{Txid: fmt.Sprintf("vtxo-%d", i)},
				Amount:   amount,
			},
		})
	}
	return vtxos
}
