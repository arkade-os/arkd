package batchsession

import (
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/stretchr/testify/require"
)

func TestFilterVtxosByExpiry(t *testing.T) {
	now := time.Now()

	const threshold int64 = 3 * 24 * 60 * 60 // 3 days in seconds

	vtxoExpiring1Day := clientlib.Vtxo{ExpiresAt: now.Add(24 * time.Hour)}
	vtxoExpiring3Days := clientlib.Vtxo{ExpiresAt: now.Add(time.Duration(threshold) * time.Second)}
	vtxoExpiring5Days := clientlib.Vtxo{ExpiresAt: now.Add(5 * 24 * time.Hour)}
	vtxoAlreadyExpired := clientlib.Vtxo{ExpiresAt: now.Add(-1 * time.Hour)}

	testCases := []struct {
		name     string
		vtxos    []clientlib.Vtxo
		expected []clientlib.Vtxo
	}{
		{
			name:     "vtxo expiring within threshold is kept",
			vtxos:    []clientlib.Vtxo{vtxoExpiring1Day},
			expected: []clientlib.Vtxo{vtxoExpiring1Day},
		},
		{
			name:     "vtxo expiring at exactly threshold boundary is kept",
			vtxos:    []clientlib.Vtxo{vtxoExpiring3Days},
			expected: []clientlib.Vtxo{vtxoExpiring3Days},
		},
		{
			name:     "vtxo expiring beyond threshold is excluded",
			vtxos:    []clientlib.Vtxo{vtxoExpiring5Days},
			expected: []clientlib.Vtxo{},
		},
		{
			name:     "already expired vtxo is kept",
			vtxos:    []clientlib.Vtxo{vtxoAlreadyExpired},
			expected: []clientlib.Vtxo{vtxoAlreadyExpired},
		},
		{
			name:     "mixed vtxos: only within-threshold ones are kept",
			vtxos:    []clientlib.Vtxo{vtxoExpiring1Day, vtxoExpiring5Days, vtxoAlreadyExpired},
			expected: []clientlib.Vtxo{vtxoExpiring1Day, vtxoAlreadyExpired},
		},
		{
			name:     "empty input returns empty result",
			vtxos:    []clientlib.Vtxo{},
			expected: []clientlib.Vtxo{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterVtxosByExpiry(tc.vtxos, threshold)
			require.Equal(t, tc.expected, got)
		})
	}
}
