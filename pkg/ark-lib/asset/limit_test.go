package asset

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)
	
const bitcoinBlockWeight = 4_000_000

func TestMaxAssetsPerVtxo(t *testing.T) {
	tests := []struct {
		maxTxWeight uint64
		expected    int
	}{
		{maxTxWeight: 0.01 * bitcoinBlockWeight, expected: 111},
		{maxTxWeight: 0.1 * bitcoinBlockWeight, expected: 1111},
		{maxTxWeight: 0.5 * bitcoinBlockWeight, expected: 5556},
		{maxTxWeight: bitcoinBlockWeight, expected: 11111},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("maxTxWeight: %d", test.maxTxWeight), func(t *testing.T) {
			got := MaxAssetsPerVtxo(test.maxTxWeight)
			require.Equal(t, test.expected, got)
		})
	}
}