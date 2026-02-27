package application

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

const bitcoinBlockWeight = 4_000_000

func TestMaxAssetsPerVtxo(t *testing.T) {
	tests := []struct {
		maxTxWeight uint64
		threshold   float64
		expected    int
	}{
		{maxTxWeight: 0.01 * bitcoinBlockWeight, threshold: 0.5, expected: 111},
		{maxTxWeight: 0.1 * bitcoinBlockWeight, threshold: 0.5, expected: 1111},
		{maxTxWeight: 0.5 * bitcoinBlockWeight, threshold: 0.5, expected: 5556},
		{maxTxWeight: bitcoinBlockWeight, threshold: 0.5, expected: 11111},
		{maxTxWeight: 0.01 * bitcoinBlockWeight, threshold: 0.25, expected: 56},
		{maxTxWeight: 0, threshold: 0.5, expected: 0},
	}

	for _, test := range tests {
		t.Run(
			fmt.Sprintf("maxTxWeight_%d_threshold_%.2f", test.maxTxWeight, test.threshold),
			func(t *testing.T) {
				got := maxAssetsPerVtxo(test.maxTxWeight, test.threshold)
				require.Equal(t, test.expected, got)
			},
		)
	}
}
