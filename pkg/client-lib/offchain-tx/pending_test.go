package offchaintx

import (
	"context"
	"testing"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/stretchr/testify/require"
)

func TestFinalizePendingTxs(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*FinalizePendingTxsArgs)
			errSubstr string
		}{
			{
				name:      "missing client",
				mutate:    func(a *FinalizePendingTxsArgs) { a.Client = nil },
				errSubstr: "missing client",
			},
			{
				name:      "missing sign tx",
				mutate:    func(a *FinalizePendingTxsArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestFinalizePendingTxsArgs()
				tc.mutate(&args)

				_, err := FinalizePendingTxs(context.Background(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

// newTestFinalizePendingTxsArgs returns a valid baseline
// FinalizePendingTxsArgs. Tests mutate a single field on the returned value to
// exercise the corresponding validation error.
func newTestFinalizePendingTxsArgs() FinalizePendingTxsArgs {
	return FinalizePendingTxsArgs{
		Client: mockClient{},
		SignTx: mockSignTx,
		Vtxos: []clientlib.Vtxo{{
			Outpoint: clientlib.Outpoint{Txid: "deadbeef", VOut: 0},
			Amount:   10000,
		}},
	}
}
