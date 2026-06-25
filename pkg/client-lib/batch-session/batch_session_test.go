package batchsession

import (
	"context"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/stretchr/testify/require"
)

func TestJoinBatch(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*JoinBatchArgs)
			errSubstr string
		}{
			{
				name:      "missing client",
				mutate:    func(a *JoinBatchArgs) { a.Client = nil },
				errSubstr: "missing client",
			},
			{
				name: "missing funds",
				mutate: func(a *JoinBatchArgs) {
					a.Vtxos = nil
					a.BoardingUtxos = nil
					a.Notes = nil
				},
				errSubstr: "missing funds to join a batch",
			},
			{
				name:      "missing outputs",
				mutate:    func(a *JoinBatchArgs) { a.Outputs = nil },
				errSubstr: "missing outputs",
			},
			{
				name:      "missing intent id",
				mutate:    func(a *JoinBatchArgs) { a.IntentId = "" },
				errSubstr: "missing intent id",
			},
			{
				name:      "missing tree signers",
				mutate:    func(a *JoinBatchArgs) { a.TreeSigners = nil },
				errSubstr: "missing tree signer(s)",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestJoinBatchArgs(t)
				tc.mutate(&args)

				_, err := JoinBatch(context.Background(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

// newTestJoinBatchArgs returns a valid baseline JoinBatchArgs. Tests in this
// file mutate a single field on the returned value to exercise the
// corresponding validation error.
func newTestJoinBatchArgs(t *testing.T) JoinBatchArgs {
	t.Helper()
	signer, err := tree.NewVtxoTreeSigner()
	require.NoError(t, err)
	return JoinBatchArgs{
		BaseArgs: BaseArgs{
			Vtxos: []clientlib.Vtxo{{
				Outpoint: clientlib.Outpoint{Txid: "deadbeef", VOut: 0},
				Amount:   10000,
			}},
			Outputs: []clientlib.Receiver{{To: "tark1qexample", Amount: 10000}},
			SignTx:  clientlib.SignFn(mockSignTx),
		},
		Client:       mockClient{},
		ServerParams: clientlib.ServerParams{Network: arklib.BitcoinRegTest, Dust: 1000},
		IntentId:     "test-intent-id",
		TreeSigners:  []tree.SignerSession{signer},
	}
}
