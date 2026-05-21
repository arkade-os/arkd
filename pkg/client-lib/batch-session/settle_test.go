package batchsession

import (
	"context"
	"testing"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsessionhandler "github.com/arkade-os/arkd/pkg/client-lib/batch-session/handler"
	"github.com/stretchr/testify/require"
)

// testAddr is a valid regtest bech32 p2wpkh address taken from the
// arkd builder tests. Reused as a baseline `Receiver.To` whenever a
// parseable on-chain address is required.
const testAddr = "bcrt1qhhq55mut9easvrncy4se8q6vg3crlug7yj4j56"

func TestSettle(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*SettleArgs)
			errSubstr string
		}{
			{
				name:      "missing client",
				mutate:    func(a *SettleArgs) { a.Client = nil },
				errSubstr: "missing client",
			},
			{
				name:      "missing sign tx",
				mutate:    func(a *SettleArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx function",
			},
			{
				name: "missing funds to settle",
				mutate: func(a *SettleArgs) {
					a.Vtxos = nil
					a.BoardingUtxos = nil
				},
				errSubstr: "missing funds to settle",
			},
			{
				name:      "missing receiver",
				mutate:    func(a *SettleArgs) { a.ReceiverAddr = "" },
				errSubstr: "missing receiver",
			},
			{
				name:      "missing server info",
				mutate:    func(a *SettleArgs) { a.ServerInfo.Dust = 0 },
				errSubstr: "missing server info",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestSettleArgs(t)
				tc.mutate(&args)

				_, err := Settle(context.Background(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

// mockClient is the smallest non-nil clientlib.Client that satisfies validation.
// Validation rejects requests before any method on Client is invoked, so the
// embedded nil interface is sufficient.
type mockClient struct{ clientlib.Client }

// mockSignTx is a valid batch-session SignFn baseline used everywhere a
// non-nil signer is required without exercising the signing path.
func mockSignTx(context.Context, string) (string, error) { return "", nil }

// newTestSettleArgs returns a valid baseline SettleArgs. Tests in this file
// mutate a single field on the returned value to exercise the corresponding
// validation error from Settle's validator.
func newTestSettleArgs(t *testing.T) SettleArgs {
	t.Helper()

	return SettleArgs{
		Client:     mockClient{},
		ServerInfo: clientlib.Info{Dust: 1000, Network: "regtest"},
		SignTx:     batchsessionhandler.SignFn(mockSignTx),
		Vtxos: []clientlib.Vtxo{{
			Outpoint: clientlib.Outpoint{Txid: "deadbeef", VOut: 0},
			Amount:   10000,
		}},
		ReceiverAddr: "tark1qexample",
	}
}
