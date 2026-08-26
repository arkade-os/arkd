package batchsession_test

import (
	"context"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsession "github.com/arkade-os/arkd/pkg/client-lib/batch-session"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// testAddr is a valid regtest bech32 p2wpkh address taken from the
// arkd builder tests. Reused as a baseline `Receiver.To` whenever a
// parseable on-chain address is required.
const testAddr = "bcrt1qhhq55mut9easvrncy4se8q6vg3crlug7yj4j56"

// testForfeitPubKey is a real compressed pubkey hex; satisfies
// validateServerInfo's hex-decode + ParsePubKey checks.
var testForfeitPubKey = pubkey("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")

func TestSettle(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*batchsession.SettleArgs)
			errSubstr string
		}{
			{
				name:      "missing client",
				mutate:    func(a *batchsession.SettleArgs) { a.Client = nil },
				errSubstr: "missing client",
			},
			{
				name:      "missing sign tx",
				mutate:    func(a *batchsession.SettleArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx function",
			},
			{
				name: "missing funds to settle",
				mutate: func(a *batchsession.SettleArgs) {
					a.Vtxos = nil
					a.BoardingUtxos = nil
				},
				errSubstr: "missing funds to settle",
			},
			{
				name:      "missing receiver",
				mutate:    func(a *batchsession.SettleArgs) { a.ReceiverAddr = "" },
				errSubstr: "missing receiver",
			},
			{
				name:      "missing server info",
				mutate:    func(a *batchsession.SettleArgs) { a.ServerParams.Dust = 0 },
				errSubstr: "missing server info",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestSettleArgs(t)
				tc.mutate(&args)

				_, err := batchsession.Settle(t.Context(), args)
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
func newTestSettleArgs(t *testing.T) batchsession.SettleArgs {
	t.Helper()

	return batchsession.SettleArgs{
		Client:       mockClient{},
		ServerParams: clientlib.ServerParams{Dust: 1000, Network: arklib.BitcoinRegTest},
		SignTx:       clientlib.SignFn(mockSignTx),
		Vtxos: []clientlib.Vtxo{{
			Outpoint: clientlib.Outpoint{Txid: "deadbeef", VOut: 0},
			Amount:   10000,
		}},
		ReceiverAddr: "tark1qexample",
	}
}

func pubkey(str string) *btcec.PublicKey {
	buf, _ := hex.DecodeString(str)
	key, _ := btcec.ParsePubKey(buf)
	return key
}
