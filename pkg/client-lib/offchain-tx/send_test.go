package offchaintx

import (
	"context"
	"encoding/hex"
	"testing"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// testSignerPubKey is a real compressed pubkey hex used so that parsePubkey()
// succeeds when a test is not exercising the pubkey error path. Reused across
// every offchain-tx invalid-path test file.
var testSignerPubKey = pubkey("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")

func TestSend(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*SendArgs)
			errSubstr string
		}{
			{
				name:      "missing client",
				mutate:    func(a *SendArgs) { a.Client = nil },
				errSubstr: "missing client",
			},
			{
				name:      "missing receivers",
				mutate:    func(a *SendArgs) { a.Receivers = nil },
				errSubstr: "missing receivers",
			},
			{
				name:      "missing sign tx",
				mutate:    func(a *SendArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx",
			},
			{
				name:      "missing server info",
				mutate:    func(a *SendArgs) { a.ServerParams.Dust = 0 },
				errSubstr: "missing server info",
			},
			{
				name:      "missing signer pubkey",
				mutate:    func(a *SendArgs) { a.ServerParams.SignerPubKey = nil },
				errSubstr: "missing signer pubkey",
			},
			{
				name:      "missing change addr",
				mutate:    func(a *SendArgs) { a.ChangeAddr = "" },
				errSubstr: "missing change address",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestSendArgs()
				tc.mutate(&args)

				_, err := Send(context.Background(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

func TestBuildAndSignTx(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*BuildAndSignTxArgs)
			errSubstr string
		}{
			{
				name:      "missing receivers",
				mutate:    func(a *BuildAndSignTxArgs) { a.Receivers = nil },
				errSubstr: "missing receivers",
			},
			{
				name:      "missing sign tx",
				mutate:    func(a *BuildAndSignTxArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx",
			},
			{
				name:      "missing server info",
				mutate:    func(a *BuildAndSignTxArgs) { a.ServerParams.Dust = 0 },
				errSubstr: "missing server info",
			},
			{
				name:      "missing signer pubkey",
				mutate:    func(a *BuildAndSignTxArgs) { a.ServerParams.SignerPubKey = nil },
				errSubstr: "missing signer pubkey",
			},
			{
				name:      "missing change addr",
				mutate:    func(a *BuildAndSignTxArgs) { a.ChangeAddr = "" },
				errSubstr: "missing change address",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestSendBuildArgs()
				tc.mutate(&args)

				_, err := BuildAndSignTx(context.Background(), args)
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

// mockSignTx is a valid SignFn baseline used everywhere a non-nil signer is
// required without exercising the signing path.
func mockSignTx(context.Context, string) (string, error) { return "", nil }

// newTestSendArgs returns a valid baseline SendArgs. Tests in this file mutate
// a single field on the returned value to exercise the corresponding
// validation error.
func newTestSendArgs() SendArgs {
	b := newTestSendBuildArgs()
	return SendArgs{
		Client:       mockClient{},
		ServerParams: b.ServerParams,
		SignTx:       b.SignTx,
		Vtxos:        b.Vtxos,
		ChangeAddr:   b.ChangeAddr,
		Receivers:    b.Receivers,
	}
}

// newTestSendBuildArgs returns a valid baseline BuildTxArgs. Tests mutate a
// single field on the returned value to exercise the corresponding validation
// error from BuildAndSignTx.
func newTestSendBuildArgs() BuildAndSignTxArgs {
	return BuildAndSignTxArgs{
		BaseArgs: BaseArgs{
			ServerParams: clientlib.ServerParams{Dust: 1000, SignerPubKey: testSignerPubKey},
			SignTx:       mockSignTx,
			ChangeAddr:   "tark1qexample",
		},
		Receivers: []clientlib.Receiver{{To: "tark1qexample", Amount: 10000}},
	}
}

func pubkey(str string) *btcec.PublicKey {
	buf, _ := hex.DecodeString(str)
	key, _ := btcec.ParsePubKey(buf)
	return key
}
