package batchsession

import (
	"context"
	"testing"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsessionhandler "github.com/arkade-os/arkd/pkg/client-lib/batch-session/handler"
	"github.com/stretchr/testify/require"
)

func TestBuildAndSignRegisterIntent(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*IntentArgs)
			errSubstr string
		}{
			{
				name: "missing funds",
				mutate: func(a *IntentArgs) {
					a.Vtxos = nil
					a.BoardingUtxos = nil
					a.Notes = nil
				},
				errSubstr: "missing funds",
			},
			{
				name:      "missing outputs",
				mutate:    func(a *IntentArgs) { a.Outputs = nil },
				errSubstr: "missing outputs",
			},
			{
				name:      "missing cosigners",
				mutate:    func(a *IntentArgs) { a.Cosigners = nil },
				errSubstr: "missing cosigners",
			},
			{
				name:      "missing sign tx",
				mutate:    func(a *IntentArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestIntentArgs()
				tc.mutate(&args)

				_, _, _, err := BuildAndSignRegisterIntent(context.Background(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

func TestBuildAndSignDeleteIntent(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*IntentArgs)
			errSubstr string
		}{
			{"missing funds", func(a *IntentArgs) {
				a.Vtxos = nil
				a.BoardingUtxos = nil
				a.Notes = nil
			}, "missing funds"},
			{"missing sign tx", func(a *IntentArgs) { a.SignTx = nil }, "missing sign tx"},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestIntentArgs()
				tc.mutate(&args)

				_, _, err := BuildAndSignDeleteIntent(context.Background(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

func TestBuildAndSignGetPendingTxIntent(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*IntentArgs)
			errSubstr string
		}{
			{"missing funds", func(a *IntentArgs) { a.Vtxos = nil }, "missing funds"},
			{"missing sign tx", func(a *IntentArgs) { a.SignTx = nil }, "missing sign tx"},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestIntentArgs()
				tc.mutate(&args)

				_, _, err := BuildAndSignGetPendingTxIntent(context.Background(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

// newTestIntentArgs returns a valid baseline IntentArgs suitable for
// BuildAndSignRegisterIntent (the strictest validator). Delete and
// GetPendingTx tests override or use a subset of the same baseline because
// their validators are looser.
func newTestIntentArgs() IntentArgs {
	return IntentArgs{
		BaseArgs: BaseArgs{
			Vtxos: []clientlib.Vtxo{{
				Outpoint: clientlib.Outpoint{Txid: "deadbeef", VOut: 0},
				Amount:   10000,
			}},
			Outputs: []clientlib.Receiver{{To: "tark1qexample", Amount: 10000}},
			SignTx:  batchsessionhandler.SignFn(mockSignTx),
		},
		Cosigners: []string{
			"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
		},
	}
}
