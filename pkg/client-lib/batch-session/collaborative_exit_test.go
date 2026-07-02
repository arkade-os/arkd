package batchsession_test

import (
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsession "github.com/arkade-os/arkd/pkg/client-lib/batch-session"
	"github.com/stretchr/testify/require"
)

func TestCollaborativeExit(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*batchsession.CollaborativeExitArgs)
			errSubstr string
		}{
			{
				name:      "missing client",
				mutate:    func(a *batchsession.CollaborativeExitArgs) { a.Client = nil },
				errSubstr: "missing client",
			},
			{
				name:      "missing sign tx",
				mutate:    func(a *batchsession.CollaborativeExitArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx function",
			},
			{
				name:      "missing funds",
				mutate:    func(a *batchsession.CollaborativeExitArgs) { a.Vtxos = nil },
				errSubstr: "missing funds for collaborative exit",
			},
			{
				name:      "missing receiver address",
				mutate:    func(a *batchsession.CollaborativeExitArgs) { a.Receiver.To = "" },
				errSubstr: "missing receiver address",
			},
			{
				name:      "missing server info",
				mutate:    func(a *batchsession.CollaborativeExitArgs) { a.ServerParams.Network = arklib.Network{} },
				errSubstr: "missing server info",
			},
			{
				name:      "invalid receiver address",
				mutate:    func(a *batchsession.CollaborativeExitArgs) { a.Receiver.To = "not-a-real-address" },
				errSubstr: "invalid receiver address",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestCollaborativeExitArgs(t)
				tc.mutate(&args)

				_, err := batchsession.CollaborativeExit(t.Context(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

// newTestCollaborativeExitArgs returns a valid baseline CollaborativeExitArgs.
// Tests in this file mutate a single field on the returned value to exercise
// the corresponding validation error.
func newTestCollaborativeExitArgs(t *testing.T) batchsession.CollaborativeExitArgs {
	t.Helper()

	return batchsession.CollaborativeExitArgs{
		Client:       mockClient{},
		ServerParams: clientlib.ServerParams{Dust: 1000, Network: arklib.BitcoinRegTest},
		SignTx:       clientlib.SignFn(mockSignTx),
		Vtxos: []clientlib.Vtxo{{
			Outpoint: clientlib.Outpoint{Txid: "deadbeef", VOut: 0},
			Amount:   10000,
		}},
		Receiver: clientlib.Receiver{To: testAddr, Amount: 10000},
	}
}
