package batchsession_test

import (
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsession "github.com/arkade-os/arkd/pkg/client-lib/batch-session"
	"github.com/stretchr/testify/require"
)

func TestRedeemNotes(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*batchsession.RedeemNotesArgs)
			errSubstr string
		}{
			{
				name:      "missing client",
				mutate:    func(a *batchsession.RedeemNotesArgs) { a.Client = nil },
				errSubstr: "missing client",
			},
			{
				name:      "missing sign tx",
				mutate:    func(a *batchsession.RedeemNotesArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx function",
			},
			{
				name:      "missing server info",
				mutate:    func(a *batchsession.RedeemNotesArgs) { a.ServerParams.Network = arklib.Network{} },
				errSubstr: "missing server info",
			},
			{
				name:      "missing receiver",
				mutate:    func(a *batchsession.RedeemNotesArgs) { a.ReceiverAddr = "" },
				errSubstr: "missing receiver",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestRedeemNotesArgs()
				tc.mutate(&args)

				_, err := batchsession.RedeemNotes(t.Context(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

// newTestRedeemNotesArgs returns a valid baseline RedeemNotesArgs. Tests in
// this file mutate a single field on the returned value to exercise the
// corresponding validation error.
func newTestRedeemNotesArgs() batchsession.RedeemNotesArgs {
	return batchsession.RedeemNotesArgs{
		Client: mockClient{},
		SignTx: clientlib.SignFn(mockSignTx),
		ServerParams: clientlib.ServerParams{
			Network:        arklib.BitcoinRegTest,
			ForfeitPubKey:  testForfeitPubKey,
			ForfeitAddress: testAddr,
		},
		Notes:        []string{"somenote"},
		ReceiverAddr: "tark1qexample",
	}
}
