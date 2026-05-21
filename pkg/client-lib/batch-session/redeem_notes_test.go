package batchsession

import (
	"context"
	"testing"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsessionhandler "github.com/arkade-os/arkd/pkg/client-lib/batch-session/handler"
	"github.com/stretchr/testify/require"
)

func TestRedeemNotes(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name      string
			mutate    func(*RedeemNotesArgs)
			errSubstr string
		}{
			{
				name:      "missing client",
				mutate:    func(a *RedeemNotesArgs) { a.Client = nil },
				errSubstr: "missing client",
			},
			{
				name:      "missing sign tx",
				mutate:    func(a *RedeemNotesArgs) { a.SignTx = nil },
				errSubstr: "missing sign tx function",
			},
			{
				name:      "missing server info",
				mutate:    func(a *RedeemNotesArgs) { a.ServerInfo.Network = "" },
				errSubstr: "missing server info",
			},
			{
				name:      "missing receiver",
				mutate:    func(a *RedeemNotesArgs) { a.ReceiverAddr = "" },
				errSubstr: "missing receiver",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestRedeemNotesArgs()
				tc.mutate(&args)

				_, err := RedeemNotes(context.Background(), args)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errSubstr)
			})
		}
	})
}

// newTestRedeemNotesArgs returns a valid baseline RedeemNotesArgs. Tests in
// this file mutate a single field on the returned value to exercise the
// corresponding validation error.
func newTestRedeemNotesArgs() RedeemNotesArgs {
	return RedeemNotesArgs{
		Client:       mockClient{},
		SignTx:       batchsessionhandler.SignFn(mockSignTx),
		ServerInfo:   clientlib.Info{Network: "regtest"},
		Notes:        []string{"somenote"},
		ReceiverAddr: "tark1qexample",
	}
}
