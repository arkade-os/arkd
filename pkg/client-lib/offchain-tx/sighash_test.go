package offchaintx

import (
	"context"
	"fmt"
	"strings"
	"testing"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/stretchr/testify/require"
)

// forbiddenSighashTypes are the types a malicious counterparty would declare to
// obtain a signature that doesn't commit to our outputs.
var forbiddenSighashTypes = []txscript.SigHashType{
	txscript.SigHashNone,
	txscript.SigHashSingle,
	txscript.SigHashNone | txscript.SigHashAnyOneCanPay,
	txscript.SigHashSingle | txscript.SigHashAnyOneCanPay,
}

// withSighashType re-encodes the given base64 psbt with the sighash type set on
// every input, mimicking a counterparty declaring it in its response.
func withSighashType(t *testing.T, tx string, sighashType txscript.SigHashType) string {
	t.Helper()
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	require.NoError(t, err)

	for i := range ptx.Inputs {
		ptx.Inputs[i].SighashType = sighashType
	}

	encoded, err := ptx.B64Encode()
	require.NoError(t, err)
	return encoded
}

// recordingClient records the txs handed to the signer so a test can assert a
// counterparty psbt never reached it.
type recordingClient struct {
	clientlib.Client
	signed    []string
	finalized bool
}

func (c *recordingClient) FinalizeTx(_ context.Context, _ string, _ []string) error {
	c.finalized = true
	return nil
}

func (c *recordingClient) signTx(_ context.Context, tx string) (string, error) {
	c.signed = append(c.signed, tx)
	return tx, nil
}

func TestVerifySignedTxSighashPolicy(t *testing.T) {
	txid := "1111111111111111111111111111111111111111111111111111111111111111"
	original := newTestVerifyPSBT(t, txid, 0, true, true)
	signers := getSigners(t)

	t.Run("forbidden", func(t *testing.T) {
		for _, sighashType := range forbiddenSighashTypes {
			t.Run(fmt.Sprintf("%#x", uint32(sighashType)), func(t *testing.T) {
				signed := withSighashType(t, original, sighashType)

				err := VerifySignedTx(original, signed, signers)
				require.ErrorContains(t, err, "forbidden sighash type")
			})
		}
	})

	// SIGHASH_ALL is allowed by the policy but is not what we built, so a
	// counterparty must not be able to swap it in either.
	t.Run("mismatch", func(t *testing.T) {
		signed := withSighashType(t, original, txscript.SigHashAll)

		err := VerifySignedTx(original, signed, signers)
		require.ErrorContains(t, err, "sighash type mismatch")
	})

	// The honest counterparty leaves the sighash type untouched: the policy must
	// let it through and fail later, on the missing signature.
	t.Run("allowed", func(t *testing.T) {
		signed := newTestVerifyPSBT(t, txid, 0, true, true)

		err := VerifySignedTx(original, signed, signers)
		require.ErrorContains(t, err, "signer signature not found")
	})
}

func TestVerifySignedCheckpointTxsSighashPolicy(t *testing.T) {
	txid := "1111111111111111111111111111111111111111111111111111111111111111"
	original := newTestVerifyPSBT(t, txid, 0, true, true)
	signers := getSigners(t)

	for _, sighashType := range forbiddenSighashTypes {
		t.Run(fmt.Sprintf("%#x", uint32(sighashType)), func(t *testing.T) {
			signed := withSighashType(t, original, sighashType)

			err := VerifySignedCheckpointTxs([]string{original}, []string{signed}, signers)
			require.ErrorContains(t, err, "forbidden sighash type")
		})
	}
}

func TestFinalizeTxSighashPolicy(t *testing.T) {
	txid := "1111111111111111111111111111111111111111111111111111111111111111"
	checkpoint := newTestVerifyPSBT(t, txid, 0, true, true)

	t.Run("forbidden", func(t *testing.T) {
		for _, sighashType := range forbiddenSighashTypes {
			t.Run(fmt.Sprintf("%#x", uint32(sighashType)), func(t *testing.T) {
				client := &recordingClient{}

				_, _, err := finalizeTx(
					context.Background(), client, client.signTx,
					clientlib.AcceptedOffchainTx{
						Txid:                txid,
						SignedCheckpointTxs: []string{withSighashType(t, checkpoint, sighashType)},
					},
				)
				require.ErrorContains(t, err, "forbidden sighash type")
				require.Empty(t, client.signed)
				require.False(t, client.finalized)
			})
		}
	})

	// unlike the submit path there is no locally built checkpoint to compare
	// against here, so anything but SIGHASH_DEFAULT is refused.
	t.Run("not default", func(t *testing.T) {
		for _, sighashType := range []txscript.SigHashType{
			txscript.SigHashAll,
			txscript.SigHashAll | txscript.SigHashAnyOneCanPay,
		} {
			t.Run(fmt.Sprintf("%#x", uint32(sighashType)), func(t *testing.T) {
				client := &recordingClient{}

				_, _, err := finalizeTx(
					context.Background(), client, client.signTx,
					clientlib.AcceptedOffchainTx{
						Txid:                txid,
						SignedCheckpointTxs: []string{withSighashType(t, checkpoint, sighashType)},
					},
				)
				require.ErrorContains(t, err, "expected SIGHASH_DEFAULT")
				require.Empty(t, client.signed)
				require.False(t, client.finalized)
			})
		}
	})
	t.Run("allowed", func(t *testing.T) {
		client := &recordingClient{}

		_, finalCheckpoints, err := finalizeTx(
			context.Background(), client, client.signTx,
			clientlib.AcceptedOffchainTx{
				Txid:                txid,
				SignedCheckpointTxs: []string{checkpoint},
			},
		)
		require.NoError(t, err)
		require.Equal(t, []string{checkpoint}, finalCheckpoints)
		require.Equal(t, []string{checkpoint}, client.signed)
		require.True(t, client.finalized)
	})
}
