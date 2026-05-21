package offchaintx

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// newTestVerifyPSBT builds a minimal base64-encoded PSBT with one input
// referencing the given outpoint plus the supplied witness data on its input
// and an attached TaprootLeafScript. It is used by the verify tests to
// exercise the structural paths of VerifySignedTx /
// VerifySignedCheckpointTxs without crafting actual Schnorr signatures.
func newTestVerifyPSBT(
	t *testing.T, prevTxidHex string, prevVOut uint32, withLeafScript, withWitnessUtxo bool,
) string {
	t.Helper()
	tx := wire.NewMsgTx(2)
	hash, err := chainhash.NewHashFromStr(prevTxidHex)
	require.NoError(t, err)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(hash, prevVOut),
		Sequence:         wire.MaxTxInSequenceNum,
	})
	tx.AddTxOut(wire.NewTxOut(330, []byte{0x51, 0x02, 0x4e, 0x73}))

	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	if withWitnessUtxo {
		ptx.Inputs[0].WitnessUtxo = &wire.TxOut{
			Value:    1000,
			PkScript: []byte{0x51, 0x02, 0x4e, 0x73},
		}
	}
	if withLeafScript {
		// A minimal-but-valid control block: leaf version byte + 32-byte
		// internal pubkey. The internal pubkey value is arbitrary because the
		// verify path that consumes it ("missing signer signature") never
		// reaches actual script execution.
		controlBlock := make([]byte, 33)
		controlBlock[0] = byte(txscript.BaseLeafVersion)
		for i := 1; i < 33; i++ {
			controlBlock[i] = 0x01
		}
		ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
			ControlBlock: controlBlock,
			Script:       []byte{0x51},
			LeafVersion:  txscript.BaseLeafVersion,
		}}
	}

	encoded, err := ptx.B64Encode()
	require.NoError(t, err)
	return encoded
}

// signerPubKey parses the canonical testSignerPubKey constant.
func signerPubKey(t *testing.T) *btcec.PublicKey {
	t.Helper()
	key, err := parsePubkey(testSignerPubKey)
	require.NoError(t, err)
	return key
}

func TestVerifySignedTx(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		txidA := "1111111111111111111111111111111111111111111111111111111111111111"
		txidB := "2222222222222222222222222222222222222222222222222222222222222222"

		validOriginal := newTestVerifyPSBT(t, txidA, 0, true, true)
		validSigned := newTestVerifyPSBT(t, txidA, 0, true, true)
		differentTxid := newTestVerifyPSBT(t, txidB, 0, true, true)

		tests := []struct {
			name      string
			original  string
			signed    string
			errSubstr string
		}{
			{"bad original psbt", "!!not-psbt", validSigned, ""},
			{"bad signed psbt", validOriginal, "!!not-psbt", ""},
			{"txid mismatch", validOriginal, differentTxid, "txids mismatch"},
			{"missing signer signature", validOriginal, validSigned, "signer signature not found"},
		}

		pubKey := signerPubKey(t)
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				err := VerifySignedTx(tc.original, tc.signed, pubKey)
				require.Error(t, err)
				if tc.errSubstr != "" {
					require.Contains(t, err.Error(), tc.errSubstr)
				}
			})
		}
	})
}

func TestVerifySignedCheckpointTxs(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		txidA := "1111111111111111111111111111111111111111111111111111111111111111"
		txidB := "2222222222222222222222222222222222222222222222222222222222222222"

		validOriginal := newTestVerifyPSBT(t, txidA, 0, true, true)
		differentTxid := newTestVerifyPSBT(t, txidB, 0, true, true)

		tests := []struct {
			name      string
			original  []string
			signed    []string
			errSubstr string
		}{
			{
				name:     "bad original element",
				original: []string{"!!not-psbt"},
				signed:   []string{validOriginal},
			},
			{
				name:     "bad signed element",
				original: []string{validOriginal},
				signed:   []string{"!!not-psbt"},
			},
			{
				name:      "signed checkpoint missing for original txid",
				original:  []string{validOriginal},
				signed:    []string{differentTxid},
				errSubstr: "not found",
			},
		}

		pubKey := signerPubKey(t)
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				err := VerifySignedCheckpointTxs(tc.original, tc.signed, pubKey)
				require.Error(t, err)
				if tc.errSubstr != "" {
					require.Contains(t, err.Error(), tc.errSubstr)
				}
			})
		}
	})
}
