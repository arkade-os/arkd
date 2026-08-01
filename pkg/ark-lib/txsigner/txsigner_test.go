package txsigner_test

import (
	"testing"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txsigner"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestTxSigner(t *testing.T) {
	t.Run("SignTapscriptInput", func(t *testing.T) {
		t.Run("signs the leaf and appends the spend sig", func(t *testing.T) {
			priv, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			xonly := schnorr.SerializePubKey(priv.PubKey())

			ptx := forfeitLikePsbt(t, priv, chainhash.Hash{0x01})

			fetcher, err := txutils.GetPrevOutputFetcher(ptx)
			require.NoError(t, err)
			sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)

			require.NoError(t, txsigner.SignTapscriptInput(ptx, 0, priv, sigHashes))

			require.Len(t, ptx.Inputs[0].TaprootScriptSpendSig, 1)
			spend := ptx.Inputs[0].TaprootScriptSpendSig[0]
			require.Len(t, spend.Signature, 64)
			require.Equal(t, xonly, spend.XOnlyPubKey)
		})

		t.Run("rejects an input without a leaf script", func(t *testing.T) {
			priv, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			pkScript := taprootPkScript(t, priv.PubKey())

			tx := wire.NewMsgTx(2)
			tx.AddTxIn(&wire.TxIn{
				PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0x02}, Index: 0},
			})
			ptx, err := psbt.NewFromUnsignedTx(tx)
			require.NoError(t, err)
			ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 100_000, PkScript: pkScript}

			fetcher, err := txutils.GetPrevOutputFetcher(ptx)
			require.NoError(t, err)
			sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)

			err = txsigner.SignTapscriptInput(ptx, 0, priv, sigHashes)
			require.Error(t, err)
		})
	})

	t.Run("ExtractFinalizedTx", func(t *testing.T) {
		t.Run("finalizes the tapscript input as a vtxo script", func(t *testing.T) {
			priv, err := btcec.NewPrivateKey()
			require.NoError(t, err)

			ptx := forfeitLikePsbt(t, priv, chainhash.Hash{0x03})

			fetcher, err := txutils.GetPrevOutputFetcher(ptx)
			require.NoError(t, err)
			sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)
			require.NoError(t, txsigner.SignTapscriptInput(ptx, 0, priv, sigHashes))

			txHex, err := txsigner.ExtractFinalizedTx(ptx)
			require.NoError(t, err)
			require.NotEmpty(t, txHex)
			require.NotEmpty(t, ptx.Inputs[0].FinalScriptWitness)
		})

		t.Run("rejects an input without a witness utxo", func(t *testing.T) {
			tx := wire.NewMsgTx(2)
			tx.AddTxIn(&wire.TxIn{
				PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0x04}, Index: 0},
			})
			ptx, err := psbt.NewFromUnsignedTx(tx)
			require.NoError(t, err)

			_, err = txsigner.ExtractFinalizedTx(ptx)
			require.Error(t, err)
		})
	})
}

// taprootPkScript returns a syntactically valid P2TR scriptPubKey for the given
// key. The signing primitive only needs a P2TR-shaped prevout; it does not
// verify that the script commits to the leaf, so this is sufficient for a unit
// test of SignTapscriptInput.
func taprootPkScript(t *testing.T, key *btcec.PublicKey) []byte {
	t.Helper()
	pkScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).AddData(schnorr.SerializePubKey(key)).Script()
	require.NoError(t, err)
	return pkScript
}

// forfeitLikePsbt builds a single-input psbt spending a real ark-lib multisig
// leaf gated by the given key.
func forfeitLikePsbt(t *testing.T, priv *btcec.PrivateKey, hash chainhash.Hash) *psbt.Packet {
	t.Helper()

	closure := arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{priv.PubKey()}}
	leafScript, err := closure.Script()
	require.NoError(t, err)

	pkScript := taprootPkScript(t, priv.PubKey())

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: hash, Index: 0}})
	tx.AddTxOut(&wire.TxOut{Value: 99_000, PkScript: pkScript})

	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 100_000, PkScript: pkScript}
	ptx.Inputs[0].SighashType = txscript.SigHashDefault
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		Script:       leafScript,
		LeafVersion:  txscript.BaseLeafVersion,
		ControlBlock: []byte{byte(txscript.BaseLeafVersion)},
	}}
	return ptx
}
