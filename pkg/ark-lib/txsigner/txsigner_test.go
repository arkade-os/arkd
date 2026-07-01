package txsigner_test

import (
	"testing"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txsigner"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

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

func TestSignTapscriptInput(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	xonly := schnorr.SerializePubKey(priv.PubKey())

	// A real ark-lib multisig leaf gated by the signer's key.
	closure := arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{priv.PubKey()}}
	leafScript, err := closure.Script()
	require.NoError(t, err)

	pkScript := taprootPkScript(t, priv.PubKey())

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0x01}, Index: 0},
	})
	tx.AddTxOut(&wire.TxOut{Value: 99_000, PkScript: pkScript})

	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 100_000, PkScript: pkScript}
	ptx.Inputs[0].SighashType = txscript.SigHashDefault
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		Script:      leafScript,
		LeafVersion: txscript.BaseLeafVersion,
	}}

	fetcher, err := txsigner.BuildPrevoutFetcher(ptx)
	require.NoError(t, err)
	sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)

	require.NoError(t, txsigner.SignTapscriptInput(ptx, 0, priv, sigHashes))

	require.Len(t, ptx.Inputs[0].TaprootScriptSpendSig, 1)
	spend := ptx.Inputs[0].TaprootScriptSpendSig[0]
	require.Len(t, spend.Signature, 64)
	require.Equal(t, xonly, spend.XOnlyPubKey)
}

func TestSignTapscriptInputRejectsMissingLeaf(t *testing.T) {
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

	fetcher, err := txsigner.BuildPrevoutFetcher(ptx)
	require.NoError(t, err)
	sigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)

	err = txsigner.SignTapscriptInput(ptx, 0, priv, sigHashes)
	require.Error(t, err)
}

func TestBuildPrevoutFetcherErrorsOnMissingWitnessUtxo(t *testing.T) {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0x03}, Index: 0},
	})
	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	_, err = txsigner.BuildPrevoutFetcher(ptx)
	require.Error(t, err)
}
