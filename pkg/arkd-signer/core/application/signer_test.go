package application_test

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/arkd-signer/core/application"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func tapscriptPsbt(t *testing.T, key *btcec.PrivateKey) string {
	t.Helper()

	closure := arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{key.PubKey()}}
	leafScript, err := closure.Script()
	require.NoError(t, err)

	// Build a real single-leaf taproot output so the PSBT (with its control
	// block) survives B64 round-tripping through the signer.
	tapLeaf := txscript.NewBaseTapLeaf(leafScript)
	tapTree := txscript.AssembleTaprootScriptTree(tapLeaf)
	internalKey := key.PubKey()
	ctrlBlock := tapTree.LeafMerkleProofs[0].ToControlBlock(internalKey)
	ctrlBytes, err := ctrlBlock.ToBytes()
	require.NoError(t, err)

	rootHash := tapTree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(internalKey, rootHash[:])
	pkScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).AddData(schnorr.SerializePubKey(outputKey)).Script()
	require.NoError(t, err)

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
		ControlBlock: ctrlBytes,
		Script:       leafScript,
		LeafVersion:  txscript.BaseLeafVersion,
	}}

	b64, err := ptx.B64Encode()
	require.NoError(t, err)
	return b64
}

func TestGetPubkey(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	svc := application.New(priv)

	got, err := svc.GetPubkey(context.Background())
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(priv.PubKey().SerializeCompressed()), got)
	require.True(t, svc.IsReady(context.Background()))
}

func TestSignTransactionTapscript(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	svc := application.New(priv)

	signed, err := svc.SignTransactionTapscript(
		context.Background(), tapscriptPsbt(t, priv), nil,
	)
	require.NoError(t, err)

	out, err := psbt.NewFromRawBytes(strings.NewReader(signed), true)
	require.NoError(t, err)
	require.Len(t, out.Inputs[0].TaprootScriptSpendSig, 1)
	require.Equal(t,
		schnorr.SerializePubKey(priv.PubKey()),
		out.Inputs[0].TaprootScriptSpendSig[0].XOnlyPubKey,
	)
}

func TestSignRejectsMissingWitnessUtxo(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	svc := application.New(priv)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0x02}, Index: 0},
	})
	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	b64, err := ptx.B64Encode()
	require.NoError(t, err)

	_, err = svc.SignTransactionTapscript(context.Background(), b64, nil)
	require.Error(t, err)
}
