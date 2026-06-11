package wallet

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/arkd-wallet/core/application"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestSignTransactionUsesDeprecatedKey makes sure SignTransaction API supports old deprecated key
func TestSignTransactionUsesDeprecatedKey(t *testing.T) {
	owner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	current, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	old, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	w := &wallet{WalletOptions: WalletOptions{
		SignerKey:            current,
		DeprecatedSignerKeys: []DeprecatedSignerKey{{Key: old}},
	}}

	leaf := leafScript(t, owner.PubKey(), old.PubKey())
	tapLeaf := txscript.NewBaseTapLeaf(leaf)
	tapTree := txscript.AssembleTaprootScriptTree(tapLeaf)
	rootHash := tapTree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(owner.PubKey(), rootHash[:])
	pkScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).AddData(schnorr.SerializePubKey(outputKey)).Script()
	require.NoError(t, err)

	ctrlBlock := tapTree.LeafMerkleProofs[0].ToControlBlock(owner.PubKey())
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	require.NoError(t, err)

	prevHash, err := chainhash.NewHashFromStr(
		"0000000000000000000000000000000000000000000000000000000000000001")
	require.NoError(t, err)
	prevOut := wire.OutPoint{Hash: *prevHash, Index: 0}
	unsigned := wire.NewMsgTx(2)
	unsigned.AddTxIn(wire.NewTxIn(&prevOut, nil, nil))
	unsigned.AddTxOut(&wire.TxOut{Value: 900, PkScript: pkScript})

	packet, err := psbt.NewFromUnsignedTx(unsigned)
	require.NoError(t, err)
	packet.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 1000, PkScript: pkScript}
	packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: ctrlBlockBytes,
		Script:       leaf,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	b64, err := packet.B64Encode()
	require.NoError(t, err)

	signed, err := w.SignTransaction(
		context.Background(), application.SignModeSigner, b64, false, nil)
	require.NoError(t, err)

	out, err := psbt.NewFromRawBytes(strings.NewReader(signed), true)
	require.NoError(t, err)
	require.Len(t, out.Inputs[0].TaprootScriptSpendSig, 1)
	require.Equal(t,
		hex.EncodeToString(schnorr.SerializePubKey(old.PubKey())),
		hex.EncodeToString(out.Inputs[0].TaprootScriptSpendSig[0].XOnlyPubKey),
	)
}

// leafScript builds a multisig leaf embedding the signer's x-only pubkey.
func leafScript(t *testing.T, owner, signer *btcec.PublicKey) []byte {
	t.Helper()
	closure := &script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{owner, signer},
		Type:    script.MultisigTypeChecksig,
	}
	s, err := closure.Script()
	require.NoError(t, err)
	return s
}
