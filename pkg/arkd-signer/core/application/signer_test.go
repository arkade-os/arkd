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

// signablePacket builds a single-input PSBT spending a taproot output via a
// multisig leaf embedding owner + leafSigner, returning the base64 PSBT.
func signablePacket(t *testing.T, owner *btcec.PrivateKey, leafSigner *btcec.PublicKey) string {
	t.Helper()
	closure := &arkscript.MultisigClosure{
		PubKeys: []*btcec.PublicKey{owner.PubKey(), leafSigner},
		Type:    arkscript.MultisigTypeChecksig,
	}
	leaf, err := closure.Script()
	require.NoError(t, err)

	tapLeaf := txscript.NewBaseTapLeaf(leaf)
	tapTree := txscript.AssembleTaprootScriptTree(tapLeaf)
	rootHash := tapTree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(owner.PubKey(), rootHash[:])
	pkScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).AddData(schnorr.SerializePubKey(outputKey)).Script()
	require.NoError(t, err)

	ctrlBlock := tapTree.LeafMerkleProofs[0].ToControlBlock(owner.PubKey())
	ctrlBytes, err := ctrlBlock.ToBytes()
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
		ControlBlock: ctrlBytes,
		Script:       leaf,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	b64, err := packet.B64Encode()
	require.NoError(t, err)
	return b64
}

func TestGetPubkey(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	svc := application.New(priv, nil)

	got, err := svc.GetPubkey(context.Background())
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(priv.PubKey().SerializeCompressed()), got)
	require.True(t, svc.IsReady(context.Background()))
}

func TestGetDeprecatedPubkeys(t *testing.T) {
	current, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	old, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	svc := application.New(current, []application.DeprecatedSignerKey{
		{Key: old, CutoffDate: 1234},
	})

	deprecated, err := svc.GetDeprecatedPubkeys(context.Background())
	require.NoError(t, err)
	require.Len(t, deprecated, 1)
	require.Equal(t,
		hex.EncodeToString(old.PubKey().SerializeCompressed()), deprecated[0].Pubkey)
	require.EqualValues(t, 1234, deprecated[0].CutoffDate)
}

// TestSignTransactionTapscriptSelectsKeyByLeaf mirrors arkd-wallet's
// signer_keys_test: the signer signs with the deprecated key whose pubkey is in
// the leaf, otherwise with the current key.
func TestSignTransactionTapscriptSelectsKeyByLeaf(t *testing.T) {
	owner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	current, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	old, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	tests := []struct {
		name       string
		svc        application.Signer
		leafSigner *btcec.PublicKey
		wantSigner *btcec.PublicKey
	}{
		{
			name:       "current key",
			svc:        application.New(current, nil),
			leafSigner: current.PubKey(),
			wantSigner: current.PubKey(),
		},
		{
			name: "deprecated key by leaf",
			svc: application.New(current, []application.DeprecatedSignerKey{
				{Key: old, CutoffDate: 0},
			}),
			leafSigner: old.PubKey(),
			wantSigner: old.PubKey(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b64 := signablePacket(t, owner, tt.leafSigner)
			signed, err := tt.svc.SignTransactionTapscript(context.Background(), b64, nil)
			require.NoError(t, err)

			out, err := psbt.NewFromRawBytes(strings.NewReader(signed), true)
			require.NoError(t, err)
			require.Len(t, out.Inputs[0].TaprootScriptSpendSig, 1)
			require.Equal(t,
				hex.EncodeToString(schnorr.SerializePubKey(tt.wantSigner)),
				hex.EncodeToString(out.Inputs[0].TaprootScriptSpendSig[0].XOnlyPubKey),
			)
		})
	}
}

func TestSignRejectsMissingWitnessUtxo(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	svc := application.New(priv, nil)

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
