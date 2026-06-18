package wallet

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
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

// TestSignTransaction makes sure SignTransaction signs taproot script-path inputs
// with the key referenced by the leaf, including deprecated signer keys. From the
// wallet's point of view the cutoff date is purely informational: it always signs
// with the deprecated key whether or not the cutoff has passed.
func TestSignTransaction(t *testing.T) {
	owner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	current, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	old, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	now := time.Now().Unix()

	tests := []struct {
		name       string
		w          *wallet
		leafSigner *btcec.PublicKey
		wantSigner *btcec.PublicKey
	}{
		{
			name:       "sign with current key",
			w:          &wallet{WalletOptions: WalletOptions{SignerKey: current}},
			leafSigner: current.PubKey(),
			wantSigner: current.PubKey(),
		},
		{
			name: "sign with deprecated key where cutoff date > now",
			w: &wallet{WalletOptions: WalletOptions{
				SignerKey:            current,
				DeprecatedSignerKeys: []DeprecatedSignerKey{{Key: old, CutoffDate: now + 3600}},
			}},
			leafSigner: old.PubKey(),
			wantSigner: old.PubKey(),
		},
		{
			name: "sign with deprecated key where cutoff passed",
			w: &wallet{WalletOptions: WalletOptions{
				SignerKey:            current,
				DeprecatedSignerKeys: []DeprecatedSignerKey{{Key: old, CutoffDate: now - 3600}},
			}},
			leafSigner: old.PubKey(),
			wantSigner: old.PubKey(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b64 := signablePacket(t, owner, tt.leafSigner)

			signed, err := tt.w.SignTransaction(
				context.Background(), application.SignModeSigner, b64, false, nil)
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

// signablePacket builds a single-input PSBT spending a taproot output via a
// multisig leaf that embeds signer's x-only pubkey, returning the base64 PSBT.
func signablePacket(t *testing.T, owner *btcec.PrivateKey, signer *btcec.PublicKey) string {
	t.Helper()
	leaf := leafScript(t, owner.PubKey(), signer)
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
	return b64
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

// TestSignerKeyForLeaf covers the key selection used when signing tapscript leaves:
// the wallet signs with whichever of its keys (current or deprecated) the leaf
// references, including CSV (sweep) leaves; a required leaf that references none of
// the wallet's keys is a hard error instead of a silent wrong-key signature.
func TestSignerKeyForLeaf(t *testing.T) {
	mustKey := func() *btcec.PrivateKey {
		k, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		return k
	}
	current, deprecated, user, stranger := mustKey(), mustKey(), mustKey(), mustKey()

	multisigLeaf := func(keys ...*btcec.PublicKey) []byte {
		s, err := (&script.MultisigClosure{
			PubKeys: keys, Type: script.MultisigTypeChecksig,
		}).Script()
		require.NoError(t, err)
		return s
	}
	csvLeaf := func(keys ...*btcec.PublicKey) []byte {
		s, err := (&script.CSVMultisigClosure{
			MultisigClosure: script.MultisigClosure{
				PubKeys: keys, Type: script.MultisigTypeChecksig,
			},
			Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
		}).Script()
		require.NoError(t, err)
		return s
	}
	pub := func(k *btcec.PrivateKey) []byte { return schnorr.SerializePubKey(k.PubKey()) }

	w := &wallet{WalletOptions: WalletOptions{
		SignerKey:            current,
		DeprecatedSignerKeys: []DeprecatedSignerKey{{Key: deprecated}},
	}}

	t.Run("current key in multisig leaf", func(t *testing.T) {
		key, err := w.signerKeyForLeaf(multisigLeaf(user.PubKey(), current.PubKey()), true)
		require.NoError(t, err)
		require.Equal(t, pub(current), pub(key))
	})

	// regression: CSV (sweep) leaves must be introspected so an old-key sweep is
	// signed with the deprecated key rather than the current one.
	t.Run("deprecated key in csv sweep leaf", func(t *testing.T) {
		key, err := w.signerKeyForLeaf(csvLeaf(deprecated.PubKey()), true)
		require.NoError(t, err)
		require.Equal(t, pub(deprecated), pub(key))
	})

	t.Run("required leaf with no held key errors", func(t *testing.T) {
		_, err := w.signerKeyForLeaf(multisigLeaf(user.PubKey(), stranger.PubKey()), true)
		require.ErrorContains(t, err, "no signer key for tapscript leaf")
	})

	t.Run("best-effort leaf with no held key falls back to current", func(t *testing.T) {
		key, err := w.signerKeyForLeaf(multisigLeaf(user.PubKey(), stranger.PubKey()), false)
		require.NoError(t, err)
		require.Equal(t, pub(current), pub(key))
	})

	t.Run("non-multisig leaf falls back to current", func(t *testing.T) {
		key, err := w.signerKeyForLeaf([]byte{0x01, 0x02, 0x03}, true)
		require.NoError(t, err)
		require.Equal(t, pub(current), pub(key))
	})
}
