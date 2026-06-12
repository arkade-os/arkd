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

// TestSignTransaction makes sure SignTransaction signs taproot script-path inputs with the
// key referenced by the leaf, including deprecated signer keys within their cutoff, and that
// it refuses to sign with a deprecated key whose cutoff date has already passed.
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
		wantErr    string
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
			name: "refuse deprecated key where cutoff passed",
			w: &wallet{WalletOptions: WalletOptions{
				SignerKey:            current,
				DeprecatedSignerKeys: []DeprecatedSignerKey{{Key: old, CutoffDate: now - 3600}},
			}},
			leafSigner: old.PubKey(),
			wantErr:    "cutoff date",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b64 := signablePacket(t, owner, tt.leafSigner)

			signed, err := tt.w.SignTransaction(
				context.Background(), application.SignModeSigner, b64, false, nil)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
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

// TestSignerKeyForLeaf makes sure signerKeyForLeaf resolves a signing key for every closure
// type the server may be asked to sign — not only the multisig forfeit closures — never
// returning a nil key for a recognised closure, and refuses to sign when the matched
// deprecated key is past its cutoff.
func TestSignerKeyForLeaf(t *testing.T) {
	owner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	current, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	old, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	now := time.Now()
	withinCutoff := []DeprecatedSignerKey{{Key: old, CutoffDate: now.Add(time.Hour).Unix()}}
	pastCutoff := []DeprecatedSignerKey{{Key: old, CutoffDate: now.Add(-time.Hour).Unix()}}

	walletWith := func(deprecated []DeprecatedSignerKey) *wallet {
		return &wallet{WalletOptions: WalletOptions{
			SignerKey:            current,
			DeprecatedSignerKeys: deprecated,
		}}
	}

	leafBuilders := []struct {
		name  string
		build func(t *testing.T, owner, signer *btcec.PublicKey) []byte
	}{
		{"multisig", leafScript},
		{"csv multisig", csvMultisigLeaf},
		{"cltv multisig", cltvMultisigLeaf},
		{"condition multisig", conditionMultisigLeaf},
		{"condition csv multisig", conditionCSVMultisigLeaf},
	}

	for _, lb := range leafBuilders {
		t.Run(lb.name, func(t *testing.T) {
			t.Run("current key", func(t *testing.T) {
				leaf := lb.build(t, owner.PubKey(), current.PubKey())
				key, err := walletWith(withinCutoff).signerKeyForLeaf(leaf)
				require.NoError(t, err)
				require.NotNil(t, key)
				want := current.PubKey().SerializeCompressed()
				require.Equal(t, want, key.PubKey().SerializeCompressed())
			})

			t.Run("deprecated key within cutoff", func(t *testing.T) {
				leaf := lb.build(t, owner.PubKey(), old.PubKey())
				key, err := walletWith(withinCutoff).signerKeyForLeaf(leaf)
				require.NoError(t, err)
				require.NotNil(t, key)
				want := old.PubKey().SerializeCompressed()
				require.Equal(t, want, key.PubKey().SerializeCompressed())
			})

			t.Run("deprecated key past cutoff", func(t *testing.T) {
				leaf := lb.build(t, owner.PubKey(), old.PubKey())
				_, err := walletWith(pastCutoff).signerKeyForLeaf(leaf)
				require.ErrorContains(t, err, "cutoff date")
			})
		})
	}
}

func csvMultisigLeaf(t *testing.T, owner, signer *btcec.PublicKey) []byte {
	t.Helper()
	s, err := (&script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{owner, signer},
			Type:    script.MultisigTypeChecksig,
		},
		Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
	}).Script()
	require.NoError(t, err)
	return s
}

func cltvMultisigLeaf(t *testing.T, owner, signer *btcec.PublicKey) []byte {
	t.Helper()
	s, err := (&script.CLTVMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{owner, signer},
			Type:    script.MultisigTypeChecksig,
		},
		Locktime: arklib.AbsoluteLocktime(1_700_000_000),
	}).Script()
	require.NoError(t, err)
	return s
}

func conditionMultisigLeaf(t *testing.T, owner, signer *btcec.PublicKey) []byte {
	t.Helper()
	s, err := (&script.ConditionMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{owner, signer},
			Type:    script.MultisigTypeChecksig,
		},
		Condition: []byte{txscript.OP_TRUE},
	}).Script()
	require.NoError(t, err)
	return s
}

func conditionCSVMultisigLeaf(t *testing.T, owner, signer *btcec.PublicKey) []byte {
	t.Helper()
	s, err := (&script.ConditionCSVMultisigClosure{
		CSVMultisigClosure: script.CSVMultisigClosure{
			MultisigClosure: script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{owner, signer},
				Type:    script.MultisigTypeChecksig,
			},
			Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
		},
		Condition: []byte{txscript.OP_TRUE},
	}).Script()
	require.NoError(t, err)
	return s
}
