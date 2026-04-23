package script_test

import (
	"crypto/rand"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestVerifyTapscriptSigs(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("signed input appears in signedInputs", func(t *testing.T) {
			setup := newSingleKeySetup(t)
			packet, prevoutFetcher := buildTx(t, setup)

			sig := makeSignature(t, setup.privKey, packet, 0, setup.leaf, prevoutFetcher)
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}

			signedInputs, err := script.VerifyTapscriptSigs(packet, prevoutFetcher)
			require.NoError(t, err)
			require.Equal(t, []int{0}, signedInputs)
		})

		t.Run("unsigned input is skipped and not returned in signedInputs", func(t *testing.T) {
			setup := newSingleKeySetup(t)
			packet, prevoutFetcher := buildTx(t, setup)
			// No signatures added.

			signedInputs, err := script.VerifyTapscriptSigs(
				packet, prevoutFetcher, script.WithSkipUnsignedInputs(),
			)
			require.NoError(t, err)
			require.Empty(t, signedInputs)
		})

		t.Run("skip signer does not require its signature", func(t *testing.T) {
			// 2-of-2 closure: sign only with key1, declare key2 as skip.
			setup, privKey2 := newTwoKeySetup(t)
			packet, prevoutFetcher := buildTx(t, setup)

			sig1 := makeSignature(t, setup.privKey, packet, 0, setup.leaf, prevoutFetcher)
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig1}

			signedInputs, err := script.VerifyTapscriptSigs(
				packet, prevoutFetcher, script.WithSkipPublicKeys(privKey2.PubKey()),
			)
			require.NoError(t, err)
			require.Equal(t, []int{0}, signedInputs)
		})

		t.Run("non-taproot prevout is skipped", func(t *testing.T) {
			setup := newSingleKeySetup(t)
			packet, _ := buildTx(t, setup)

			// Replace the prevout with a P2WPKH script (non-taproot).
			p2wpkhScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_0).
				AddData(make([]byte, 20)).
				Script()
			require.NoError(t, err)

			packet.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 1_000, PkScript: p2wpkhScript}
			prevoutFetcher, err := txutils.GetPrevOutputFetcher(packet)
			require.NoError(t, err)

			signedInputs, err := script.VerifyTapscriptSigs(packet, prevoutFetcher)
			require.NoError(t, err)
			require.Empty(t, signedInputs)
		})

		t.Run("note closure input is skipped", func(t *testing.T) {
			setup := newSingleKeySetup(t)
			packet, prevoutFetcher := buildTx(t, setup)

			// Replace TaprootLeafScript with a note closure script.
			// The control block check is never reached for note closures.
			noteScript := make([]byte, 35)
			noteScript[0] = txscript.OP_SHA256
			noteScript[1] = txscript.OP_DATA_32
			// bytes 2–33: arbitrary 32-byte hash
			noteScript[34] = txscript.OP_EQUAL

			packet.Inputs[0].TaprootLeafScript[0].Script = noteScript

			signedInputs, err := script.VerifyTapscriptSigs(packet, prevoutFetcher)
			require.NoError(t, err)
			require.Empty(t, signedInputs)
		})

		t.Run("input without taproot leaf script is skipped", func(t *testing.T) {
			setup := newSingleKeySetup(t)
			packet, prevoutFetcher := buildTx(t, setup)

			packet.Inputs[0].TaprootLeafScript = nil

			signedInputs, err := script.VerifyTapscriptSigs(packet, prevoutFetcher)
			require.NoError(t, err)
			require.Empty(t, signedInputs)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("wrong parity bit in control block", func(t *testing.T) {
			setup := newSingleKeySetup(t)
			packet, prevoutFetcher := buildTx(t, setup)

			// Flip bit 0 of byte 0: correct x-coordinate, wrong Y parity.
			corrupted := make([]byte, len(setup.controlBlockBytes))
			copy(corrupted, setup.controlBlockBytes)
			corrupted[0] ^= 0x01
			packet.Inputs[0].TaprootLeafScript[0].ControlBlock = corrupted

			_, err := script.VerifyTapscriptSigs(packet, prevoutFetcher)
			require.Error(t, err)
		})

		t.Run("wrong x-coordinate from tampered merkle path", func(t *testing.T) {
			setup := newSingleKeySetup(t)
			packet, prevoutFetcher := buildTx(t, setup)

			// Append a fake 32-byte sibling node; this changes the computed
			// root hash and therefore the output key's x-coordinate.
			fakeNode := make([]byte, 32)
			_, err := rand.Read(fakeNode)
			require.NoError(t, err)

			corrupted := append(append([]byte{}, setup.controlBlockBytes...), fakeNode...)
			packet.Inputs[0].TaprootLeafScript[0].ControlBlock = corrupted

			_, err = script.VerifyTapscriptSigs(packet, prevoutFetcher)
			require.Error(t, err)
		})

		t.Run("invalid signature bytes", func(t *testing.T) {
			setup := newSingleKeySetup(t)
			packet, prevoutFetcher := buildTx(t, setup)

			sig := makeSignature(t, setup.privKey, packet, 0, setup.leaf, prevoutFetcher)
			// Corrupt the first byte of the signature.
			sig.Signature[0] ^= 0xff
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}

			_, err := script.VerifyTapscriptSigs(packet, prevoutFetcher)
			require.Error(t, err)
		})

		t.Run("missing signer signature in 2-of-2 multisig", func(t *testing.T) {
			// 2-of-2 closure: only sign with key1, key2 not in skip.
			setup, _ := newTwoKeySetup(t)
			packet, prevoutFetcher := buildTx(t, setup)

			sig1 := makeSignature(t, setup.privKey, packet, 0, setup.leaf, prevoutFetcher)
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig1}

			_, err := script.VerifyTapscriptSigs(packet, prevoutFetcher)
			require.Error(t, err)
		})

		t.Run("unsigned input errors by default", func(t *testing.T) {
			setup := newSingleKeySetup(t)
			packet, prevoutFetcher := buildTx(t, setup)
			// No signatures added.

			_, err := script.VerifyTapscriptSigs(packet, prevoutFetcher)
			require.Error(t, err)
		})

		t.Run("wrong leaf hash in tapscript sig", func(t *testing.T) {
			setup := newSingleKeySetup(t)
			packet, prevoutFetcher := buildTx(t, setup)

			sig := makeSignature(t, setup.privKey, packet, 0, setup.leaf, prevoutFetcher)
			// Replace the leaf hash with random bytes.
			_, err := rand.Read(sig.LeafHash)
			require.NoError(t, err)
			packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{sig}

			_, err = script.VerifyTapscriptSigs(packet, prevoutFetcher)
			require.Error(t, err)
		})
	})
}

type verifySetup struct {
	privKey           *btcec.PrivateKey
	closureScript     []byte
	p2trScript        []byte
	controlBlockBytes []byte
	leaf              txscript.TapLeaf
}

func newSingleKeySetup(t *testing.T) verifySetup {
	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	closure := &script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{privKey.PubKey()},
		Type:    script.MultisigTypeChecksig,
	}
	closureScript, err := closure.Script()
	require.NoError(t, err)

	return buildSetupFromScript(t, closureScript, privKey)
}

// newTwoKeySetup returns a 2-of-2 MultisigClosure (both keys required).
func newTwoKeySetup(t *testing.T) (verifySetup, *btcec.PrivateKey) {
	t.Helper()

	privKey1, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	privKey2, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	closure := &script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{privKey1.PubKey(), privKey2.PubKey()},
		Type:    script.MultisigTypeChecksig,
	}
	closureScript, err := closure.Script()
	require.NoError(t, err)

	return buildSetupFromScript(t, closureScript, privKey1), privKey2
}

func buildSetupFromScript(
	t *testing.T, closureScript []byte, primaryKey *btcec.PrivateKey,
) verifySetup {
	t.Helper()

	leaf := txscript.NewBaseTapLeaf(closureScript)
	tapTree := txscript.AssembleTaprootScriptTree(leaf)
	root := tapTree.RootNode.TapHash()

	unspendableKey := script.UnspendableKey()
	taprootKey := txscript.ComputeTaprootOutputKey(unspendableKey, root[:])

	p2trScript, err := script.P2TRScript(taprootKey)
	require.NoError(t, err)

	leafIndex := tapTree.LeafProofIndex[leaf.TapHash()]
	proof := tapTree.LeafMerkleProofs[leafIndex]
	cb := proof.ToControlBlock(unspendableKey)
	cbBytes, err := cb.ToBytes()
	require.NoError(t, err)

	return verifySetup{
		privKey:           primaryKey,
		closureScript:     closureScript,
		p2trScript:        p2trScript,
		controlBlockBytes: cbBytes,
		leaf:              leaf,
	}
}

// buildTx builds a one-input PSBT spending a P2TR output described by setup.
func buildTx(t *testing.T, s verifySetup) (*psbt.Packet, txscript.PrevOutputFetcher) {
	t.Helper()

	var prevHash [32]byte
	_, err := rand.Read(prevHash[:])
	require.NoError(t, err)

	prevOutPoint := wire.OutPoint{Hash: prevHash, Index: 0}
	prevTxOut := &wire.TxOut{Value: 1_000, PkScript: s.p2trScript}

	packet, err := psbt.New(
		[]*wire.OutPoint{&prevOutPoint},
		[]*wire.TxOut{wire.NewTxOut(900, s.p2trScript)},
		2, 0,
		[]uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)

	packet.Inputs[0].WitnessUtxo = prevTxOut
	packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: s.controlBlockBytes,
			Script:       s.closureScript,
			LeafVersion:  txscript.BaseLeafVersion,
		},
	}

	prevoutFetcher, err := txutils.GetPrevOutputFetcher(packet)
	require.NoError(t, err)

	return packet, prevoutFetcher
}

// makeSignature computes and returns a valid tapscript spend sig for inputIndex.
func makeSignature(
	t *testing.T, privKey *btcec.PrivateKey, tx *psbt.Packet,
	inputIndex int, leaf txscript.TapLeaf, prevoutFetcher txscript.PrevOutputFetcher,
) *psbt.TaprootScriptSpendSig {
	t.Helper()

	txSigHashes := txscript.NewTxSigHashes(tx.UnsignedTx, prevoutFetcher)
	leafHash := leaf.TapHash()

	sighash, err := txscript.CalcTapscriptSignaturehash(
		txSigHashes, txscript.SigHashDefault,
		tx.UnsignedTx, inputIndex, prevoutFetcher, leaf,
	)
	require.NoError(t, err)

	sig, err := schnorr.Sign(privKey, sighash)
	require.NoError(t, err)

	return &psbt.TaprootScriptSpendSig{
		XOnlyPubKey: schnorr.SerializePubKey(privKey.PubKey()),
		LeafHash:    leafHash[:],
		Signature:   sig.Serialize(),
		SigHash:     txscript.SigHashDefault,
	}
}
