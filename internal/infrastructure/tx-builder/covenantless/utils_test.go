package txbuilder_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

type vtxoSetup struct {
	closureKey    *btcec.PrivateKey
	signerKey     *btcec.PrivateKey
	closureScript []byte
	p2trScript    []byte
	cbBytes       []byte
	leaf          txscript.TapLeaf
}

// newSingleKeyVtxoSetup builds a MultisigClosure with closureKey only.
func newSingleKeyVtxoSetup(t *testing.T, signerKey *btcec.PrivateKey) vtxoSetup {
	t.Helper()
	closureKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return buildVtxoSetup(t, closureKey, signerKey, []*btcec.PublicKey{closureKey.PubKey()})
}

// newTwoKeyVtxoSetup builds a MultisigClosure with both closureKey and signerKey.
func newTwoKeyVtxoSetup(t *testing.T, signerKey *btcec.PrivateKey) vtxoSetup {
	t.Helper()
	closureKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return buildVtxoSetup(
		t, closureKey, signerKey, []*btcec.PublicKey{closureKey.PubKey(), signerKey.PubKey()},
	)
}

func buildVtxoSetup(
	t *testing.T, closureKey, signerKey *btcec.PrivateKey, pubkeys []*btcec.PublicKey,
) vtxoSetup {
	t.Helper()

	closure := &script.MultisigClosure{PubKeys: pubkeys, Type: script.MultisigTypeChecksig}
	closureScript, err := closure.Script()
	require.NoError(t, err)

	leaf := txscript.NewBaseTapLeaf(closureScript)
	tapTree := txscript.AssembleTaprootScriptTree(leaf)
	root := tapTree.RootNode.TapHash()

	unspendableKey := script.UnspendableKey()
	taprootKey := txscript.ComputeTaprootOutputKey(unspendableKey, root[:])

	p2trScript, err := script.P2TRScript(taprootKey)
	require.NoError(t, err)

	leafIndex := tapTree.LeafProofIndex[leaf.TapHash()]
	cb := tapTree.LeafMerkleProofs[leafIndex].ToControlBlock(unspendableKey)
	cbBytes, err := cb.ToBytes()
	require.NoError(t, err)

	return vtxoSetup{
		closureKey:    closureKey,
		signerKey:     signerKey,
		closureScript: closureScript,
		p2trScript:    p2trScript,
		cbBytes:       cbBytes,
		leaf:          leaf,
	}
}

func buildTx(t *testing.T, s vtxoSetup, cbOverride []byte) *psbt.Packet {
	t.Helper()

	cb := s.cbBytes
	if cbOverride != nil {
		cb = cbOverride
	}

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
	packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: cb,
		Script:       s.closureScript,
		LeafVersion:  txscript.BaseLeafVersion,
	}}

	return packet
}

func makeVtxoSig(
	t *testing.T, privKey *btcec.PrivateKey, packet *psbt.Packet, leaf txscript.TapLeaf,
) *psbt.TaprootScriptSpendSig {
	t.Helper()

	prevoutFetcher, err := txutils.GetPrevOutputFetcher(packet)
	require.NoError(t, err)

	txSigHashes := txscript.NewTxSigHashes(packet.UnsignedTx, prevoutFetcher)
	leafHash := leaf.TapHash()

	sighash, err := txscript.CalcTapscriptSignaturehash(
		txSigHashes, txscript.SigHashDefault,
		packet.UnsignedTx, 0, prevoutFetcher, leaf,
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

func encodeTx(t *testing.T, tx *psbt.Packet) string {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, tx.Serialize(&buf))
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func randomInput() []ports.TxInput {
	txid := randomHex(32)
	input := ports.TxInput{
		Txid:   txid,
		Index:  0,
		Script: "a914ea9f486e82efb3dd83a69fd96e3f0113757da03c87",
		Value:  1000,
	}

	return []ports.TxInput{input}
}

func randomHex(len int) string {
	buf := make([]byte, len)
	// nolint
	rand.Read(buf)
	return hex.EncodeToString(buf)
}
