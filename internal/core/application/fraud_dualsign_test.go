package application

import (
	"bytes"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
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

// broadcastForfeitTx signs a forfeit tx in two passes: the operator signer signs
// the vtxo tapscript input, then the wallet signs the connector input. The
// wallet pass is not scoped to the connector, so it also appends a signature
// from its own forfeit key to the vtxo input the signer just signed.
//
// That extra signature is inert only because script.FinalizeVtxoScript keys
// witness args by xonly pubkey and the wallet forfeit key is absent from the
// forfeit closure. These tests pin that invariant: the witness that actually
// reaches the chain must be authorized by the operator key, and the wallet's
// stray signature must not appear in it. If someone puts the wallet forfeit
// pubkey inside a vtxo closure, the second case here is what should fail.
func TestForfeitWitnessIsAuthorizedByOperatorKey(t *testing.T) {
	owner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	operator, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	walletForfeit, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	t.Run("operator signature survives the wallet's extra pass", func(t *testing.T) {
		ptx, sigHashes := forfeitPacket(t, owner, operator.PubKey())

		// Pass 1: the operator signer, plus the owner so the 2-of-2 leaf can be
		// satisfied at all.
		require.NoError(t, txsigner.SignTapscriptInput(ptx, 0, operator, sigHashes))
		require.NoError(t, txsigner.SignTapscriptInput(ptx, 0, owner, sigHashes))

		// Pass 2: the wallet's unscoped sweep over every tapscript input.
		require.NoError(t, txsigner.SignTapscriptInput(ptx, 0, walletForfeit, sigHashes))
		require.Len(t, ptx.Inputs[0].TaprootScriptSpendSig, 3,
			"the psbt should carry the stray wallet signature before finalization")

		require.NoError(t, script.FinalizeVtxoScript(ptx, 0))

		witness := ptx.Inputs[0].FinalScriptWitness
		require.NotEmpty(t, witness)
		require.True(t, witnessHasSigFor(t, ptx, 0, operator.PubKey()),
			"the operator signature must be the one that reaches the chain")
		require.False(t, witnessHasSigFor(t, ptx, 0, walletForfeit.PubKey()),
			"the wallet forfeit signature must not reach the chain")
	})

	// Without the operator's signature the leaf cannot be satisfied, so the
	// wallet's stray signature must not be able to stand in for it.
	t.Run("wallet signature alone cannot satisfy the leaf", func(t *testing.T) {
		ptx, sigHashes := forfeitPacket(t, owner, operator.PubKey())

		require.NoError(t, txsigner.SignTapscriptInput(ptx, 0, owner, sigHashes))
		require.NoError(t, txsigner.SignTapscriptInput(ptx, 0, walletForfeit, sigHashes))

		require.Error(t, script.FinalizeVtxoScript(ptx, 0))
	})
}

// witnessHasSigFor reports whether the finalized witness carries the signature
// the given key produced for this input.
func witnessHasSigFor(
	t *testing.T, ptx *psbt.Packet, inputIndex int, pubkey *btcec.PublicKey,
) bool {
	t.Helper()
	want := schnorr.SerializePubKey(pubkey)

	var sig []byte
	for _, s := range ptx.Inputs[inputIndex].TaprootScriptSpendSig {
		if bytes.Equal(s.XOnlyPubKey, want) {
			sig = s.Signature
			break
		}
	}
	require.NotNil(t, sig, "no signature recorded for the requested key")

	witness, err := txutils.ReadTxWitness(ptx.Inputs[inputIndex].FinalScriptWitness)
	require.NoError(t, err)
	for _, item := range witness {
		if bytes.Equal(item, sig) {
			return true
		}
	}
	return false
}

// forfeitPacket builds a forfeit-shaped psbt: input 0 is the vtxo, spent through
// an owner+operator multisig leaf, which is the input both signing passes touch.
func forfeitPacket(
	t *testing.T, owner *btcec.PrivateKey, operator *btcec.PublicKey,
) (*psbt.Packet, *txscript.TxSigHashes) {
	t.Helper()
	closure := &script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{owner.PubKey(), operator},
		Type:    script.MultisigTypeChecksig,
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
		"0000000000000000000000000000000000000000000000000000000000000001",
	)
	require.NoError(t, err)

	unsigned := wire.NewMsgTx(2)
	unsigned.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: *prevHash, Index: 0}, nil, nil))
	unsigned.AddTxOut(&wire.TxOut{Value: 900, PkScript: pkScript})

	ptx, err := psbt.NewFromUnsignedTx(unsigned)
	require.NoError(t, err)
	ptx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 1000, PkScript: pkScript}
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: ctrlBytes,
		Script:       leaf,
		LeafVersion:  txscript.BaseLeafVersion,
	}}

	fetcher, err := txutils.GetPrevOutputFetcher(ptx)
	require.NoError(t, err)
	return ptx, txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher)
}
