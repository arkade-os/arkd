package handlers_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestArkdSignerSignsOnchainArkade verifies that emulator.New (wired with nil
// finalizer, i.e. signing-only) correctly signs an onchain arkade spend PSBT
// without any chain access. The prevout tx is synthetic — its txid is derived
// from TxHash(), so no explorer or Nigiri is needed.
func TestArkdSignerSignsOnchainArkade(t *testing.T) {
	ctx := context.Background()

	// --- Keys ---
	// operatorKey is both the emulator signing key and the arkd pubkey passed
	// to emulator.New (i.e. the check that rejects "arkd pubkey in tapscript"
	// uses THIS key). We use a separate operatorPub-as-arkdPub trick: we use
	// a DIFFERENT random key as arkdPubKey so that the containsPubKey check
	// never fires for our closure (the closure has bob, alice, and the tweaked
	// emulator key — none of which equals the arkdKey).
	operatorKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	operatorPub := operatorKey.PubKey()

	// arkdKey is what gets passed as arkdPubKey to emulator.New. It must NOT
	// appear in the VTXO tapscript closures, so we make it a fresh random key.
	arkdKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	bobKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	bobPub := bobKey.PubKey()

	aliceKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	alicePub := aliceKey.PubKey()

	const (
		fundingAmount int64 = 1_000_000
		feeAmount     int64 = 500
		spendAmount         = fundingAmount - feeAmount
	)

	// --- Bob's destination P2TR output ---
	bobPkScript, err := txscript.PayToTaprootScript(bobPub)
	require.NoError(t, err)

	// --- Build arkade script: output 0 pays Bob exactly spendAmount ---
	// Mirrors onchain_test.go lines 55-66 exactly.
	arkadeScript, err := txscript.NewScriptBuilder().
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY). // taproot version
		AddData(bobPkScript[2:]).     // 32-byte witness program (strip version+pushbyte)
		AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddInt64(spendAmount).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	arkadeScriptHash := arkade.ArkadeScriptHash(arkadeScript)

	// --- VTXO-shaped tapscript with the arkade closure (mirrors utils_test.go:798) ---
	vtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					bobPub,
					alicePub,
					arkade.ComputeArkadeScriptPublicKey(operatorPub, arkadeScriptHash),
				},
			},
		},
	}

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]
	arkadeTapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(arkadeTapscript).TapHash(),
	)
	require.NoError(t, err)

	// --- Build synthetic prevout tx (no chain access) ---
	contractPkScript, err := script.P2TRScript(vtxoTapKey)
	require.NoError(t, err)

	fundingOutput := &wire.TxOut{Value: fundingAmount, PkScript: contractPkScript}

	// The prevoutTx must have at least one input to survive wire.MsgTx.Serialize /
	// Deserialize: a bare tx with 0 inputs serializes with a zero-byte that btcd
	// misreads as the segwit marker (0x00), causing "unexpected EOF" on
	// deserialization. A synthetic coinbase-style input avoids that.
	prevoutTx := wire.NewMsgTx(wire.TxVersion)
	prevoutTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}, // coinbase-style
		Sequence:         wire.MaxTxInSequenceNum,
	})
	prevoutTx.AddTxOut(fundingOutput) // index 0
	fundingTxid := prevoutTx.TxHash()

	// --- Build spend PSBT (mirrors buildOnchainSpendPtxCustomPrevout, lines 445-487) ---
	unsigned := wire.NewMsgTx(wire.TxVersion)
	unsigned.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: fundingTxid, Index: 0},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	unsigned.AddTxOut(&wire.TxOut{Value: spendAmount, PkScript: bobPkScript})

	ptx, err := psbt.NewFromUnsignedTx(unsigned)
	require.NoError(t, err)

	ptx.Inputs[0].WitnessUtxo = fundingOutput
	ptx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: merkleProof.ControlBlock,
			Script:       merkleProof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		},
	}

	require.NoError(t, txutils.SetArkPsbtField(ptx, 0, arkade.PrevoutTxField, *prevoutTx))

	// Embed the emulator packet (mirrors addEmulatorPacket in utils_test.go:838).
	addEmulatorPacketLocal(t, ptx, []arkade.EmulatorEntry{{Vin: 0, Script: arkadeScript}})

	// --- Construct service directly (signing-only, nil finalizer) ---
	svc, err := emulator.New(
		ctx,
		operatorKey,
		nil, // no deprecated keys
		arkdKey.PubKey(),
		nil, // nil finalizer: signing-only
		arkade.DefaultComputeLimits(),
	)
	require.NoError(t, err)
	t.Cleanup(svc.Close)

	// --- Call SubmitOnchainTx directly with the in-memory PSBT ---
	// (No b64 round-trip needed since the emulator Service works on *psbt.Packet.)
	signed, err := svc.SubmitOnchainTx(ctx, emulator.OnchainTx{Tx: ptx})
	require.NoError(t, err)
	require.NotNil(t, signed)

	// --- Assert: the emulator's tweaked key appears in TaprootScriptSpendSig ---
	expectedPub := schnorr.SerializePubKey(
		arkade.ComputeArkadeScriptPublicKey(operatorPub, arkadeScriptHash),
	)

	found := false
	for _, sig := range signed.Inputs[0].TaprootScriptSpendSig {
		if bytes.Equal(sig.XOnlyPubKey, expectedPub) {
			found = true
			break
		}
	}
	require.True(t, found,
		"expected emulator tweaked pubkey %s in TaprootScriptSpendSig, got sigs for: %v",
		hex.EncodeToString(expectedPub),
		func() []string {
			keys := make([]string, 0, len(signed.Inputs[0].TaprootScriptSpendSig))
			for _, s := range signed.Inputs[0].TaprootScriptSpendSig {
				keys = append(keys, hex.EncodeToString(s.XOnlyPubKey))
			}
			return keys
		}(),
	)
}

// addEmulatorPacketLocal is a local copy of addEmulatorPacket from the
// integration test suite (utils_test.go:838). It embeds the emulator packet
// into the transaction's OP_RETURN output.
func addEmulatorPacketLocal(t *testing.T, ptx *psbt.Packet, entries []arkade.EmulatorEntry) {
	t.Helper()

	packet, err := arkade.NewPacket(entries...)
	require.NoError(t, err)

	// Look for an existing OP_RETURN with ARK extension.
	for i, out := range ptx.UnsignedTx.TxOut {
		if !extension.IsExtension(out.PkScript) {
			continue
		}
		ext, err := extension.NewExtensionFromBytes(out.PkScript)
		if err != nil {
			continue
		}
		ext = append(ext, packet)
		combined, err := ext.Serialize()
		require.NoError(t, err)
		ptx.UnsignedTx.TxOut[i].PkScript = combined
		return
	}

	// No existing ARK extension — insert a new OP_RETURN output.
	ext := extension.Extension{packet}
	txOut, err := ext.TxOut()
	require.NoError(t, err)

	ptx.UnsignedTx.AddTxOut(txOut)
	ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
}
