package handlers_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	emulatorv1 "github.com/arkade-os/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/emulator/pkg/emulator"
	"github.com/arkade-os/emulator/pkg/emulator/grpchandler"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	chainhash "github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestArkdSignerEmulator groups the signing-only (nil finalizer) emulator
// service tests wired through the arkd-signer handler package.
func TestArkdSignerEmulator(t *testing.T) {
	// TestEmulatorGetInfoReturnsOperatorPubkey verifies that emulator.New wired
	// with nil finalizer (signing-only) returns the operator pubkey via GetInfo,
	// and that grpchandler.New correctly wraps it.
	t.Run("GetInfoReturnsOperatorPubkey", func(t *testing.T) {
		priv, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		svc, err := emulator.New(
			context.Background(),
			priv,
			nil, // no deprecated keys
			priv.PubKey(),
			nil, // nil finalizer: signing-only
			arkade.DefaultComputeLimits(),
		)
		require.NoError(t, err)
		t.Cleanup(svc.Close)

		// Check via the Service interface directly.
		info, err := svc.GetInfo(context.Background())
		require.NoError(t, err)
		require.NotNil(t, info)

		wantPubkey := hex.EncodeToString(priv.PubKey().SerializeCompressed())
		require.Equal(t, wantPubkey, info.SignerPublicKey)
		require.Empty(t, info.DeprecatedSignerPublicKeys)

		// Also check through the gRPC handler.
		h := grpchandler.New("", svc)
		resp, err := h.GetInfo(context.Background(), &emulatorv1.GetInfoRequest{})
		require.NoError(t, err)
		require.Equal(t, wantPubkey, resp.GetSignerPubkey())
	})

	// TestArkdSignerSignsOnchainArkade verifies that emulator.New (wired with nil
	// finalizer, i.e. signing-only) correctly signs an onchain arkade spend PSBT
	// without any chain access. The prevout tx is synthetic — its txid is derived
	// from TxHash(), so no explorer or Nigiri is needed.
	t.Run("SignsOnchainArkade", func(t *testing.T) {
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

		// --- VTXO-shaped tapscript with the arkade closure ---
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

		// --- Build spend PSBT ---
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

		// Embed the emulator packet.
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
	})

	// TestArkdSignerRejectsOnchainArkadeContainingArkdKey verifies the safety guard
	// of shared-key signing-only mode: when emulator.New is wired with the operator
	// OWN pubkey as arkdPubKey (as production config.go does) and the tapscript
	// closure contains that raw operator pubkey, SubmitOnchainTx must reject the
	// spend. The closure also carries the tweaked arkade key so execution reaches
	// the guard rather than failing earlier at arkade script resolution.
	t.Run("RejectsOnchainArkadeContainingArkdKey", func(t *testing.T) {
		ctx := context.Background()

		// --- Keys ---
		// One operator key doubles as the emulator signing key and the arkdPubKey,
		// matching production shared-key mode.
		operatorKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		operatorPub := operatorKey.PubKey()

		bobKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		bobPub := bobKey.PubKey()

		const (
			fundingAmount int64 = 1_000_000
			feeAmount     int64 = 500
			spendAmount         = fundingAmount - feeAmount
		)

		// --- Bob's destination P2TR output ---
		bobPkScript, err := txscript.PayToTaprootScript(bobPub)
		require.NoError(t, err)

		// --- Build arkade script: output 0 pays Bob exactly spendAmount ---
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

		// Tweaked arkade key derived from the operator key: required so execution
		// reaches the guard instead of failing at arkade script resolution.
		tweaked := arkade.ComputeArkadeScriptPublicKey(operatorPub, arkadeScriptHash)

		// --- VTXO-shaped tapscript: closure carries BOTH the tweaked key (reach the
		// guard) AND the raw operator pubkey (trip the guard). ---
		vtxoScript := script.TapscriptsVtxoScript{
			Closures: []script.Closure{
				&script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{
						bobPub,
						tweaked,
						operatorPub,
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

		prevoutTx := wire.NewMsgTx(wire.TxVersion)
		prevoutTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}, // coinbase-style
			Sequence:         wire.MaxTxInSequenceNum,
		})
		prevoutTx.AddTxOut(fundingOutput) // index 0
		fundingTxid := prevoutTx.TxHash()

		// --- Build spend PSBT ---
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

		addEmulatorPacketLocal(t, ptx, []arkade.EmulatorEntry{{Vin: 0, Script: arkadeScript}})

		// --- Construct service in shared-key mode: arkdPubKey = raw operator pubkey ---
		svc, err := emulator.New(
			ctx,
			operatorKey,
			nil, // no deprecated keys
			operatorPub,
			nil, // nil finalizer: signing-only
			arkade.DefaultComputeLimits(),
		)
		require.NoError(t, err)
		t.Cleanup(svc.Close)

		// --- The guard must reject: closure contains the arkd signer pubkey ---
		signed, err := svc.SubmitOnchainTx(ctx, emulator.OnchainTx{Tx: ptx})
		require.Error(t, err)
		require.ErrorContains(t, err, "contains arkd signer pubkey")
		require.Nil(t, signed)
	})

	// TestArkdSignerSignsOffchainArkade verifies that emulator.New (signing-only,
	// nil finalizer) signs an OFFCHAIN arkade spend via SubmitTx. The ark tx spends
	// a checkpoint that itself spends a synthetic prevArkTx output. With a nil
	// finalizer the emulator returns the signed ark tx and checkpoints without any
	// arkd round-trip, so we assert the emulator signed checkpoint input 0 with its
	// tweaked arkade key.
	t.Run("SignsOffchainArkade", func(t *testing.T) {
		ctx := context.Background()

		emulatorKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		arkdKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		arkadeScriptBytes := []byte{txscript.OP_TRUE}
		scriptHash := arkade.ArkadeScriptHash(arkadeScriptBytes)
		tweakedEmulatorPub := arkade.ComputeArkadeScriptPublicKey(emulatorKey.PubKey(), scriptHash)

		// closure: emulator tweaked key second-to-last, arkd last (emulator = finalizer role)
		closure := script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{tweakedEmulatorPub, arkdKey.PubKey()},
		}
		vtxoScript := script.TapscriptsVtxoScript{Closures: []script.Closure{&closure}}
		vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
		require.NoError(t, err)

		forfeitScript, err := vtxoScript.ForfeitClosures()[0].Script()
		require.NoError(t, err)
		forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
		merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
		require.NoError(t, err)
		vtxoPkScript, err := script.P2TRScript(vtxoTapKey)
		require.NoError(t, err)

		// prevArkTx holds the vtxo output; checkpoint spends prevArkTx:0; arkTx spends checkpoint:0
		prevArkTx := wire.NewMsgTx(2)
		prevArkTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xaa}, Index: 0},
		})
		prevArkTx.AddTxOut(&wire.TxOut{Value: 5_000, PkScript: vtxoPkScript})
		prevArkTxHash := prevArkTx.TxHash()

		checkpointTx := wire.NewMsgTx(2)
		checkpointTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: prevArkTxHash, Index: 0},
		})
		checkpointTx.AddTxOut(&wire.TxOut{Value: 4_900, PkScript: vtxoPkScript})
		checkpointPtx, err := psbt.NewFromUnsignedTx(checkpointTx)
		require.NoError(t, err)
		checkpointPtx.Inputs[0].WitnessUtxo = &wire.TxOut{Value: 5_000, PkScript: vtxoPkScript}
		checkpointPtx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
			{
				ControlBlock: merkleProof.ControlBlock,
				Script:       merkleProof.Script,
				LeafVersion:  txscript.BaseLeafVersion,
			},
		}
		checkpointTxID := checkpointPtx.UnsignedTx.TxHash()

		arkTx := wire.NewMsgTx(2)
		arkTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: checkpointTxID, Index: 0},
		})
		arkTx.AddTxOut(&wire.TxOut{Value: 4_800, PkScript: vtxoPkScript})
		arkPtx, err := psbt.NewFromUnsignedTx(arkTx)
		require.NoError(t, err)
		arkPtx.Inputs[0].WitnessUtxo = checkpointPtx.UnsignedTx.TxOut[0]
		arkPtx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
			{
				ControlBlock: merkleProof.ControlBlock,
				Script:       merkleProof.Script,
				LeafVersion:  txscript.BaseLeafVersion,
			},
		}
		arkPtx.Outputs = append(arkPtx.Outputs, psbt.POutput{})

		// OP_RETURN emulator packet, entry Vin=0.
		addEmulatorPacketLocal(t, arkPtx, []arkade.EmulatorEntry{{Vin: 0, Script: arkadeScriptBytes}})

		// offchain prevout field is PrevArkTxField (not PrevoutTxField).
		require.NoError(t, txutils.SetArkPsbtField(arkPtx, 0, arkade.PrevArkTxField, *prevArkTx))

		// --- Construct service (signing-only, nil finalizer) ---
		svc, err := emulator.New(
			ctx,
			emulatorKey,
			nil, // no deprecated keys
			arkdKey.PubKey(),
			nil, // nil finalizer: signing-only
			arkade.DefaultComputeLimits(),
		)
		require.NoError(t, err)
		t.Cleanup(svc.Close)

		out, err := svc.SubmitTx(ctx, emulator.OffchainTx{
			ArkTx:       arkPtx,
			Checkpoints: []*psbt.Packet{checkpointPtx},
		})
		require.NoError(t, err)
		require.NotNil(t, out)
		require.NotNil(t, out.ArkTx)
		require.NotEmpty(t, out.Checkpoints)

		// --- Assert: the emulator signed checkpoint input 0 with its tweaked key ---
		expectedPub := schnorr.SerializePubKey(tweakedEmulatorPub)

		found := false
		for _, sig := range out.Checkpoints[0].Inputs[0].TaprootScriptSpendSig {
			if bytes.Equal(sig.XOnlyPubKey, expectedPub) {
				found = true
				break
			}
		}
		require.NotEmpty(t, out.Checkpoints[0].Inputs[0].TaprootScriptSpendSig)
		require.True(t, found,
			"expected emulator tweaked pubkey %s in checkpoint TaprootScriptSpendSig, got sigs for: %v",
			hex.EncodeToString(expectedPub),
			func() []string {
				keys := make([]string, 0, len(out.Checkpoints[0].Inputs[0].TaprootScriptSpendSig))
				for _, s := range out.Checkpoints[0].Inputs[0].TaprootScriptSpendSig {
					keys = append(keys, hex.EncodeToString(s.XOnlyPubKey))
				}
				return keys
			}(),
		)
	})

	// TestArkdSignerSignsIntentArkade verifies that emulator.New (signing-only, nil
	// finalizer) signs an INTENT proof via SubmitIntent. An intent proof has no
	// template: input 0 is the message input and input 1 is the arkade vtxo input.
	// SubmitIntent skips input 0 in the packet loop, then when input 1 is a valid
	// arkade script it executes + signs input 1 AND also signs input 0 using the
	// input 1 script tweak and leaf. We assert both inputs carry the emulator's
	// tweaked-key TaprootScriptSpendSig, proving the real intent signing path.
	t.Run("SignsIntentArkade", func(t *testing.T) {
		ctx := context.Background()

		emulatorKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		// arkdPubKey is unused by SubmitIntent; keep it a fresh random key out of the
		// closure so no guard fires.
		arkdKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		bobKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		bobPub := bobKey.PubKey()

		// Trivial arkade script keeps execution free of output constraints.
		arkadeScriptBytes := []byte{txscript.OP_TRUE}
		scriptHash := arkade.ArkadeScriptHash(arkadeScriptBytes)
		tweakedEmulatorPub := arkade.ComputeArkadeScriptPublicKey(emulatorKey.PubKey(), scriptHash)

		// VTXO-shaped tapscript: closure carries the tweaked emulator key (plus bob).
		vtxoScript := script.TapscriptsVtxoScript{
			Closures: []script.Closure{
				&script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{bobPub, tweakedEmulatorPub},
				},
			},
		}
		vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
		require.NoError(t, err)

		forfeitScript, err := vtxoScript.ForfeitClosures()[0].Script()
		require.NoError(t, err)
		forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
		merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
		require.NoError(t, err)
		vtxoPkScript, err := script.P2TRScript(vtxoTapKey)
		require.NoError(t, err)

		const vtxoAmount int64 = 5_000

		vtxoUtxo := &wire.TxOut{Value: vtxoAmount, PkScript: vtxoPkScript}
		leafScript := []*psbt.TaprootTapLeafScript{
			{
				ControlBlock: merkleProof.ControlBlock,
				Script:       merkleProof.Script,
				LeafVersion:  txscript.BaseLeafVersion,
			},
		}

		// Synthetic prev ark tx funding the vtxo at output 0. A coinbase-style input
		// lets it serialize; its txhash becomes input 1's outpoint.
		prevArkTx := wire.NewMsgTx(2)
		prevArkTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Index: 0xffffffff},
			Sequence:         wire.MaxTxInSequenceNum,
		})
		prevArkTx.AddTxOut(vtxoUtxo) // index 0
		prevArkTxHash := prevArkTx.TxHash()

		// Build the intent proof tx: input 0 = message input, input 1 = vtxo input.
		unsigned := wire.NewMsgTx(2)
		unsigned.AddTxIn(&wire.TxIn{
			// distinct synthetic outpoint for the message input
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xbb}, Index: 0},
		})
		unsigned.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: prevArkTxHash, Index: 0},
		})
		bobPkScript, err := txscript.PayToTaprootScript(bobPub)
		require.NoError(t, err)
		unsigned.AddTxOut(&wire.TxOut{Value: 4_900, PkScript: bobPkScript})

		ptx, err := psbt.NewFromUnsignedTx(unsigned)
		require.NoError(t, err)

		// Message input (0) and vtxo input (1) share the same WitnessUtxo and leaf:
		// SubmitIntent signs input 0 with input 1 script tweak and leaf.
		for i := range ptx.Inputs {
			ptx.Inputs[i].WitnessUtxo = vtxoUtxo
			ptx.Inputs[i].TaprootLeafScript = leafScript
		}

		// intent uses PrevArkTxField; only the arkade input needs it.
		require.NoError(t, txutils.SetArkPsbtField(ptx, 1, arkade.PrevArkTxField, *prevArkTx))

		// OP_RETURN emulator packet, entry Vin=1 (the arkade input).
		addEmulatorPacketLocal(t, ptx, []arkade.EmulatorEntry{{Vin: 1, Script: arkadeScriptBytes}})

		// --- Construct service (signing-only, nil finalizer) ---
		svc, err := emulator.New(
			ctx,
			emulatorKey,
			nil, // no deprecated keys
			arkdKey.PubKey(),
			nil, // nil finalizer: signing-only
			arkade.DefaultComputeLimits(),
		)
		require.NoError(t, err)
		t.Cleanup(svc.Close)

		signed, err := svc.SubmitIntent(ctx, emulator.Intent{
			Proof:   intent.Proof{Packet: *ptx},
			Message: intent.RegisterMessage{},
		})
		require.NoError(t, err)
		require.NotNil(t, signed)

		expectedPub := schnorr.SerializePubKey(tweakedEmulatorPub)

		hasTweakedSig := func(sigs []*psbt.TaprootScriptSpendSig) bool {
			for _, sig := range sigs {
				if bytes.Equal(sig.XOnlyPubKey, expectedPub) {
					return true
				}
			}
			return false
		}

		require.True(t, hasTweakedSig(signed.Inputs[1].TaprootScriptSpendSig),
			"expected emulator tweaked pubkey in vtxo input (1) TaprootScriptSpendSig")
		// SubmitIntent also signs the message input (0) when input 1 is arkade.
		require.True(t, hasTweakedSig(signed.Inputs[0].TaprootScriptSpendSig),
			"expected emulator tweaked pubkey in message input (0) TaprootScriptSpendSig")
	})

	// TestArkdSignerFinalizationRequiresSignedIntent verifies the first precondition
	// of SubmitFinalization: getSignedInputAssociations returns an empty set when the
	// intent proof carries no signed vtxo inputs, so SubmitFinalization rejects with
	// "no signed inputs found in intent proof". The full happy path (a valid
	// tree.TxTree ConnectorTree, 2-input forfeits, and a pre-signed intent proof) is
	// integration-level and is covered at the e2e level, not here.
	t.Run("FinalizationRequiresSignedIntent", func(t *testing.T) {
		ctx := context.Background()

		emulatorKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		// Fresh random arkdPubKey; unused by this path but required by the constructor.
		arkdKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		bobKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		bobPub := bobKey.PubKey()

		// Trivial arkade script; the input never gets executed since it stays unsigned.
		arkadeScriptBytes := []byte{txscript.OP_TRUE}
		scriptHash := arkade.ArkadeScriptHash(arkadeScriptBytes)
		tweakedEmulatorPub := arkade.ComputeArkadeScriptPublicKey(emulatorKey.PubKey(), scriptHash)

		// VTXO-shaped taproot script for the arkade input (input 1).
		vtxoScript := script.TapscriptsVtxoScript{
			Closures: []script.Closure{
				&script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{bobPub, tweakedEmulatorPub},
				},
			},
		}
		vtxoTapKey, _, err := vtxoScript.TapTree()
		require.NoError(t, err)
		vtxoPkScript, err := script.P2TRScript(vtxoTapKey)
		require.NoError(t, err)

		const vtxoAmount int64 = 5_000
		vtxoUtxo := &wire.TxOut{Value: vtxoAmount, PkScript: vtxoPkScript}

		// Intent proof tx: input 0 = message input, input 1 = arkade vtxo input.
		unsigned := wire.NewMsgTx(2)
		unsigned.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xbb}, Index: 0},
		})
		unsigned.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{0xcc}, Index: 0},
		})
		bobPkScript, err := txscript.PayToTaprootScript(bobPub)
		require.NoError(t, err)
		unsigned.AddTxOut(&wire.TxOut{Value: 4_900, PkScript: bobPkScript})

		ptx, err := psbt.NewFromUnsignedTx(unsigned)
		require.NoError(t, err)

		// Both inputs get a WitnessUtxo so computePrevoutFetcher succeeds; input 1 is
		// left UNSIGNED (no TaprootScriptSpendSig), so getSignedInputAssociations skips
		// it and the signed-input set is empty.
		ptx.Inputs[0].WitnessUtxo = vtxoUtxo
		ptx.Inputs[1].WitnessUtxo = vtxoUtxo

		// OP_RETURN emulator packet, entry Vin=1: well-formed and present so the code
		// reaches the "no signed inputs" branch rather than failing earlier.
		addEmulatorPacketLocal(t, ptx, []arkade.EmulatorEntry{{Vin: 1, Script: arkadeScriptBytes}})

		// --- Construct service (signing-only, nil finalizer) ---
		svc, err := emulator.New(
			ctx,
			emulatorKey,
			nil, // no deprecated keys
			arkdKey.PubKey(),
			nil, // nil finalizer: signing-only
			arkade.DefaultComputeLimits(),
		)
		require.NoError(t, err)
		t.Cleanup(svc.Close)

		result, err := svc.SubmitFinalization(ctx, emulator.BatchFinalization{
			Intent: emulator.Intent{
				Proof:   intent.Proof{Packet: *ptx},
				Message: intent.RegisterMessage{},
			},
			Forfeits:      nil,
			ConnectorTree: nil,
			CommitmentTx:  nil,
		})
		require.Error(t, err)
		require.ErrorContains(t, err, "no signed inputs found in intent proof")
		require.Nil(t, result)
	})
}

// addEmulatorPacketLocal embeds the emulator packet into the transaction's OP_RETURN output.
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
