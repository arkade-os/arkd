package e2e_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	emulatorv1 "github.com/arkade-os/emulator/api-spec/protobuf/gen/emulator/v1"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestArkdSignerEmulatorOnchainSigning dials the running arkd-signer gRPC
// service, submits a synthetic onchain ArkadeScript spend PSBT, and asserts
// that the returned signed PSBT carries a TaprootScriptSpendSig for the
// tweaked operator key.
//
// The fixture mirrors emulator_signing_onchain_test.go exactly:
//   - operator key = compose default ARKD_SIGNER_SECRET_KEY
//   - MultisigClosure leaf contains the tweaked operator (emulator) key
//   - synthetic prevout tx has a coinbase-style input to avoid btcd's
//     zero-input serialization trap
func TestArkdSignerEmulatorOnchainSigning(t *testing.T) {
	ctx := context.Background()

	addr := os.Getenv("ARKD_SIGNER_ADDR")
	if addr == "" {
		addr = "localhost:6061"
	}

	// Dial arkd-signer (plain h2c, no TLS).
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	client := emulatorv1.NewEmulatorServiceClient(conn)

	// --- Operator key (compose default ARKD_SIGNER_SECRET_KEY) ---
	operatorKeyBytes, err := hex.DecodeString(
		"afcd3fa10f82a05fddc9574fdb13b3991b568e89cc39a72ba4401df8abef35f0",
	)
	require.NoError(t, err)
	operatorKey, operatorPub := btcec.PrivKeyFromBytes(operatorKeyBytes)
	_ = operatorKey // key used server-side; we need it here to compute expected pubkey

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
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(bobPkScript[2:]).
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

	// --- Build synthetic prevout tx ---
	contractPkScript, err := script.P2TRScript(vtxoTapKey)
	require.NoError(t, err)

	fundingOutput := &wire.TxOut{Value: fundingAmount, PkScript: contractPkScript}

	prevoutTx := wire.NewMsgTx(wire.TxVersion)
	prevoutTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: 0xffffffff}, // coinbase-style
		Sequence:         wire.MaxTxInSequenceNum,
	})
	prevoutTx.AddTxOut(fundingOutput)
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

	addEmulatorPacketE2E(t, ptx, []arkade.EmulatorEntry{{Vin: 0, Script: arkadeScript}})

	// --- Encode PSBT to b64 ---
	b64, err := ptx.B64Encode()
	require.NoError(t, err)

	// --- Call SubmitOnchainTx on the running arkd-signer ---
	resp, err := client.SubmitOnchainTx(ctx, &emulatorv1.SubmitOnchainTxRequest{Tx: b64})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetSignedTx())

	// --- Decode the returned signed PSBT and verify the signature ---
	signedPtx, err := psbt.NewFromRawBytes(strings.NewReader(resp.GetSignedTx()), true)
	require.NoError(t, err)
	require.NotEmpty(t, signedPtx.Inputs)

	expectedPub := schnorr.SerializePubKey(
		arkade.ComputeArkadeScriptPublicKey(operatorPub, arkadeScriptHash),
	)

	found := false
	for _, sig := range signedPtx.Inputs[0].TaprootScriptSpendSig {
		if bytes.Equal(sig.XOnlyPubKey, expectedPub) {
			found = true
			break
		}
	}
	require.True(t, found,
		"expected emulator tweaked pubkey %s in TaprootScriptSpendSig, got sigs for: %v",
		hex.EncodeToString(expectedPub),
		func() []string {
			keys := make([]string, 0, len(signedPtx.Inputs[0].TaprootScriptSpendSig))
			for _, s := range signedPtx.Inputs[0].TaprootScriptSpendSig {
				keys = append(keys, hex.EncodeToString(s.XOnlyPubKey))
			}
			return keys
		}(),
	)
}

// addEmulatorPacketE2E embeds an emulator packet into the PSBT's OP_RETURN
// extension output. It is a local copy of the same helper in the unit test
// suite (emulator_signing_onchain_test.go) and utils_test.go.
func addEmulatorPacketE2E(t *testing.T, ptx *psbt.Packet, entries []arkade.EmulatorEntry) {
	t.Helper()

	packet, err := arkade.NewPacket(entries...)
	require.NoError(t, err)

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

	ext := extension.Extension{packet}
	txOut, err := ext.TxOut()
	require.NoError(t, err)

	ptx.UnsignedTx.AddTxOut(txOut)
	ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
}
