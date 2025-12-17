package offchain

import (
	"bytes"
	"crypto/sha256"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

func TestRebuildAssetTxs(t *testing.T) {
	ownerKey := mustKey(t, "asset-rebuild-owner")
	signerKey := mustKey(t, "asset-rebuild-signer")

	collaborativeClosure := &script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{ownerKey.PubKey(), signerKey.PubKey()},
	}
	vtxo, tapKey := buildVtxoInput(t, 42_000, collaborativeClosure)
	destinationScript := mustP2TRScript(t, tapKey)

	txid := sha256.Sum256([]byte("txid"))
	var txidHash [32]byte
	copy(txidHash[:], txid[:])

	assetGroup := &asset.AssetGroup{
		NormalAssets: []asset.Asset{{
			AssetId: asset.AssetId{TxId: txidHash, Index: 0},
			Inputs: []asset.AssetInput{{
				Type:   asset.AssetInputTypeLocal,
				Vin:    0,
				Amount: 5,
			}},
			Outputs: []asset.AssetOutput{{
				Type:   asset.AssetOutputTypeLocal,
				Vout:   0,
				Amount: 5,
			}},
		}},
		SubDustKey: tapKey,
	}
	opret, err := assetGroup.EncodeOpret(200)
	require.NoError(t, err)

	outputs := []*wire.TxOut{
		{
			Value:    vtxo.Amount,
			PkScript: destinationScript,
		},
		&opret,
	}

	signerScript := mustClosureScript(t, &script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{signerKey.PubKey()},
		},
		Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 6},
	})

	// Assertion removed as Txhash is no longer in AssetInput
	// require.True(t, bytes.Equal(assetGroup.NormalAssets[0].Inputs[0].Txhash, vtxo.Outpoint.Hash[:]))
	require.EqualValues(t, 0, assetGroup.NormalAssets[0].Inputs[0].Vin)

	arkTx, checkpoints, err := BuildAssetTxs(outputs, 1, []VtxoInput{vtxo}, signerScript)
	require.NoError(t, err)
	require.Len(t, checkpoints, 1)

	// Build the inputs slice the same way SubmitOffchainTx constructs it.
	ins := []VtxoInput{{
		Outpoint:           &checkpoints[0].UnsignedTx.TxIn[0].PreviousOutPoint,
		Tapscript:          vtxo.Tapscript,
		RevealedTapscripts: vtxo.RevealedTapscripts,
		Amount:             vtxo.Amount,
	}}

	// Prepare checkpoint map keyed by checkpoint txid.
	checkpointTxMap := make(map[string]string)
	for _, cp := range checkpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		checkpointTxMap[cp.UnsignedTx.TxHash().String()] = encoded
	}

	// Remove anchor output to mimic service.SubmitOffchainTx behaviour.
	outputsNoAnchor := make([]*wire.TxOut, 0, len(arkTx.UnsignedTx.TxOut)-1)
	assetGroupIndex := -1
	for idx, out := range arkTx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) {
			continue
		}
		outputsNoAnchor = append(outputsNoAnchor, out)
		if asset.IsAssetGroup(out.PkScript) {
			assetGroupIndex = idx
		}
	}
	require.NotEqual(t, -1, assetGroupIndex)

	rebuiltArk, rebuiltCheckpoints, err := RebuildAssetTxs(
		outputsNoAnchor, assetGroupIndex, checkpointTxMap, ins, signerScript,
	)
	require.NoError(t, err)
	require.NotNil(t, rebuiltArk)
	require.Len(t, rebuiltCheckpoints, len(checkpoints))
	require.Equal(t, checkpoints[0].UnsignedTx.LockTime, rebuiltCheckpoints[0].UnsignedTx.LockTime)
	require.Equal(t, len(checkpoints[0].UnsignedTx.TxIn), len(rebuiltCheckpoints[0].UnsignedTx.TxIn))
	require.Equal(t, len(checkpoints[0].UnsignedTx.TxOut), len(rebuiltCheckpoints[0].UnsignedTx.TxOut))
	for i := range checkpoints[0].UnsignedTx.TxIn {
		require.Equal(t, checkpoints[0].UnsignedTx.TxIn[i].Sequence, rebuiltCheckpoints[0].UnsignedTx.TxIn[i].Sequence)
		require.True(t, checkpoints[0].UnsignedTx.TxIn[i].PreviousOutPoint == rebuiltCheckpoints[0].UnsignedTx.TxIn[i].PreviousOutPoint)
	}
	for i := range checkpoints[0].UnsignedTx.TxOut {
		require.Equal(t, checkpoints[0].UnsignedTx.TxOut[i].Value, rebuiltCheckpoints[0].UnsignedTx.TxOut[i].Value)
		require.Equal(t, checkpoints[0].UnsignedTx.TxOut[i].PkScript, rebuiltCheckpoints[0].UnsignedTx.TxOut[i].PkScript)
	}
	require.Equal(t, arkTx.UnsignedTx.TxID(), rebuiltArk.UnsignedTx.TxID())
}

func TestRebuildAssetTxsWithControlAsset(t *testing.T) {
	ownerKey := mustKey(t, "asset-rebuild-owner-ca")
	signerKey := mustKey(t, "asset-rebuild-signer-ca")

	collaborativeClosure := &script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{ownerKey.PubKey(), signerKey.PubKey()},
	}

	controlVtxo, controlTapKey := buildVtxoInputWithSeed(t, 21_000, collaborativeClosure, "control-vtxo")
	normalVtxo, normalTapKey := buildVtxoInputWithSeed(t, 15_000, collaborativeClosure, "normal-vtxo")

	// Create asset group with matching control asset
	assetIDHash := sha256.Sum256([]byte("asset-id-ca"))
	var assetID [32]byte
	copy(assetID[:], assetIDHash[:])

	caIDHash := sha256.Sum256([]byte("control-id-ca"))
	var caID [32]byte
	copy(caID[:], caIDHash[:])

	controlAsset := asset.Asset{
		AssetId:        asset.AssetId{TxId: caID, Index: 0},
		ControlAssetId: &asset.AssetId{TxId: caID, Index: 0},
		Inputs: []asset.AssetInput{{
			Type:   asset.AssetInputTypeLocal,
			Vin:    0,
			Amount: 7,
		}},
		Outputs: []asset.AssetOutput{
			{
				Type:   asset.AssetOutputTypeLocal,
				Amount: 1,
				Vout:   0,
			},
		},
		Metadata: []asset.Metadata{{Key: "type", Value: "control"}},
	}

	normalAsset := asset.Asset{
		AssetId:        asset.AssetId{TxId: assetID, Index: 0},
		ControlAssetId: &asset.AssetId{TxId: caID, Index: 0},
		Inputs: []asset.AssetInput{{
			Type:   asset.AssetInputTypeLocal,
			Vin:    1,
			Amount: 5,
		}},
		Outputs: []asset.AssetOutput{
			{
				Type:   asset.AssetOutputTypeLocal,
				Amount: 100,
				Vout:   0,
			},
		},
		Metadata: []asset.Metadata{{Key: "type", Value: "normal"}},
	}

	assetGroup := &asset.AssetGroup{
		ControlAssets: []asset.Asset{controlAsset},
		NormalAssets:  []asset.Asset{normalAsset},
		SubDustKey:    normalTapKey,
	}
	opret, err := assetGroup.EncodeOpret(0)
	require.NoError(t, err)

	outputs := []*wire.TxOut{
		{Value: controlVtxo.Amount, PkScript: mustP2TRScript(t, controlTapKey)},
		{Value: normalVtxo.Amount, PkScript: mustP2TRScript(t, normalTapKey)},
		&opret,
	}

	signerScript := mustClosureScript(t, &script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{signerKey.PubKey()},
		},
		Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 4},
	})

	arkTx, checkpoints, err := BuildAssetTxs(
		outputs, 2, []VtxoInput{controlVtxo, normalVtxo}, signerScript,
	)
	require.NoError(t, err)
	require.Len(t, checkpoints, 2)

	// Build ins as SubmitOffchainTx does.
	vtxoByHash := map[string]VtxoInput{
		controlVtxo.Outpoint.Hash.String(): controlVtxo,
		normalVtxo.Outpoint.Hash.String():  normalVtxo,
	}
	ins := make([]VtxoInput, 0, len(checkpoints))
	for _, cp := range checkpoints {
		prev := cp.UnsignedTx.TxIn[0].PreviousOutPoint
		orig := vtxoByHash[prev.Hash.String()]
		ins = append(ins, VtxoInput{
			Outpoint:           &prev,
			Tapscript:          orig.Tapscript,
			RevealedTapscripts: orig.RevealedTapscripts,
			Amount:             orig.Amount,
		})
	}

	checkpointTxMap := make(map[string]string)
	for _, cp := range checkpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		checkpointTxMap[cp.UnsignedTx.TxHash().String()] = encoded
	}

	outputsNoAnchor := make([]*wire.TxOut, 0, len(arkTx.UnsignedTx.TxOut)-1)
	assetGroupIndex := -1
	for idx, out := range arkTx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, txutils.ANCHOR_PKSCRIPT) {
			continue
		}
		outputsNoAnchor = append(outputsNoAnchor, out)
		if asset.IsAssetGroup(out.PkScript) {
			assetGroupIndex = idx
		}
	}
	require.NotEqual(t, -1, assetGroupIndex)

	rebuiltArk, rebuiltCheckpoints, err := RebuildAssetTxs(
		outputsNoAnchor, assetGroupIndex, checkpointTxMap, ins, signerScript,
	)
	require.NoError(t, err)
	require.Len(t, rebuiltCheckpoints, len(checkpoints))
	require.Equal(t, arkTx.UnsignedTx.TxID(), rebuiltArk.UnsignedTx.TxID())

	// Verify asset group matches and points to rebuilt checkpoints.
	origGroup, err := asset.DecodeAssetGroupFromOpret(outputsNoAnchor[assetGroupIndex].PkScript)
	require.NoError(t, err)
	rebuiltGroup, err := asset.DecodeAssetGroupFromOpret(rebuiltArk.UnsignedTx.TxOut[assetGroupIndex].PkScript)
	require.NoError(t, err)

	require.NotNil(t, rebuiltGroup.ControlAssets)
	require.Len(t, rebuiltGroup.ControlAssets, 1)
	require.Equal(t, len(origGroup.ControlAssets[0].Inputs), len(rebuiltGroup.ControlAssets[0].Inputs))
	require.Equal(t, len(origGroup.NormalAssets[0].Inputs), len(rebuiltGroup.NormalAssets[0].Inputs))

	// Map rebuilt checkpoint txids for quick lookup.
	rebuiltCheckpointIDs := make(map[string]struct{})
	for _, cp := range rebuiltCheckpoints {
		rebuiltCheckpointIDs[cp.UnsignedTx.TxHash().String()] = struct{}{}
	}

	for _, in := range rebuiltGroup.ControlAssets[0].Inputs {
		var found bool
		for _, cp := range rebuiltCheckpoints {
			pkScript := cp.UnsignedTx.TxOut[0].PkScript
			teleportHash := asset.CalculateTeleportHash(pkScript, [32]byte{})
			if bytes.Equal(teleportHash[:], in.Commitment[:]) {
				found = true
				break
			}
		}
		require.True(t, found)
	}
	for _, in := range rebuiltGroup.NormalAssets[0].Inputs {
		var found bool
		for _, cp := range rebuiltCheckpoints {
			pkScript := cp.UnsignedTx.TxOut[0].PkScript
			teleportHash := asset.CalculateTeleportHash(pkScript, [32]byte{})
			if bytes.Equal(teleportHash[:], in.Commitment[:]) {
				found = true
				break
			}
		}
		require.True(t, found)
	}
}

func mustKey(t *testing.T, seed string) *btcec.PrivateKey {
	t.Helper()

	sum := sha256.Sum256([]byte(seed))
	key, _ := btcec.PrivKeyFromBytes(sum[:])
	return key
}

func mustClosureScript(t *testing.T, closure script.Closure) []byte {
	t.Helper()

	scriptBytes, err := closure.Script()
	require.NoError(t, err)
	return scriptBytes
}

func mustP2TRScript(t *testing.T, key *btcec.PublicKey) []byte {
	t.Helper()

	pkScript, err := script.P2TRScript(key)
	require.NoError(t, err)
	return pkScript
}

func buildVtxoInput(t *testing.T, amount int64, closure script.Closure) (VtxoInput, *btcec.PublicKey) {
	t.Helper()

	vtxoScript := &script.TapscriptsVtxoScript{
		Closures: []script.Closure{closure},
	}
	tapKey, tapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	leafScript := mustClosureScript(t, closure)
	tapLeafHash := txscript.NewBaseTapLeaf(leafScript).TapHash()
	proof, err := tapTree.GetTaprootMerkleProof(tapLeafHash)
	require.NoError(t, err)

	controlBlock, err := txscript.ParseControlBlock(proof.ControlBlock)
	require.NoError(t, err)

	revealedTapscripts, err := vtxoScript.Encode()
	require.NoError(t, err)

	outpoint := &wire.OutPoint{
		Hash:  chainhash.DoubleHashH(leafScript),
		Index: 0,
	}

	return VtxoInput{
		Outpoint: outpoint,
		Amount:   amount,
		Tapscript: &waddrmgr.Tapscript{
			ControlBlock:   controlBlock,
			RevealedScript: proof.Script,
		},
		RevealedTapscripts: revealedTapscripts,
	}, tapKey
}

func buildVtxoInputWithSeed(
	t *testing.T, amount int64, closure script.Closure, seed string,
) (VtxoInput, *btcec.PublicKey) {
	vtxo, tapKey := buildVtxoInput(t, amount, closure)
	vtxo.Outpoint = &wire.OutPoint{
		Hash:  chainhash.DoubleHashH([]byte(seed)),
		Index: 0,
	}
	return vtxo, tapKey
}
