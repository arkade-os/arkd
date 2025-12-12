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

	assetID := sha256.Sum256([]byte("asset-rebuild"))
	batchID := sha256.Sum256([]byte("batch-rebuild"))
	assetGroup := &asset.AssetGroup{
		NormalAsset: asset.Asset{
			AssetId: assetID,
			Inputs: []asset.AssetInput{{
				Txhash: vtxo.Outpoint.Hash[:],
				Vout:   vtxo.Outpoint.Index,
				Amount: 5,
			}},
			Outputs: []asset.AssetOutput{{
				PublicKey: *tapKey,
				Vout:      0,
				Amount:    5,
			}},
		},
		SubDustKey: tapKey,
	}
	opret, err := assetGroup.EncodeOpret(batchID[:])
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

	require.True(t, bytes.Equal(assetGroup.NormalAsset.Inputs[0].Txhash, vtxo.Outpoint.Hash[:]))
	require.EqualValues(t, assetGroup.NormalAsset.Inputs[0].Vout, vtxo.Outpoint.Index)

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

	// Asset group in rebuilt ark tx should point to the rebuilt checkpoints.
	foundAsset := false
	for _, out := range rebuiltArk.UnsignedTx.TxOut {
		if !asset.IsAssetGroup(out.PkScript) {
			continue
		}
		foundAsset = true
		decoded, _, err := asset.DecodeAssetGroupFromOpret(out.PkScript)
		require.NoError(t, err)
		require.Len(t, decoded.NormalAsset.Inputs, 1)
		require.Equal(t, rebuiltCheckpoints[0].UnsignedTx.TxHash().String(),
			chainhash.Hash(decoded.NormalAsset.Inputs[0].Txhash).String())
	}
	require.True(t, foundAsset)
}

func TestRebuildAssetTxsWithControlAsset(t *testing.T) {
	ownerKey := mustKey(t, "asset-rebuild-owner-ca")
	signerKey := mustKey(t, "asset-rebuild-signer-ca")

	collaborativeClosure := &script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{ownerKey.PubKey(), signerKey.PubKey()},
	}

	controlVtxo, controlTapKey := buildVtxoInputWithSeed(t, 21_000, collaborativeClosure, "control-vtxo")
	normalVtxo, normalTapKey := buildVtxoInputWithSeed(t, 15_000, collaborativeClosure, "normal-vtxo")

	controlAssetID := sha256.Sum256([]byte("control-asset"))
	normalAssetID := sha256.Sum256([]byte("normal-asset"))
	batchID := sha256.Sum256([]byte("batch-rebuild-control"))

	controlAsset := &asset.Asset{
		AssetId: controlAssetID,
		Inputs: []asset.AssetInput{{
			Txhash: controlVtxo.Outpoint.Hash[:],
			Vout:   controlVtxo.Outpoint.Index,
			Amount: 7,
		}},
		Outputs: []asset.AssetOutput{{
			PublicKey: *controlTapKey,
			Vout:      0,
			Amount:    7,
		}},
	}
	normalAsset := asset.Asset{
		AssetId:        normalAssetID,
		ControlAssetId: controlAssetID,
		Inputs: []asset.AssetInput{{
			Txhash: normalVtxo.Outpoint.Hash[:],
			Vout:   normalVtxo.Outpoint.Index,
			Amount: 5,
		}},
		Outputs: []asset.AssetOutput{{
			PublicKey: *normalTapKey,
			Vout:      0,
			Amount:    5,
		}},
	}

	assetGroup := &asset.AssetGroup{
		ControlAsset: controlAsset,
		NormalAsset:  normalAsset,
		SubDustKey:   normalTapKey,
	}
	opret, err := assetGroup.EncodeOpret(batchID[:])
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
	origGroup, _, err := asset.DecodeAssetGroupFromOpret(outputsNoAnchor[assetGroupIndex].PkScript)
	require.NoError(t, err)
	rebuiltGroup, _, err := asset.DecodeAssetGroupFromOpret(rebuiltArk.UnsignedTx.TxOut[assetGroupIndex].PkScript)
	require.NoError(t, err)

	require.NotNil(t, rebuiltGroup.ControlAsset)
	require.Equal(t, len(origGroup.ControlAsset.Inputs), len(rebuiltGroup.ControlAsset.Inputs))
	require.Equal(t, len(origGroup.NormalAsset.Inputs), len(rebuiltGroup.NormalAsset.Inputs))

	// Map rebuilt checkpoint txids for quick lookup.
	rebuiltCheckpointIDs := make(map[string]struct{})
	for _, cp := range rebuiltCheckpoints {
		rebuiltCheckpointIDs[cp.UnsignedTx.TxHash().String()] = struct{}{}
	}

	for _, in := range rebuiltGroup.ControlAsset.Inputs {
		_, ok := rebuiltCheckpointIDs[chainhash.Hash(in.Txhash).String()]
		require.True(t, ok)
	}
	for _, in := range rebuiltGroup.NormalAsset.Inputs {
		_, ok := rebuiltCheckpointIDs[chainhash.Hash(in.Txhash).String()]
		require.True(t, ok)
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
