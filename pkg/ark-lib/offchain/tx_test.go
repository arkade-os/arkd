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
	ownerKey := mustKey(t, "asset-rebuild-owner-ca")
	signerKey := mustKey(t, "asset-rebuild-signer-ca")

	collaborativeClosure := &script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{ownerKey.PubKey(), signerKey.PubKey()},
	}

	dustAmount := int64(1000)
	controlVtxo, controlTapKey := buildVtxoInputWithSeed(t, dustAmount, collaborativeClosure, "control-vtxo")
	normalVtxo, normalTapKey := buildVtxoInputWithSeed(t, dustAmount, collaborativeClosure, "normal-vtxo")
	changeVtxo, changeTapKey := buildVtxoInputWithSeed(t, dustAmount, collaborativeClosure, "change-vtxo")

	// Create asset group with matching control asset
	assetInputTxhash := sha256.Sum256([]byte("asset-input"))
	var assetInTxId [32]byte
	copy(assetInTxId[:], assetInputTxhash[:])

	caInputTxId := sha256.Sum256([]byte("control-input"))
	var caID [32]byte
	copy(caID[:], caInputTxId[:])

	controlAsset := asset.AssetGroup{
		AssetId: &asset.AssetId{TxHash: caID, Index: 0},
		Inputs: []asset.AssetInput{{
			Type:   asset.AssetTypeLocal,
			Vin:    0,
			Amount: 7,
		}},
		Outputs: []asset.AssetOutput{
			{
				Type:   asset.AssetTypeLocal,
				Amount: 1,
				Vout:   0,
			},
		},
		Metadata: []asset.Metadata{{Key: "type", Value: "control"}},
	}

	normalAsset := asset.AssetGroup{
		AssetId:      &asset.AssetId{TxHash: assetInTxId, Index: 0},
		ControlAsset: asset.AssetRefFromId(asset.AssetId{TxHash: caID, Index: 0}),
		Inputs: []asset.AssetInput{{
			Type:   asset.AssetTypeLocal,
			Vin:    1,
			Amount: 5,
		}},
		Outputs: []asset.AssetOutput{
			{
				Type:   asset.AssetTypeLocal,
				Amount: 100,
				Vout:   1,
			},
		},
		Metadata: []asset.Metadata{{Key: "type", Value: "normal"}},
	}

	assetGroup := &asset.AssetPacket{
		Assets:  []asset.AssetGroup{controlAsset, normalAsset},
		Version: asset.AssetVersion,
	}
	opret, err := assetGroup.EncodeAssetPacket(0, &asset.SubDustPacket{Key: normalTapKey})
	require.NoError(t, err)

	outputs := []*wire.TxOut{
		{Value: controlVtxo.Amount, PkScript: mustP2TRScript(t, controlTapKey)},
		{Value: normalVtxo.Amount, PkScript: mustP2TRScript(t, normalTapKey)},
		&opret,
		{Value: changeVtxo.Amount, PkScript: mustP2TRScript(t, changeTapKey)},
	}

	signerScript := mustClosureScript(t, &script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{signerKey.PubKey()},
		},
		Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 4},
	})

	arkTx, checkpoints, err := BuildAssetTxs(
		outputs, 2, []VtxoInput{controlVtxo, normalVtxo, changeVtxo}, signerScript,
	)
	require.NoError(t, err)
	require.Len(t, checkpoints, 3)

	// Build ins as SubmitOffchainTx does.
	vtxoByHash := map[string]VtxoInput{
		controlVtxo.Outpoint.Hash.String(): controlVtxo,
		normalVtxo.Outpoint.Hash.String():  normalVtxo,
		changeVtxo.Outpoint.Hash.String():  changeVtxo,
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
		if asset.ContainsAssetPacket(out.PkScript) {
			assetGroupIndex = idx
		}
	}
	require.NotEqual(t, -1, assetGroupIndex)

	rebuiltArk, rebuiltCheckpoints, err := BuildAssetTxs(
		outputsNoAnchor, assetGroupIndex, ins, signerScript,
	)
	require.NoError(t, err)
	require.Len(t, rebuiltCheckpoints, len(checkpoints))
	require.Equal(t, arkTx.UnsignedTx.TxID(), rebuiltArk.UnsignedTx.TxID())

	// Verify asset group matches and points to rebuilt checkpoints.
	origPacket, err := asset.DecodeAssetPacket(outputsNoAnchor[assetGroupIndex].PkScript)
	require.NoError(t, err)
	rebuiltPacket, err := asset.DecodeAssetPacket(rebuiltArk.UnsignedTx.TxOut[assetGroupIndex].PkScript)
	require.NoError(t, err)

	require.NotNil(t, rebuiltPacket)
	require.Len(t, rebuiltPacket.Assets, 2)
	require.Equal(t, len(origPacket.Assets[0].Inputs), len(rebuiltPacket.Assets[0].Inputs))
	require.Equal(t, len(origPacket.Assets[1].Inputs), len(rebuiltPacket.Assets[1].Inputs))

	// Map rebuilt checkpoint txids for quick lookup.
	rebuiltCheckpointIDs := make(map[string]struct{})
	for _, cp := range rebuiltCheckpoints {
		rebuiltCheckpointIDs[cp.UnsignedTx.TxHash().String()] = struct{}{}
	}

	for _, in := range rebuiltPacket.Assets[0].Inputs {
		require.Equal(t, asset.AssetTypeLocal, in.Type)
		require.Less(t, int(in.Vin), len(rebuiltArk.UnsignedTx.TxIn))
	}
	for _, in := range rebuiltPacket.Assets[1].Inputs {
		require.Equal(t, asset.AssetTypeLocal, in.Type)
		require.Less(t, int(in.Vin), len(rebuiltArk.UnsignedTx.TxIn))
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
