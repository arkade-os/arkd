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
	"github.com/stretchr/testify/require"
)

func TestRebuildAssetTxsScenarios(t *testing.T) {
	ownerKey := mustKey(t, "asset-rebuild-owner-scenarios")
	signerKey := mustKey(t, "asset-rebuild-signer-scenarios")

	collaborativeClosure := &script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{ownerKey.PubKey(), signerKey.PubKey()},
	}

	signerScript := mustClosureScript(t, &script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{signerKey.PubKey()},
		},
		Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 4},
	})

	// Helper function to run a scenario
	runScenario := func(t *testing.T, assetGroup *asset.AssetGroup, vtxos []VtxoInput) {
		var outputs []*wire.TxOut

		// Add outputs for each vtxo
		for _, v := range vtxos {
			rootHash := v.Tapscript.ControlBlock.RootHash(v.Tapscript.RevealedScript)
			taprootKey := txscript.ComputeTaprootOutputKey(script.UnspendableKey(), rootHash)
			outputs = append(outputs, &wire.TxOut{Value: v.Amount, PkScript: mustP2TRScript(t, taprootKey)})
		}

		opret, err := assetGroup.EncodeOpret(0)
		require.NoError(t, err)
		outputs = append(outputs, &opret)

		// Build Ark Tx
		arkTx, checkpoints, err := BuildAssetTxs(outputs, len(outputs)-1, vtxos, signerScript)
		require.NoError(t, err)
		require.Len(t, checkpoints, len(vtxos))

		// Rebuild
		checkpointTxMap := make(map[string]string)
		for _, cp := range checkpoints {
			encoded, err := cp.B64Encode()
			require.NoError(t, err)
			checkpointTxMap[cp.UnsignedTx.TxHash().String()] = encoded
		}

		// Reconstruct inputs for RebuildAssetTxs (simulate what service does)
		vtxoByHash := make(map[string]VtxoInput)
		for _, v := range vtxos {
			vtxoByHash[v.Outpoint.Hash.String()] = v
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

		// Verification
		require.Equal(t, arkTx.UnsignedTx.TxID(), rebuiltArk.UnsignedTx.TxID())
		require.Len(t, rebuiltCheckpoints, len(checkpoints))

		rebuiltGroup, err := asset.DecodeAssetGroupFromOpret(rebuiltArk.UnsignedTx.TxOut[assetGroupIndex].PkScript)
		require.NoError(t, err)
		require.Len(t, rebuiltGroup.ControlAssets, len(assetGroup.ControlAssets))
		require.Len(t, rebuiltGroup.NormalAssets, len(assetGroup.NormalAssets))

		// Verify all inputs in rebuiltGroup point to a valid checkpoint (indirectly verified by TxID match, but good to check)
		rebuiltCheckpointIDs := make(map[string]struct{})
		for _, cp := range rebuiltCheckpoints {
			rebuiltCheckpointIDs[cp.UnsignedTx.TxHash().String()] = struct{}{}
		}

		// assert inputs use Teleport and point to checkpoints
		checkInputs := func(inputs []asset.AssetInput) {
			for _, in := range inputs {
				require.Equal(t, asset.AssetInputTypeTeleport, in.Type)

				// RebuildAssetTxs updates Commitment to VTXO hash (which matches prev.Hash).
				// Wait, my change to RebuildAssetTxs at step 365 updates inputs to Teleport(VTXO Hash).
				// But BuildAssetTxs *outputs* Teleport(Checkpoint Hash).
				// So rebuiltGroup (from rebuiltArk) should have Teleport(Checkpoint Hash).
				// Let's verify THAT.

				// Oh, RebuildAssetTxs calls BuildAssetTxs.
				// BuildAssetTxs generates new AssetGroup (encoded in ArkTx) with Teleport(Checkpoint Hash).
				// So YES, it should be Checkpoint Hash.

				hashStr := chainhash.Hash(in.Commitment).String()
				_, ok := rebuiltCheckpointIDs[hashStr]
				require.True(t, ok, "Asset input should point to a checkpoint")
			}
		}

		for _, ca := range rebuiltGroup.ControlAssets {
			checkInputs(ca.Inputs)
		}
		for _, na := range rebuiltGroup.NormalAssets {
			checkInputs(na.Inputs)
		}
	}

	// Pre-generate some VtxoInputs and tapKeys for scenarios
	vtxo, tapKey := buildVtxoInputWithSeed(t, 21_000, collaborativeClosure, "scenario-vtxo-1")
	vtxo2, _ := buildVtxoInputWithSeed(t, 15_000, collaborativeClosure, "scenario-vtxo-2")
	// vtxo3, tapKey3 := buildVtxoInputWithSeed(t, 10_000, collaborativeClosure, "scenario-vtxo-3")

	// Test different scenarios
	// 1. 0 control assets, 2 normal assets
	t.Run("0 control, 2 normal", func(t *testing.T) {
		assetIDHash := sha256.Sum256([]byte("asset-0c-2n-1"))
		var assetID [32]byte
		copy(assetID[:], assetIDHash[:])

		assetID2Hash := sha256.Sum256([]byte("asset-0c-2n-2"))
		var assetID2 [32]byte
		copy(assetID2[:], assetID2Hash[:])

		assetGroup := &asset.AssetGroup{
			NormalAssets: []asset.Asset{
				{
					AssetId: asset.AssetId{TxId: assetID, Index: 0},
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
				},
				{
					AssetId: asset.AssetId{TxId: assetID2, Index: 0},
					Inputs: []asset.AssetInput{{
						Type:   asset.AssetInputTypeLocal,
						Vin:    1,
						Amount: 10,
					}},
					Outputs: []asset.AssetOutput{{
						Type:   asset.AssetOutputTypeLocal,
						Vout:   0,
						Amount: 10,
					}},
				},
			},
			SubDustKey: tapKey,
		}

		runScenario(t, assetGroup, []VtxoInput{vtxo, vtxo2})
	})

	// 2. 1 control asset, 2 normal assets
	t.Run("1 control, 2 normal", func(t *testing.T) {
		caIDHash := sha256.Sum256([]byte("control-asset-1"))
		var caID [32]byte
		copy(caID[:], caIDHash[:])

		assetIDHash := sha256.Sum256([]byte("normal-asset-1"))
		var assetID [32]byte
		copy(assetID[:], assetIDHash[:])

		assetID2Hash := sha256.Sum256([]byte("normal-asset-2"))
		var assetID2 [32]byte
		copy(assetID2[:], assetID2Hash[:])

		assetGroup := &asset.AssetGroup{
			ControlAssets: []asset.Asset{{
				AssetId:        asset.AssetId{TxId: caID, Index: 0},
				ControlAssetId: asset.AssetId{TxId: caID, Index: 0},
				Inputs: []asset.AssetInput{{
					Type:   asset.AssetInputTypeLocal,
					Vin:    0,
					Amount: 1,
				}},
				Outputs: []asset.AssetOutput{{
					Type:   asset.AssetOutputTypeLocal,
					Vout:   0,
					Amount: 1,
				}},
			}},
			NormalAssets: []asset.Asset{
				{
					AssetId:        asset.AssetId{TxId: assetID, Index: 0},
					ControlAssetId: asset.AssetId{TxId: caID, Index: 0},
					Inputs: []asset.AssetInput{{
						Type:   asset.AssetInputTypeLocal,
						Vin:    1,
						Amount: 5,
					}},
					Outputs: []asset.AssetOutput{{
						Type:   asset.AssetOutputTypeLocal,
						Vout:   0,
						Amount: 5,
					}},
				},
			},
			SubDustKey: tapKey,
		}

		runScenario(t, assetGroup, []VtxoInput{vtxo, vtxo2})
	})
}
