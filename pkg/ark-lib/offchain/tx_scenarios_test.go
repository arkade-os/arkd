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

	tests := []struct {
		name          string
		controlAssets int
		normalAssets  int
	}{
		{
			name:          "Two Normal Assets, Zero Control Assets",
			controlAssets: 0,
			normalAssets:  2,
		},
		{
			name:          "One Control Asset, Two Normal Assets",
			controlAssets: 1,
			normalAssets:  2,
		},
		{
			name:          "Two Control Assets, Two Normal Assets",
			controlAssets: 2,
			normalAssets:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var vtxos []VtxoInput
			var outputs []*wire.TxOut
			var controlAssetData []asset.Asset
			var normalAssetData []asset.Asset

			// Generate Control Assets
			for i := 0; i < tt.controlAssets; i++ {
				vtxo, tapKey := buildVtxoInputWithSeed(t, 21_000+int64(i)*1000, collaborativeClosure, tt.name+"control"+string(rune(i)))
				vtxos = append(vtxos, vtxo)

				assetID := sha256.Sum256([]byte("control-asset-" + string(rune(i))))

				controlAsset := asset.Asset{
					AssetId: assetID,
					Inputs: []asset.AssetInput{{
						Txhash: vtxo.Outpoint.Hash[:],
						Vout:   vtxo.Outpoint.Index,
						Amount: uint64(vtxo.Amount),
					}},
					Outputs: []asset.AssetOutput{{
						PublicKey: *tapKey,
						Vout:      0,
						Amount:    uint64(vtxo.Amount),
					}},
				}
				controlAssetData = append(controlAssetData, controlAsset)
				outputs = append(outputs, &wire.TxOut{Value: vtxo.Amount, PkScript: mustP2TRScript(t, tapKey)})
			}

			// Generate Normal Assets
			for i := 0; i < tt.normalAssets; i++ {
				vtxo, tapKey := buildVtxoInputWithSeed(t, 15_000+int64(i)*1000, collaborativeClosure, tt.name+"normal"+string(rune(i)))
				vtxos = append(vtxos, vtxo)

				assetID := sha256.Sum256([]byte("normal-asset-" + string(rune(i))))

				// If we have control assets, link normal asset to first control asset for simplicity
				var caID [32]byte
				if len(controlAssetData) > 0 {
					caID = controlAssetData[0].AssetId
				}

				normalAsset := asset.Asset{
					AssetId:        assetID,
					ControlAssetId: caID,
					Inputs: []asset.AssetInput{{
						Txhash: vtxo.Outpoint.Hash[:],
						Vout:   vtxo.Outpoint.Index,
						Amount: uint64(vtxo.Amount),
					}},
					Outputs: []asset.AssetOutput{{
						PublicKey: *tapKey,
						Vout:      0,
						Amount:    uint64(vtxo.Amount),
					}},
				}
				normalAssetData = append(normalAssetData, normalAsset)
				outputs = append(outputs, &wire.TxOut{Value: vtxo.Amount, PkScript: mustP2TRScript(t, tapKey)})
			}

			// SubDustKey (using owner key for simplicity)
			subDustKey := ownerKey.PubKey()

			assetGroup := &asset.AssetGroup{
				ControlAssets: controlAssetData,
				NormalAssets:  normalAssetData,
				SubDustKey:    subDustKey,
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
			require.Len(t, rebuiltGroup.ControlAssets, tt.controlAssets)
			require.Len(t, rebuiltGroup.NormalAssets, tt.normalAssets)

			// Verify all inputs in rebuiltGroup point to a valid checkpoint (indirectly verified by TxID match, but good to check)
			rebuiltCheckpointIDs := make(map[string]struct{})
			for _, cp := range rebuiltCheckpoints {
				rebuiltCheckpointIDs[cp.UnsignedTx.TxHash().String()] = struct{}{}
			}

			for _, ca := range rebuiltGroup.ControlAssets {
				for _, in := range ca.Inputs {
					_, ok := rebuiltCheckpointIDs[chainhash.Hash(in.Txhash).String()]
					require.True(t, ok, "Control Asset input should point to a checkpoint")
				}
			}
			for _, na := range rebuiltGroup.NormalAssets {
				for _, in := range na.Inputs {
					_, ok := rebuiltCheckpointIDs[chainhash.Hash(in.Txhash).String()]
					require.True(t, ok, "Normal Asset input should point to a checkpoint")
				}
			}
		})
	}
}
