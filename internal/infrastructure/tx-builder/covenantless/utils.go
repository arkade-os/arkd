package txbuilder

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/arkade-os/arkd/internal/core/domain"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func getOnchainOutputs(
	intents []domain.Intent, network *chaincfg.Params,
) ([]*wire.TxOut, error) {
	outputs := make([]*wire.TxOut, 0)
	for _, intent := range intents {
		for _, receiver := range intent.Receivers {
			if receiver.IsOnchain() {
				receiverAddr, err := btcutil.DecodeAddress(receiver.OnchainAddress, network)
				if err != nil {
					return nil, err
				}

				receiverScript, err := txscript.PayToAddrScript(receiverAddr)
				if err != nil {
					return nil, err
				}

				outputs = append(outputs, &wire.TxOut{
					Value:    int64(receiver.Amount),
					PkScript: receiverScript,
				})
			}
		}
	}
	return outputs, nil
}

func getOutputVtxosLeaves(
	intents []domain.Intent, signingPubkey *btcec.PublicKey, unilateralExitDelay arklib.RelativeLocktime, cosignersPublicKeys [][]string,
) ([]tree.Leaf, error) {
	if len(cosignersPublicKeys) != len(intents) {
		return nil, fmt.Errorf(
			"cosigners public keys length %d does not match intents length %d",
			len(cosignersPublicKeys), len(intents),
		)
	}

	leaves := make([]tree.Leaf, 0)
	emptyBatchID := make([]byte, 32)

	for i, intent := range intents {
		cosigners := cosignersPublicKeys[i]

		for _, receiver := range intent.Receivers {
			if receiver.IsOnchain() {
				// Onchain outputs are not part of the vtxo tree.
				continue
			}

			// Decode and parse receiver pubkey once for both asset and non-asset cases.
			pubkeyBytes, err := hex.DecodeString(receiver.PubKey)
			if err != nil {
				return nil, fmt.Errorf("receiver pubkey hex decode failed: %w", err)
			}

			pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
			if err != nil {
				return nil, fmt.Errorf("receiver pubkey parse failed: %w", err)
			}

			// Asset teleport case
			if len(receiver.AssetId) > 0 {
				leaf, err := buildTeleportAssetLeaf(
					receiver,
					intents,
					pubkey,
					signingPubkey,
					unilateralExitDelay,
					cosigners,
					emptyBatchID,
					pubkeyBytes,
				)
				if err != nil {
					return nil, err
				}
				leaves = append(leaves, leaf)
				continue
			}

			// Plain offchain vtxo (no asset)
			vtxoScript, err := script.P2TRScript(pubkey)
			if err != nil {
				return nil, fmt.Errorf("failed to create P2TR script: %w", err)
			}

			log.Printf("plain vtxo script %s", hex.EncodeToString(vtxoScript))

			leaves = append(leaves, tree.Leaf{
				Script:              hex.EncodeToString(vtxoScript),
				Amount:              receiver.Amount,
				CosignersPublicKeys: cosigners,
			})

		}
	}
	return leaves, nil
}

func taprootOutputScript(taprootKey *btcec.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(taprootKey)).Script()
}

func getAssetFromIntents(
	intents []domain.Intent, assetId [32]byte,
) (*asset.Asset, error) {

	for _, intent := range intents {
		for _, assetGroup := range intent.AssetGroupList {
			decodedAssetGroup, _, err := asset.DecodeAssetGroupFromOpret(assetGroup)
			if err != nil {
				return nil, fmt.Errorf("failed to decode asset from input: %s", err)
			}

			if decodedAssetGroup.ControlAsset != nil {
				decodedControlAsset := decodedAssetGroup.ControlAsset
				if decodedControlAsset.AssetId == assetId {
					return decodedControlAsset, nil
				}
			}
			decodedAsset := decodedAssetGroup.NormalAsset
			if decodedAsset.AssetId == assetId {
				return &decodedAsset, nil
			}
		}

	}
	return nil, fmt.Errorf("asset with id %x not found in intents", assetId)
}

// buildTeleportAssetLeaf builds the leaf for an offchain receiver that has an associated asset teleport.
func buildTeleportAssetLeaf(
	receiver domain.Receiver,
	intents []domain.Intent,
	receiverPubKey *btcec.PublicKey,
	signingPubkey *btcec.PublicKey,
	unilateralExitDelay arklib.RelativeLocktime,
	cosigners []string,
	batchID []byte,
	receiverPubkeyBytes []byte,
) (tree.Leaf, error) {
	// Decode teleport hash
	hash, err := hex.DecodeString(receiver.AssetTeleportHash)
	if err != nil {
		return tree.Leaf{}, fmt.Errorf("failed to decode teleport hash: %w", err)
	}

	// Decode teleport owner pubkey
	ownerPubkeyBytes, err := hex.DecodeString(receiver.AssetTeleportPubkey)
	if err != nil {
		return tree.Leaf{}, fmt.Errorf("failed to decode teleport pubkey: %w", err)
	}

	ownerPubkey, err := schnorr.ParsePubKey(ownerPubkeyBytes)
	if err != nil {
		return tree.Leaf{}, fmt.Errorf("failed to parse teleport pubkey: %w", err)
	}

	// Build teleport script/taptree
	teleportScript := script.NewTeleportVtxoScript(ownerPubkey, signingPubkey, hash, unilateralExitDelay)

	teleportKey, _, err := teleportScript.TapTree()
	if err != nil {
		return tree.Leaf{}, fmt.Errorf("failed to get teleport taproot key: %w", err)
	}

	encodedTeleportPubkey := schnorr.SerializePubKey(teleportKey)

	// TODO(Joshua): decide whether to make this a hard failure.
	if !bytes.Equal(encodedTeleportPubkey, receiverPubkeyBytes) {
		log.Println("asset teleport pubkey does not match reconstructed teleport pubkey")
	}

	// Decode asset ID
	assetIdBytes, err := hex.DecodeString(receiver.AssetId)
	if err != nil {
		return tree.Leaf{}, fmt.Errorf("failed to decode asset id: %w", err)
	}

	var assetId [32]byte
	copy(assetId[:], assetIdBytes)

	// Get base asset details from intents
	assetDetails, err := getAssetFromIntents(intents, assetId)
	if err != nil {
		return tree.Leaf{}, fmt.Errorf("failed to get asset from intents: %w", err)
	}

	// Work on a copy so we don't mutate shared state
	assetCopy := *assetDetails
	assetCopy.Outputs = []asset.AssetOutput{{
		PublicKey: *teleportKey,
		Vout:      0,
		Amount:    receiver.AssetAmount,
	}}
	assetCopy.Inputs = nil

	assetGroup := &asset.AssetGroup{
		ControlAsset: nil,
		NormalAsset:  assetCopy,
	}

	assetOpret, err := assetGroup.EncodeOpret(batchID)
	if err != nil {
		return tree.Leaf{}, fmt.Errorf("failed to encode asset opreturn: %w", err)
	}

	vtxoScript, err := script.P2TRScript(receiverPubKey)
	if err != nil {
		return tree.Leaf{}, fmt.Errorf("failed to create teleport P2TR script: %w", err)
	}

	return tree.Leaf{
		Script:              hex.EncodeToString(vtxoScript),
		Amount:              receiver.Amount,
		CosignersPublicKeys: cosigners,
		AssetScript:         string(assetOpret.PkScript),
	}, nil
}
