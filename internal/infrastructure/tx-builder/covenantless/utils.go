package txbuilder

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
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
	intents []domain.Intent, cosignersPublicKeys [][]string,
) ([]tree.Leaf, error) {
	if len(cosignersPublicKeys) != len(intents) {
		return nil, fmt.Errorf(
			"cosigners public keys length %d does not match intents length %d",
			len(cosignersPublicKeys), len(intents),
		)
	}

	leaves := make([]tree.Leaf, 0)

	for i, intent := range intents {
		cosigners := cosignersPublicKeys[i]

		for _, receiver := range intent.Receivers {
			if receiver.IsOnchain() {
				// Onchain outputs are not part of the vtxo tree.
				continue
			}

			// AssetGroup teleport case
			if len(receiver.AssetId) > 0 {
				leaf, err := buildTeleportAssetLeaf(
					receiver,
					intents,
					cosigners,
				)
				if err != nil {
					return nil, err
				}
				leaves = append(leaves, leaf)
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

// buildTeleportAssetLeaf builds the leaf for an offchain receiver that has an associated asset teleport.
func buildTeleportAssetLeaf(
	receiver domain.Receiver,
	intents []domain.Intent,
	cosigners []string,
) (tree.Leaf, error) {
	// Decode teleport hash
	hash, err := hex.DecodeString(receiver.AssetTeleportHash)
	if err != nil {
		return tree.Leaf{}, fmt.Errorf("failed to decode teleport hash: %w", err)
	}

	assetId, err := extension.AssetIdFromString(receiver.AssetId)
	if err != nil {
		return tree.Leaf{}, fmt.Errorf("failed to decode asset id: %w", err)
	}

	if assetId == nil {
		return tree.Leaf{}, fmt.Errorf("asset id is nil")
	}

	assetGroup := extension.AssetGroup{
		AssetId: assetId,
	}

	var h [32]byte
	copy(h[:], hash)
	assetGroup.Outputs = []extension.AssetOutput{{
		Type:       extension.AssetTypeTeleport,
		Commitment: h,
		Amount:     receiver.Amount,
	}}
	assetGroup.Inputs = nil

	assetPacket := &extension.AssetPacket{
		Assets: []extension.AssetGroup{assetGroup},
	}

	assetOpret, err := assetPacket.EncodeAssetPacket()
	if err != nil {
		return tree.Leaf{}, fmt.Errorf("failed to encode asset opreturn: %w", err)
	}

	return tree.Leaf{
		Script:              "",
		Amount:              receiver.Amount,
		CosignersPublicKeys: cosigners,
		AssetScript:         string(assetOpret.PkScript),
	}, nil
}
