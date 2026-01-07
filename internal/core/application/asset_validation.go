package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

func (s *service) validateAssetTransaction(
	ctx context.Context,
	arkTx wire.MsgTx,
	checkpointTxMap map[string]string,
	assetOutput []byte,
) error {
	decodedAssetPacket, err := asset.DecodeAssetPacket(assetOutput)
	if err != nil {
		return fmt.Errorf("error decoding asset from opreturn: %s", err)
	}

	controlAssets := decodedAssetPacket.ControlAssets
	normalAssets := decodedAssetPacket.NormalAssets
	allAssets := make([]asset.AssetGroup, 0, len(controlAssets)+len(normalAssets))
	allAssets = append(allAssets, normalAssets...)
	allAssets = append(allAssets, controlAssets...)

	if err := ensureUniqueAssetVouts(allAssets); err != nil {
		return err
	}

	if err := s.validateControlAssetsForNormalAssets(ctx, controlAssets, normalAssets); err != nil {
		return err
	}

	return s.validateAssetGroups(ctx, arkTx, checkpointTxMap, allAssets)
}

func (s *service) validateControlAssetsForNormalAssets(
	ctx context.Context,
	controlAssets, normalAssets []asset.AssetGroup,
) error {
	for _, normalAsset := range normalAssets {
		// Ensure Presence of Control Asset for Issuance and Metadata modification
		if len(normalAsset.Inputs) == 0 {
			if normalAsset.ControlAssetId == nil {
				continue
			}
			if err := s.ensureControlAssetExists(ctx, controlAssets, *normalAsset.ControlAssetId); err != nil {
				return err
			}
		}

		totalInputAmount := sumAssetInputs(normalAsset.Inputs)
		totalOutputAmount := sumAssetOutputs(normalAsset.Outputs)
		// Ensure Presence of Control Asset for Reissue/Burn
		if totalInputAmount != totalOutputAmount {
			if normalAsset.ControlAssetId == nil {
				return fmt.Errorf("missing control asset for asset reissue/burn")
			}

			if err := s.ensureControlAssetExists(ctx, controlAssets, *normalAsset.ControlAssetId); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *service) ensureControlAssetExists(
	ctx context.Context,
	controlAssets []asset.AssetGroup,
	controlAssetID asset.AssetId,
) error {
	// check in the provided control assets first
	if hasMatchingControlAsset(controlAssets, &controlAssetID) {
		return nil
	}

	controlAssetIDStr := controlAssetID.ToString()
	existingControlAsset, err := s.repoManager.Assets().GetAssetGroupByID(ctx, controlAssetIDStr)
	if err != nil {
		return fmt.Errorf("error retrieving control asset %s: %w", controlAssetIDStr, err)
	}
	if existingControlAsset == nil {
		return fmt.Errorf("control asset %s not found", controlAssetIDStr)
	}

	return nil
}

func hasMatchingControlAsset(controlAssets []asset.AssetGroup, controlAssetID *asset.AssetId) bool {
	if controlAssetID == nil {
		return false
	}

	for _, ca := range controlAssets {
		if ca.AssetId == *controlAssetID {
			return true
		}
	}

	return false
}

func sumAssetInputs(inputs []asset.AssetInput) uint64 {
	total := uint64(0)
	for _, in := range inputs {
		total += in.Amount
	}
	return total
}

func sumAssetOutputs(outputs []asset.AssetOutput) uint64 {
	total := uint64(0)
	for _, out := range outputs {
		total += out.Amount
	}
	return total
}

func (s *service) validateAssetGroups(
	ctx context.Context,
	arkTx wire.MsgTx,
	checkpointTxMap map[string]string,
	assets []asset.AssetGroup,
) error {
	for _, grpAsset := range assets {
		if err := asset.VerifyAssetOutputs(arkTx.TxOut, grpAsset.Outputs); err != nil {
			return err
		}

		for _, input := range grpAsset.Inputs {
			if err := s.validateAssetInput(ctx, arkTx, checkpointTxMap, input); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *service) validateAssetInput(
	ctx context.Context,
	arkTx wire.MsgTx,
	checkpointTxMap map[string]string,
	input asset.AssetInput,
) error {
	if input.Type == asset.AssetTypeTeleport {
		expectedHash := asset.CalculateTeleportHash(input.Witness.Script, input.Witness.Nonce)
		if !bytes.Equal(input.Commitment[:], expectedHash[:]) {
			return fmt.Errorf("asset input commitment does not match teleport hash witness")
		}

		teleportHash := hex.EncodeToString(input.Commitment[:])
		teleportAsset, err := s.repoManager.Assets().GetTeleportAsset(ctx, teleportHash)
		if err != nil {
			return fmt.Errorf("asset input teleport hash does not exist")
		}
		if teleportAsset == nil {
			return fmt.Errorf("asset input teleport hash does not exist")
		}
		if teleportAsset.IsClaimed {
			return fmt.Errorf("asset input teleport hash is already claimed")
		}

		return nil
	}

	if int(input.Vin) >= len(arkTx.TxIn) {
		return fmt.Errorf("asset input index out of range: %d", input.Vin)
	}

	checkpointOutpoint := arkTx.TxIn[input.Vin].PreviousOutPoint
	checkpointTxHex, ok := checkpointTxMap[checkpointOutpoint.Hash.String()]
	if !ok {
		return fmt.Errorf(
			"checkpoint tx %s not found for asset input %d",
			checkpointOutpoint.Hash,
			input.Vin,
		)
	}

	checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(checkpointTxHex), true)
	if err != nil {
		return fmt.Errorf("failed to decode checkpoint tx %s: %w", checkpointOutpoint.Hash, err)
	}
	if len(checkpointPtx.UnsignedTx.TxIn) == 0 {
		return fmt.Errorf("checkpoint tx %s missing input", checkpointOutpoint.Hash)
	}

	prev := checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint
	offchainTx, err := s.repoManager.OffchainTxs().GetOffchainTx(ctx, prev.Hash.String())
	if err != nil {
		return fmt.Errorf("error retrieving offchain tx %s: %w", prev.Hash, err)
	}
	if offchainTx == nil {
		return fmt.Errorf("offchain tx %s not found in rounds or offchain storage", prev.Hash)
	}
	if !offchainTx.IsFinalized() {
		return fmt.Errorf("offchain tx %s is failed", prev.Hash)
	}

	if err := asset.VerifyAssetOutputInTx(offchainTx.ArkTx, prev.Index); err != nil {
		return err
	}

	return nil
}

func ensureUniqueAssetVouts(assets []asset.AssetGroup) error {
	seen := make(map[uint32]struct{})
	for _, grpAsset := range assets {
		for _, out := range grpAsset.Outputs {
			if out.Type != asset.AssetTypeLocal {
				continue
			}
			if _, exists := seen[out.Vout]; exists {
				return fmt.Errorf("duplicate asset output vout %d", out.Vout)
			}
			seen[out.Vout] = struct{}{}
		}
	}
	return nil
}
