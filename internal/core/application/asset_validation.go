package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

func (s *service) validateAssetTransition(
	ctx context.Context,
	arkTx wire.MsgTx,
	checkpointTxMap map[string]string,
	opReturnOutput wire.TxOut,
) error {
	decodedAssetPacket, err := extension.DecodeAssetPacket(opReturnOutput)
	if err != nil {
		return fmt.Errorf("error decoding asset from opreturn: %s", err)
	}

	allAssets := decodedAssetPacket.Assets

	if err := ensureUniqueAssetVouts(allAssets); err != nil {
		return err
	}

	if err := s.validateControlAssets(ctx, allAssets); err != nil {
		return err
	}

	for _, grpAsset := range allAssets {
		if err := s.validateAssetGroup(ctx, arkTx, checkpointTxMap, grpAsset); err != nil {
			return err
		}
	}

	return nil
}

func (s *service) validateControlAssets(ctx context.Context, assets []extension.AssetGroup) error {
	// Validate Presence of Control Assets
	for _, asst := range assets {

		// If AssetId is nill : Issuance
		if asst.AssetId == nil && asst.ControlAsset != nil {
			switch asst.ControlAsset.Type {
			case extension.AssetRefByGroup:
				if int(asst.ControlAsset.GroupIndex) >= len(assets) {
					return fmt.Errorf("control asset group index %d out of range for issuance", asst.ControlAsset.GroupIndex)
				}

			case extension.AssetRefByID:
				controlAssetIDStr := asst.ControlAsset.AssetId.ToString()
				assetGroup, err := s.repoManager.Assets().GetAssetGroupByID(ctx, controlAssetIDStr)
				if err != nil {
					return fmt.Errorf("error retrieving control asset %s for issuance: %w", controlAssetIDStr, err)
				}

				if assetGroup == nil {
					return fmt.Errorf("control asset %s does not exist for issuance", controlAssetIDStr)
				}

			default:
				return fmt.Errorf("invalid control asset reference for issuance")
			}
			continue
		}

		// Ensure Presence of Control Asset for  Reissuance
		totalInputAmount := sumAssetInputs(asst.Inputs)
		totalOutputAmount := sumAssetOutputs(asst.Outputs)

		if totalOutputAmount > totalInputAmount {
			if asst.AssetId == nil {
				return fmt.Errorf("missing asset ID")
			}

			controlAssetDetails, err := s.repoManager.Assets().GetAssetGroupByID(ctx, asst.AssetId.ToString())
			if err != nil {
				return fmt.Errorf("error retrieving asset %s: %w", asst.AssetId.ToString(), err)
			}

			if controlAssetDetails == nil {
				return fmt.Errorf("asset %s does not exist", asst.AssetId.ToString())
			}

			controlAssetId := controlAssetDetails.ControlAssetID
			if controlAssetId == "" {
				return fmt.Errorf("asset %s does not have a control asset", asst.AssetId.ToString())
			}

			decodedControlAssetId, err := extension.AssetIdFromString(controlAssetId)
			if err != nil {
				return fmt.Errorf("error decoding control asset ID %s: %w", controlAssetId, err)
			}

			if decodedControlAssetId == nil {
				return fmt.Errorf("invalid control asset ID %s", controlAssetId)
			}

			if err := s.ensureAssetPresence(ctx, assets, *decodedControlAssetId); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *service) validateAssetGroup(
	ctx context.Context,
	arkTx wire.MsgTx,
	checkpointTxMap map[string]string,
	grpAsset extension.AssetGroup,
) error {

	if grpAsset.AssetId != nil {
		gp, err := s.repoManager.Assets().GetAssetGroupByID(ctx, grpAsset.AssetId.ToString())

		if err != nil {
			return fmt.Errorf("error retrieving asset group %s: %w", grpAsset.AssetId.ToString(), err)
		}
		if gp == nil {
			return fmt.Errorf("asset group %s does not exist", grpAsset.AssetId.ToString())
		}
	}

	for _, output := range grpAsset.Outputs {
		if err := s.validateAssetOutput(ctx, arkTx, grpAsset, output); err != nil {
			return err
		}
	}

	for _, input := range grpAsset.Inputs {
		if err := s.validateAssetInput(ctx, arkTx, checkpointTxMap, input); err != nil {
			return err
		}
	}

	return nil
}

func (s *service) validateAssetOutput(
	ctx context.Context,
	arkTx wire.MsgTx,
	assetGp extension.AssetGroup,
	output extension.AssetOutput,
) error {
	processedOutputs := 0

	for _, assetOut := range assetGp.Outputs {
		switch assetOut.Type {
		case extension.AssetTypeLocal:
			for index := range arkTx.TxOut {
				if index == int(assetOut.Vout) {
					processedOutputs++
					break
				}
			}
		case extension.AssetTypeTeleport:
			processedOutputs++
		default:
			return fmt.Errorf("unknown asset output type %d", assetOut.Type)
		}
	}

	if processedOutputs != len(assetGp.Outputs) {
		errors := fmt.Errorf("not all asset outputs verified: processed %d of %d",
			processedOutputs, len(assetGp.Outputs))
		return errors
	}
	return nil
}

func (s *service) validateAssetInput(
	ctx context.Context,
	arkTx wire.MsgTx,
	checkpointTxMap map[string]string,
	input extension.AssetInput,
) error {
	if input.Type == extension.AssetTypeTeleport {
		expectedHash := extension.CalculateTeleportHash(input.Witness.Script, input.Witness.Nonce)
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

	if err := s.verifyAssetInputPrevOut(ctx, input, prev, arkTx); err != nil {
		return err
	}

	return nil
}

func (s *service) verifyAssetInputPrevOut(
	ctx context.Context,
	input extension.AssetInput,
	prev wire.OutPoint,
	arkTx wire.MsgTx,
) error {

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

	decodedArkTx, err := psbt.NewFromRawBytes(strings.NewReader(offchainTx.ArkTx), true)
	if err != nil {
		return fmt.Errorf("error decoding Ark Tx: %s", err)
	}

	var assetGroup *extension.AssetPacket

	for _, output := range decodedArkTx.UnsignedTx.TxOut {
		if extension.ContainsAssetPacket(output.PkScript) {
			assetGp, err := extension.DecodeAssetPacket(*output)
			if err != nil {
				return fmt.Errorf("error decoding asset Opreturn: %s", err)
			}
			assetGroup = assetGp
			break
		}
	}
	if assetGroup == nil {
		return fmt.Errorf("asset packet missing in offchain tx %s", prev.Hash)
	}

	// verify asset input in present in assetGroup.Inputs
	totalAssetOuts := make([]extension.AssetOutput, 0)
	for _, asset := range assetGroup.Assets {
		totalAssetOuts = append(totalAssetOuts, asset.Outputs...)
	}

	for _, assetOut := range totalAssetOuts {
		if assetOut.Vout == prev.Index && input.Amount == assetOut.Amount {
			return nil
		}
	}

	return fmt.Errorf("asset output %d not found", prev.Index)

}

func sumAssetInputs(inputs []extension.AssetInput) uint64 {
	total := uint64(0)
	for _, in := range inputs {
		total += in.Amount
	}
	return total
}

func sumAssetOutputs(outputs []extension.AssetOutput) uint64 {
	total := uint64(0)
	for _, out := range outputs {
		total += out.Amount
	}
	return total
}

func ensureUniqueAssetVouts(assets []extension.AssetGroup) error {
	seen := make(map[uint32]struct{})
	for _, grpAsset := range assets {
		for _, out := range grpAsset.Outputs {
			if out.Type != extension.AssetTypeLocal {
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

func (s *service) ensureAssetPresence(
	ctx context.Context,
	assets []extension.AssetGroup,
	asset extension.AssetId,
) error {
	if len(assets) == 0 {
		return fmt.Errorf("no assets provided for control asset validation")
	}

	for _, asst := range assets {
		if asst.AssetId != nil && (*asst.AssetId == asset) {
			return nil
		}
	}

	return fmt.Errorf("missing control asset %s in transaction", asset.ToString())
}
