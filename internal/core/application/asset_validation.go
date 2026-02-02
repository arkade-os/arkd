package application

import (
	"bytes"
	"context"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

// validateAssetTransaction validates that asset packet data matches the transaction inputs and outputs
func (s *service) validateAssetTransaction(
	ctx context.Context, arkPtx *psbt.Packet, packet asset.Packet, spentVtxos []domain.Vtxo,
) errors.Error {
	// validate every asset in the spentVtxos list is present in the packet
	if err := validateInputVtxoAssets(arkPtx, spentVtxos, packet); err != nil {
		return err
	}

	for groupIndex, group := range packet {
		assetID := ""

		// verify the issuance transaction references a valid control asset
		if group.IsIssuance() {
			assetID = asset.AssetId{
				Txid:  arkPtx.UnsignedTx.TxHash(),
				Index: uint16(groupIndex),
			}.String()

			if err := validateIssuance(packet, group); err != nil {
				return err
			}
		} else {
			assetID = group.AssetId.String()
		}

		// verify the reissuance has the associated control asset present in the packet
		if group.IsReissuance() {
			if err := s.validateReissuance(ctx, packet, group); err != nil {
				return err
			}
		}

		// validate inputs and outputs are related to real transaction ins/outs
		if err := validateGroupOutputs(arkPtx.UnsignedTx, assetID, group); err != nil {
			return err
		}
		if err := validateGroupInputs(arkPtx.UnsignedTx, assetID, spentVtxos, group); err != nil {
			return err
		}
	}

	return nil
}

// validateReissuance validates the control asset of a reissuance asset group
// it verifies the control asset of the reissuance is present in the packet
func (s *service) validateReissuance(
	ctx context.Context,
	packet asset.Packet,
	group asset.AssetGroup,
) errors.Error {
	assetID := group.AssetId.String()

	assetInfos, err := s.repoManager.Assets().GetAssetGroupByID(ctx, assetID)
	if err != nil {
		return errors.ASSET_VALIDATION_FAILED.New("error retrieving asset %s: %w", assetID, err).
			WithMetadata(errors.AssetValidationMetadata{AssetID: assetID})
	}
	if assetInfos == nil {
		return errors.ASSET_NOT_FOUND.New("asset %s does not exist", assetID).
			WithMetadata(errors.AssetValidationMetadata{AssetID: assetID})
	}

	if len(assetInfos.ControlAssetID) == 0 {
		return errors.CONTROL_ASSET_INVALID.New("asset %s does not have a control asset", assetID).
			WithMetadata(errors.ControlAssetMetadata{AssetID: assetID})
	}

	controlAssetGroup := findAssetGroupByAssetId(packet, assetInfos.ControlAssetID)
	if controlAssetGroup == nil {
		return errors.ASSET_NOT_FOUND.New("control asset %s not found in the packet", assetInfos.ControlAssetID).
			WithMetadata(errors.AssetValidationMetadata{AssetID: assetInfos.ControlAssetID})
	}

	return nil
}

// validateIssuance validates the control asset of an issuance asset group
// if it's present and referenced by group, it must be issued in the same transaction
func validateIssuance(packet asset.Packet, grp asset.AssetGroup) errors.Error {
	if grp.ControlAsset == nil {
		return nil
	}

	if grp.ControlAsset.Type == asset.AssetRefByID {
		// by id means the control asset is an existing asset, it must be present in the packet
		// no need to validate anything, not the operator's responsibility if you specify non existent asset id
		return nil
	}

	if grp.ControlAsset.Type == asset.AssetRefByGroup {
		// by group means the control asset is minted in the same transaction
		if int(grp.ControlAsset.GroupIndex) >= len(packet) {
			return errors.ASSET_VALIDATION_FAILED.New(
				"control asset group index %d out of range", grp.ControlAsset.GroupIndex,
			)
		}

		controlAssetGroup := packet[grp.ControlAsset.GroupIndex]

		// fail if not an issuance
		if !controlAssetGroup.IsIssuance() {
			return errors.ASSET_VALIDATION_FAILED.New(
				"control asset referenced by group index %d is not an issuance",
				grp.ControlAsset.GroupIndex,
			)
		}
	}

	return errors.ASSET_VALIDATION_FAILED.New("invalid control asset reference type for issuance")
}

// validateInputVtxoAssets ensures every asset in the spentVtxos list is present in the packet, and that the amounts match
func validateInputVtxoAssets(
	arkPtx *psbt.Packet,
	spentVtxos []domain.Vtxo,
	packet asset.Packet,
) errors.Error {
	outpointToInputIndex := make(map[wire.OutPoint]int)
	for inputIndex, input := range arkPtx.UnsignedTx.TxIn {
		outpointToInputIndex[input.PreviousOutPoint] = inputIndex
	}

	for _, vtxo := range spentVtxos {
		outpoint, err := wire.NewOutPointFromString(vtxo.Outpoint.String())
		if err != nil {
			return errors.INTERNAL_ERROR.New(
				"error parsing outpoint %s: %w",
				vtxo.Outpoint.String(),
				err,
			)
		}

		vtxoInputIndex, ok := outpointToInputIndex[*outpoint]
		if !ok {
			return errors.INTERNAL_ERROR.New(
				"vtxo %s is not present in the ark tx",
				vtxo.Outpoint.String(),
			)
		}

		for _, asst := range vtxo.Assets {
			assetGroup := findAssetGroupByAssetId(packet, asst.AssetID)
			if assetGroup == nil {
				return errors.ASSET_NOT_FOUND.New(
					"vtxo %s owns asset %s but it's not present in the packet",
					vtxo.Outpoint.String(),
					asst.AssetID,
				).
					WithMetadata(errors.AssetValidationMetadata{AssetID: asst.AssetID})
			}

			foundVtxoInput := false
			for _, input := range assetGroup.Inputs {
				if input.Vin == uint16(vtxoInputIndex) {
					foundVtxoInput = true
					if input.Amount != asst.Amount {
						return errors.ASSET_INPUT_INVALID.New(
							"vtxo %s owns asset %s but amount mismatch: %d != %d",
							vtxo.Outpoint.String(), asst.AssetID, input.Amount, asst.Amount).
							WithMetadata(errors.AssetInputMetadata{AssetID: asst.AssetID})
					}
					break
				}
			}

			if !foundVtxoInput {
				return errors.ASSET_INPUT_INVALID.New(
					"vtxo %s owns asset %s but it's not present in the asset group inputs",
					vtxo.Outpoint.String(), asst.AssetID).
					WithMetadata(errors.AssetInputMetadata{AssetID: asst.AssetID})
			}
		}
	}

	return nil
}

// validateGroupOutputs ensures every output index referenced in the asset group is present in the ark tx
func validateGroupOutputs(arkTx *wire.MsgTx, assetID string, grp asset.AssetGroup) errors.Error {
	if len(grp.Outputs) == 0 {
		return nil
	}

	assetPacketIndex, anchorIndex := -1, -1
	for outputIndex, output := range arkTx.TxOut {
		if bytes.Equal(output.PkScript, txutils.ANCHOR_PKSCRIPT) {
			anchorIndex = outputIndex
			continue
		}
		if asset.IsAssetPacket(output.PkScript) {
			assetPacketIndex = outputIndex
		}
	}

	for _, assetOut := range grp.Outputs {
		vout := int(assetOut.Vout)

		// verify vout is in range
		if vout >= len(arkTx.TxOut) {
			return errors.ASSET_OUTPUT_INVALID.New(
				"asset output vout %d out of range (%d outputs)",
				vout, len(arkTx.TxOut),
			).WithMetadata(errors.AssetOutputMetadata{OutputIndex: int(assetOut.Vout), AssetID: assetID})
		}

		// verify referenced output is not the P2A output
		if vout == anchorIndex {
			return errors.ASSET_OUTPUT_INVALID.New(
				"asset output vout %d is an anchor output",
				vout,
			).WithMetadata(errors.AssetOutputMetadata{OutputIndex: vout, AssetID: assetID})
		}

		// verify referenced output is not the packet itself
		if vout == assetPacketIndex {
			return errors.ASSET_OUTPUT_INVALID.New(
				"asset output vout %d is a packet output",
				vout,
			).WithMetadata(errors.AssetOutputMetadata{OutputIndex: vout, AssetID: assetID})
		}
	}

	return nil
}

// validateGroupInputs ensures every input index referenced in the asset group is present in the ark tx
// and it matches the amount of the vtxo asset referenced by the input
func validateGroupInputs(
	arkTx *wire.MsgTx,
	assetID string,
	spentVtxos []domain.Vtxo,
	grp asset.AssetGroup,
) errors.Error {
	if len(grp.Inputs) == 0 {
		return nil
	}

	indexedVtxos := make(map[wire.OutPoint]domain.Vtxo)
	for _, vtxo := range spentVtxos {
		outpoint, err := wire.NewOutPointFromString(vtxo.Outpoint.String())
		if err != nil {
			return errors.INTERNAL_ERROR.New(
				"error parsing outpoint %s: %w",
				vtxo.Outpoint.String(),
				err,
			)
		}

		indexedVtxos[*outpoint] = vtxo
	}

	for _, input := range grp.Inputs {
		// intent input type is always created by arkd operator, so if we receive one from tx submitted by user, it's invalid
		if input.Type == asset.AssetTypeIntent {
			return errors.ASSET_INPUT_INVALID.New("unexpected asset input type: %s", input.Type).
				WithMetadata(errors.AssetInputMetadata{InputIndex: int(input.Vin), AssetID: assetID})
		}

		if int(input.Vin) >= len(arkTx.TxIn) {
			return errors.ASSET_INPUT_INVALID.New(
				"asset input index out of range: %d (%d inputs)", input.Vin, len(arkTx.TxIn)).
				WithMetadata(errors.AssetInputMetadata{InputIndex: int(input.Vin), AssetID: assetID})
		}

		inputOutpoint := arkTx.TxIn[input.Vin].PreviousOutPoint
		vtxo, ok := indexedVtxos[inputOutpoint]
		if !ok {
			return errors.ASSET_INPUT_INVALID.New(
				"asset input %d references outpoint %s which is not a valid vtxo", input.Vin, inputOutpoint.String()).
				WithMetadata(errors.AssetInputMetadata{InputIndex: int(input.Vin), AssetID: assetID})
		}

		// verify vtxo holds the referenced asset, and amount matches
		vtxoHasAsset := false
		for _, asst := range vtxo.Assets {
			if asst.AssetID == assetID {
				if asst.Amount != input.Amount {
					return errors.ASSET_INPUT_INVALID.New(
						"asset input %d references vtxo with asset %s but amount mismatch: %d != %d",
						input.Vin, asst.AssetID, asst.Amount, input.Amount).
						WithMetadata(errors.AssetInputMetadata{InputIndex: int(input.Vin), AssetID: assetID})
				}

				vtxoHasAsset = true
				break
			}
		}

		if !vtxoHasAsset {
			return errors.ASSET_INPUT_INVALID.New(
				"asset input %d references vtxo with asset %s but asset not found",
				input.Vin, assetID).
				WithMetadata(errors.AssetInputMetadata{InputIndex: int(input.Vin), AssetID: assetID})
		}
	}

	return nil
}

func findAssetGroupByAssetId(packet asset.Packet, assetId string) *asset.AssetGroup {
	for _, g := range packet {
		if g.AssetId != nil && g.AssetId.String() == assetId {
			return &g
		}
	}

	return nil
}
