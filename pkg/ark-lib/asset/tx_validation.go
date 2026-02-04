package asset

import (
	"bytes"
	"context"
	errs "errors"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/wire"
)

type AssetTxo struct {
	AssetID string
	Amount uint64
}

type ControlAssetSource interface {
	GetControlAsset(ctx context.Context, assetID string) (string, error)
}

// validateAssetTransaction validates that asset packet data matches the transaction inputs and outputs
func ValidateAssetTransaction(
	ctx context.Context, tx *wire.MsgTx, assetPrevouts map[int][]AssetTxo, ctrlSrc ControlAssetSource,
) errors.Error {
	packet, err := NewPacketFromTx(tx)
	if err != nil {
		if errs.Is(err, AssetPacketNotFoundError{tx.TxID()}) {
			if len(assetPrevouts) > 0 {
				return errors.ASSET_VALIDATION_FAILED.New("asset packet not found in tx %s", tx.TxID())
			}
			return nil
		}
		return errors.ASSET_VALIDATION_FAILED.New("error creating asset packet: %w", err)
	}
	
	// validate every asset in the input assets list is present in the packet
	if err := validateInputAssets(assetPrevouts, packet); err != nil {
		return err
	}

	for groupIndex, group := range packet {
		assetID := ""

		// verify the issuance transaction references a valid control asset
		if group.IsIssuance() {
			assetID = AssetId{
				Txid:  tx.TxHash(),
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
			if err := validateReissuance(ctx, packet, group, ctrlSrc); err != nil {
				return err
			}
		}

		// validate inputs and outputs are related to real transaction ins/outs
		if err := validateGroupOutputs(tx, assetID, group); err != nil {
			return err
		}
		if err := validateGroupInputs(tx, assetID, assetPrevouts, group); err != nil {
			return err
		}
	}

	return nil
}

// validateReissuance validates the control asset of a reissuance asset group
// it verifies the control asset of the reissuance is present in the packet
func validateReissuance(
	ctx context.Context,
	packet Packet,
	group AssetGroup,
	ctrlAssetSource ControlAssetSource,
) errors.Error {
	if ctrlAssetSource == nil {
		return errors.ASSET_VALIDATION_FAILED.New("control asset source is nil, cannot validate reissuance")
	}

	assetID := group.AssetId.String()

	ctrlAssetID, err := ctrlAssetSource.GetControlAsset(ctx, assetID)
	if err != nil {
		return errors.ASSET_VALIDATION_FAILED.New("error retrieving asset %s: %w", assetID, err).
			WithMetadata(errors.AssetValidationMetadata{AssetID: assetID})
	}
	if len(ctrlAssetID) == 0 {
		return errors.CONTROL_ASSET_INVALID.New("asset %s does not have a control asset", assetID).
			WithMetadata(errors.ControlAssetMetadata{AssetID: assetID})
	}

	controlAssetGroup := findAssetGroupByAssetId(packet, ctrlAssetID)
	if controlAssetGroup == nil {
		return errors.ASSET_NOT_FOUND.New("control asset %s not found in the packet", ctrlAssetID).
			WithMetadata(errors.AssetValidationMetadata{AssetID: ctrlAssetID})
	}

	return nil
}

// validateIssuance validates the control asset of an issuance asset group
// if it's present and referenced by group, it must be issued in the same transaction
func validateIssuance(packet Packet, grp AssetGroup) errors.Error {
	if grp.ControlAsset == nil {
		return nil
	}

	if grp.ControlAsset.Type == AssetRefByID {
		// by id means the control asset is an existing asset
		// no need to validate anything, not the operator's responsibility if you specify non existent asset id
		return nil
	}

	if grp.ControlAsset.Type == AssetRefByGroup {
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

		return nil
	}

	return errors.ASSET_VALIDATION_FAILED.New("invalid control asset reference type for issuance")
}

// validateInputVtxoAssets ensures every asset in the spentVtxos list is present in the packet, and that the amounts match
func validateInputAssets(assetPrevouts map[int][]AssetTxo, packet Packet) errors.Error {
	for inputIndex, assets := range assetPrevouts {
		for _, asst := range assets {
			assetGroup := findAssetGroupByAssetId(packet, asst.AssetID)
			if assetGroup == nil {
				return errors.ASSET_NOT_FOUND.New(
					"input %d owns asset %s but it's not present in the packet",
					inputIndex,
					asst.AssetID,
				).
					WithMetadata(errors.AssetValidationMetadata{AssetID: asst.AssetID})
			}

			foundVtxoInput := false
			for _, input := range assetGroup.Inputs {
				if input.Vin == uint16(inputIndex) {
					foundVtxoInput = true
					if input.Amount != asst.Amount {
						return errors.ASSET_INPUT_INVALID.New(
							"input %d owns asset %s but amount mismatch: %d != %d",
							inputIndex, asst.AssetID, input.Amount, asst.Amount).
							WithMetadata(errors.AssetInputMetadata{AssetID: asst.AssetID})
					}
					break
				}
			}

			if !foundVtxoInput {
				return errors.ASSET_INPUT_INVALID.New(
					"input %d owns asset %s but it's not present in the asset group inputs",
					inputIndex, asst.AssetID).
					WithMetadata(errors.AssetInputMetadata{AssetID: asst.AssetID})
			}
		}
	}

	return nil
}

// validateGroupOutputs ensures every output index referenced in the asset group is present in the ark tx
func validateGroupOutputs(arkTx *wire.MsgTx, assetID string, grp AssetGroup) errors.Error {
	if len(grp.Outputs) == 0 {
		return nil
	}

	assetPacketIndex, anchorIndex := -1, -1
	for outputIndex, output := range arkTx.TxOut {
		if bytes.Equal(output.PkScript, txutils.ANCHOR_PKSCRIPT) {
			anchorIndex = outputIndex
			continue
		}
		if IsAssetPacket(output.PkScript) {
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
	arkTx *wire.MsgTx, assetID string, inputAssets map[int][]AssetTxo, grp AssetGroup,
) errors.Error {
	if len(grp.Inputs) == 0 {
		return nil
	}

	for i, input := range grp.Inputs {
		// intent input type is always created by arkd operator, so if we receive one from tx submitted by user, it's invalid
		if input.Type == AssetTypeIntent {
			return errors.ASSET_INPUT_INVALID.New("unexpected asset input type: %s", input.Type).
				WithMetadata(errors.AssetInputMetadata{InputIndex: int(input.Vin), AssetID: assetID})
		}

		if int(input.Vin) >= len(arkTx.TxIn) {
			return errors.ASSET_INPUT_INVALID.New(
				"asset input index out of range: %d (%d inputs)", input.Vin, len(arkTx.TxIn)).
				WithMetadata(errors.AssetInputMetadata{InputIndex: int(input.Vin), AssetID: assetID})
		}

		assets, ok := inputAssets[int(input.Vin)]
		if !ok {
			return errors.ASSET_INPUT_INVALID.New(
				"asset input %d references input %d which does not contain any assets", i, int(input.Vin)).
				WithMetadata(errors.AssetInputMetadata{InputIndex: int(input.Vin), AssetID: assetID})
		}

		// verify vtxo holds the referenced asset, and amount matches
		vtxoHasAsset := false
		for _, asst := range assets {
			if asst.AssetID == assetID {
				if asst.Amount != input.Amount {
					return errors.ASSET_INPUT_INVALID.New(
						"asset input %d references input with asset %s but amount mismatch: %d != %d",
						i, asst.AssetID, asst.Amount, input.Amount).
						WithMetadata(errors.AssetInputMetadata{InputIndex: int(input.Vin), AssetID: assetID})
				}

				vtxoHasAsset = true
				break
			}
		}

		if !vtxoHasAsset {
			return errors.ASSET_INPUT_INVALID.New(
				"asset input %d references input with asset %s but asset not found in tx input %d",
				i, assetID, int(input.Vin),
			).
				WithMetadata(errors.AssetInputMetadata{InputIndex: int(input.Vin), AssetID: assetID})
		}
	}

	return nil
}

func findAssetGroupByAssetId(packet Packet, assetId string) *AssetGroup {
	for _, g := range packet {
		if g.AssetId != nil && g.AssetId.String() == assetId {
			return &g
		}
	}

	return nil
}
