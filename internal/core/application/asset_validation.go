package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type assetValidationState int

const (
	assetValidationDecode assetValidationState = iota
	assetValidationControl
	assetValidationGroup
	assetValidationDone
)

type assetValidationMachine struct {
	ctx             context.Context
	arkTx           wire.MsgTx
	checkpointTxMap map[string]string
	opReturnOutput  wire.TxOut
	assets          []extension.AssetGroup
	groupIndex      int
}

type controlAssetState int

const (
	controlAssetStart controlAssetState = iota
	controlAssetIssuance
	controlAssetReissuance
	controlAssetDone
)

type controlAssetMachine struct {
	ctx    context.Context
	assets []extension.AssetGroup
	asset  extension.AssetGroup
	state  controlAssetState
}

func (s *service) validateAssetTransition(
	ctx context.Context,
	arkTx wire.MsgTx,
	checkpointTxMap map[string]string,
	opReturnOutput wire.TxOut,
) error {
	machine := assetValidationMachine{
		ctx:             ctx,
		arkTx:           arkTx,
		checkpointTxMap: checkpointTxMap,
		opReturnOutput:  opReturnOutput,
	}
	return machine.run(s)
}

func (m *assetValidationMachine) run(s *service) error {
	state := assetValidationDecode

	for {
		switch state {
		case assetValidationDecode:
			decodedAssetPacket, err := extension.DecodeAssetPacket(m.opReturnOutput)
			if err != nil {
				return errors.ASSET_PACKET_INVALID.New("error decoding asset from opreturn: %s", err).
					WithMetadata(errors.AssetValidationMetadata{Message: err.Error()})
			}

			m.assets = decodedAssetPacket.Assets
			m.groupIndex = 0
			state = assetValidationControl
		case assetValidationControl:
			if err := s.validateControlAssets(m.ctx, m.assets); err != nil {
				return err
			}
			state = assetValidationGroup
		case assetValidationGroup:
			if m.groupIndex >= len(m.assets) {
				state = assetValidationDone
				continue
			}

			if err := s.validateAssetGroup(m.ctx, m.arkTx, m.checkpointTxMap, m.assets, m.groupIndex); err != nil {
				return err
			}

			m.groupIndex++
		case assetValidationDone:
			return nil
		default:
			return errors.ASSET_VALIDATION_FAILED.New("invalid asset validation state %d", state).
				WithMetadata(errors.AssetValidationMetadata{})
		}
	}
}

func (s *service) validateControlAssets(ctx context.Context, assets []extension.AssetGroup) error {
	for _, asst := range assets {
		machine := controlAssetMachine{
			ctx:    ctx,
			assets: assets,
			asset:  asst,
			state:  controlAssetStart,
		}
		if err := machine.run(s); err != nil {
			return err
		}
	}

	return nil
}

func (m *controlAssetMachine) run(s *service) error {
	for {
		switch m.state {
		case controlAssetStart:
			m.state = m.classify()
		case controlAssetIssuance:
			if err := m.validateIssuance(s); err != nil {
				return err
			}
			m.state = controlAssetDone
		case controlAssetReissuance:
			if err := m.validateReissuance(s); err != nil {
				return err
			}
			m.state = controlAssetDone
		case controlAssetDone:
			return nil
		default:
			return errors.CONTROL_ASSET_INVALID.New("invalid control asset validation state %d", m.state).
				WithMetadata(errors.ControlAssetMetadata{})
		}
	}
}

func (m *controlAssetMachine) classify() controlAssetState {
	if m.asset.AssetId == nil {
		return controlAssetIssuance
	}
	return controlAssetReissuance
}

func (m *controlAssetMachine) validateIssuance(s *service) error {
	if m.asset.ControlAsset == nil {
		return nil
	}

	switch m.asset.ControlAsset.Type {
	case extension.AssetRefByGroup:
		if int(m.asset.ControlAsset.GroupIndex) >= len(m.assets) {
			return errors.CONTROL_ASSET_INVALID.New(
				"control asset group index %d out of range for issuance",
				m.asset.ControlAsset.GroupIndex,
			).WithMetadata(errors.ControlAssetMetadata{
				GroupIndex: int(m.asset.ControlAsset.GroupIndex),
			})
		}
	case extension.AssetRefByID:
		controlAssetIDStr := m.asset.ControlAsset.AssetId.ToString()
		assetGroup, err := s.repoManager.Assets().GetAssetGroupByID(m.ctx, controlAssetIDStr)
		if err != nil {
			return errors.CONTROL_ASSET_INVALID.New(
				"error retrieving control asset %s for issuance: %w",
				controlAssetIDStr,
				err,
			).WithMetadata(errors.ControlAssetMetadata{
				ControlAssetID: controlAssetIDStr,
			})
		}
		if assetGroup == nil {
			return errors.CONTROL_ASSET_NOT_FOUND.New(
				"control asset %s does not exist for issuance",
				controlAssetIDStr,
			).WithMetadata(errors.ControlAssetMetadata{
				ControlAssetID: controlAssetIDStr,
			})
		}
	default:
		return errors.CONTROL_ASSET_INVALID.New("invalid control asset reference for issuance").
			WithMetadata(errors.ControlAssetMetadata{})
	}

	return nil
}

func (m *controlAssetMachine) validateReissuance(s *service) error {
	totalInputAmount := sumAssetInputs(m.asset.Inputs)
	totalOutputAmount := sumAssetOutputs(m.asset.Outputs)
	if totalOutputAmount <= totalInputAmount {
		return nil
	}

	if m.asset.AssetId == nil {
		return errors.ASSET_VALIDATION_FAILED.New("missing asset ID").
			WithMetadata(errors.AssetValidationMetadata{Message: "asset ID required for reissuance"})
	}

	assetID := m.asset.AssetId.ToString()
	controlAssetDetails, err := s.repoManager.Assets().GetAssetGroupByID(m.ctx, assetID)
	if err != nil {
		return errors.ASSET_VALIDATION_FAILED.New("error retrieving asset %s: %w", assetID, err).
			WithMetadata(errors.AssetValidationMetadata{AssetID: assetID})
	}
	if controlAssetDetails == nil {
		return errors.ASSET_NOT_FOUND.New("asset %s does not exist", assetID).
			WithMetadata(errors.AssetValidationMetadata{AssetID: assetID})
	}

	controlAssetId := controlAssetDetails.ControlAssetID
	if controlAssetId == "" {
		return errors.CONTROL_ASSET_INVALID.New("asset %s does not have a control asset", assetID).
			WithMetadata(errors.ControlAssetMetadata{AssetID: assetID})
	}

	decodedControlAssetId, err := extension.AssetIdFromString(controlAssetId)
	if err != nil {
		return errors.CONTROL_ASSET_INVALID.New("error decoding control asset ID %s: %w", controlAssetId, err).
			WithMetadata(errors.ControlAssetMetadata{AssetID: assetID, ControlAssetID: controlAssetId})
	}
	if decodedControlAssetId == nil {
		return errors.CONTROL_ASSET_INVALID.New("invalid control asset ID %s", controlAssetId).
			WithMetadata(errors.ControlAssetMetadata{AssetID: assetID, ControlAssetID: controlAssetId})
	}

	if err := s.ensureAssetPresence(m.ctx, m.assets, *decodedControlAssetId); err != nil {
		return err
	}

	return nil
}

type assetGroupValidationState int

const (
	assetGroupValidateExists assetGroupValidationState = iota
	assetGroupValidateOutputs
	assetGroupValidateInputs
	assetGroupDone
)

type assetGroupValidationMachine struct {
	ctx             context.Context
	arkTx           wire.MsgTx
	checkpointTxMap map[string]string
	assets          []extension.AssetGroup
	groupIndex      int
	state           assetGroupValidationState
	inputIndex      int
}

func (s *service) validateAssetGroup(
	ctx context.Context,
	arkTx wire.MsgTx,
	checkpointTxMap map[string]string,
	assetPacketList []extension.AssetGroup,
	groupIndex int,
) error {
	machine := assetGroupValidationMachine{
		ctx:             ctx,
		arkTx:           arkTx,
		checkpointTxMap: checkpointTxMap,
		assets:          assetPacketList,
		groupIndex:      groupIndex,
		state:           assetGroupValidateExists,
	}
	return machine.run(s)
}

func (m *assetGroupValidationMachine) run(s *service) error {
	grpAsset := m.group()
	for {
		switch m.state {
		case assetGroupValidateExists:
			if grpAsset.AssetId != nil {
				assetID := grpAsset.AssetId.ToString()
				gp, err := s.repoManager.Assets().GetAssetGroupByID(m.ctx, assetID)
				if err != nil {
					return errors.ASSET_VALIDATION_FAILED.New(
						"error retrieving asset group %s: %w",
						assetID,
						err,
					).WithMetadata(errors.AssetValidationMetadata{AssetID: assetID})
				}
				if gp == nil {
					return errors.ASSET_NOT_FOUND.New("asset group %s does not exist", assetID).
						WithMetadata(errors.AssetValidationMetadata{AssetID: assetID})
				}
			}
			m.state = assetGroupValidateOutputs
		case assetGroupValidateOutputs:
			if err := m.validateOutputs(s); err != nil {
				return err
			}
			m.state = assetGroupValidateInputs
		case assetGroupValidateInputs:
			if m.inputIndex >= len(grpAsset.Inputs) {
				m.state = assetGroupDone
				continue
			}

			input := grpAsset.Inputs[m.inputIndex]
			if err := m.validateInput(s, input); err != nil {
				return err
			}
			m.inputIndex++
		case assetGroupDone:
			return nil
		default:
			return errors.ASSET_VALIDATION_FAILED.New("invalid asset group validation state %d", m.state).
				WithMetadata(errors.AssetValidationMetadata{})
		}
	}
}

func (m *assetGroupValidationMachine) group() extension.AssetGroup {
	return m.assets[m.groupIndex]
}

func (m *assetGroupValidationMachine) validateOutputs(s *service) error {
	machine := assetOutputValidationMachine{
		ctx:        m.ctx,
		arkTx:      m.arkTx,
		assetsList: m.assets,
		assetGp:    m.group(),
		state:      assetOutputInit,
	}
	return machine.run(s)
}

func (m *assetGroupValidationMachine) validateInput(s *service, input extension.AssetInput) error {
	grpAsset := m.group()
	if input.Type == extension.AssetTypeTeleport {
		if grpAsset.AssetId == nil {
			return errors.TELEPORT_VALIDATION_FAILED.New("asset ID is required for teleport input validation").
				WithMetadata(errors.TeleportValidationMetadata{})
		}

		txHash, err := chainhash.NewHash(input.Witness.IntentId)
		if err != nil {
			return errors.TELEPORT_VALIDATION_FAILED.New("invalid intent ID for teleport input validation: %w", err).
				WithMetadata(errors.TeleportValidationMetadata{})
		}

		intent, err := s.repoManager.Rounds().GetIntentByTxid(context.Background(), txHash.String())
		if err != nil {
			return errors.TELEPORT_VALIDATION_FAILED.New("error retrieving intent for teleport input validation: %w", err).
				WithMetadata(errors.TeleportValidationMetadata{})
		}

		decodedProof, err := psbt.NewFromRawBytes(strings.NewReader(intent.Proof), true)
		if err != nil {
			return errors.TELEPORT_VALIDATION_FAILED.New("error decoding intent proof for teleport input validation: %w", err).
				WithMetadata(errors.TeleportValidationMetadata{})
		}

		if err := s.validateTeleportInput(*decodedProof, m.arkTx, *grpAsset.AssetId, uint32(input.Vin), input.Witness.Script); err != nil {
			return err
		}
		return nil
	}

	if int(input.Vin) >= len(m.arkTx.TxIn) {
		return errors.ASSET_INPUT_INVALID.New("asset input index out of range: %d", input.Vin).
			WithMetadata(errors.AssetInputMetadata{InputIndex: int(input.Vin)})
	}

	checkpointOutpoint := m.arkTx.TxIn[input.Vin].PreviousOutPoint
	checkpointTxHex, ok := m.checkpointTxMap[checkpointOutpoint.Hash.String()]
	if !ok {
		return errors.CHECKPOINT_TX_NOT_FOUND.New(
			"checkpoint tx %s not found for asset input %d",
			checkpointOutpoint.Hash,
			input.Vin,
		).WithMetadata(errors.CheckpointValidationMetadata{
			Txid:       checkpointOutpoint.Hash.String(),
			InputIndex: int(input.Vin),
		})
	}

	checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(checkpointTxHex), true)
	if err != nil {
		return errors.CHECKPOINT_TX_INVALID.New("failed to decode checkpoint tx %s: %w", checkpointOutpoint.Hash, err).
			WithMetadata(errors.CheckpointValidationMetadata{Txid: checkpointOutpoint.Hash.String()})
	}
	if len(checkpointPtx.UnsignedTx.TxIn) == 0 {
		return errors.CHECKPOINT_TX_INVALID.New("checkpoint tx %s missing input", checkpointOutpoint.Hash).
			WithMetadata(errors.CheckpointValidationMetadata{Txid: checkpointOutpoint.Hash.String()})
	}

	prev := checkpointPtx.UnsignedTx.TxIn[0].PreviousOutPoint

	if err := s.verifyAssetInputPrevOut(m.ctx, input, prev); err != nil {
		return err
	}

	return nil
}

type assetOutputValidationState int

const (
	assetOutputInit assetOutputValidationState = iota
	assetOutputCollect
	assetOutputCountCheck
	assetOutputTeleportCheck
	assetOutputDone
)

type assetOutputValidationMachine struct {
	ctx             context.Context
	arkTx           wire.MsgTx
	assetsList      []extension.AssetGroup
	assetGp         extension.AssetGroup
	state           assetOutputValidationState
	processed       int
	sumInputs       uint64
	sumOutputs      uint64
	teleportInputs  map[string]uint64
	localScriptAmts map[string]uint64
}

func (m *assetOutputValidationMachine) run(s *service) error {
	for {
		switch m.state {
		case assetOutputInit:
			m.sumInputs = sumAssetInputs(m.assetGp.Inputs)
			m.sumOutputs = sumAssetOutputs(m.assetGp.Outputs)
			m.teleportInputs = make(map[string]uint64)
			m.localScriptAmts = make(map[string]uint64)
			m.processed = 0
			for _, in := range m.assetGp.Inputs {
				if in.Type == extension.AssetTypeTeleport {
					teleportScriptHex := hex.EncodeToString(in.Witness.Script[:])
					m.teleportInputs[teleportScriptHex] += in.Amount
				}
			}
			m.state = assetOutputCollect
		case assetOutputCollect:
			for _, assetOut := range m.assetGp.Outputs {
				switch assetOut.Type {
				case extension.AssetTypeLocal:
					for index, txout := range m.arkTx.TxOut {
						if index == int(assetOut.Vout) {
							m.localScriptAmts[hex.EncodeToString(txout.PkScript)] += assetOut.Amount
							m.processed++
							break
						}
					}
				case extension.AssetTypeTeleport:
					m.processed++
				default:
					return errors.ASSET_OUTPUT_INVALID.New("unknown asset output type %d", assetOut.Type).
						WithMetadata(errors.AssetOutputMetadata{OutputType: int(assetOut.Type)})
				}
			}
			m.state = assetOutputCountCheck
		case assetOutputCountCheck:
			if m.processed != len(m.assetGp.Outputs) {
				return errors.ASSET_OUTPUT_INVALID.New(
					"not all asset outputs verified: processed %d of %d",
					m.processed, len(m.assetGp.Outputs),
				).WithMetadata(errors.AssetOutputMetadata{})
			}
			m.state = assetOutputTeleportCheck
		case assetOutputTeleportCheck:
			// Teleport redemptions must land on a local output with the same script.
			for scriptHex, inAmount := range m.teleportInputs {
				outAmount, exists := m.localScriptAmts[scriptHex]
				if !exists {
					return errors.TELEPORT_VALIDATION_FAILED.New(
						"teleport input script %s not found in output",
						scriptHex,
					).WithMetadata(errors.TeleportValidationMetadata{Script: scriptHex})
				}
				if outAmount > inAmount {
					// verify if extra amount is covered by existing input
					if m.sumInputs == m.sumOutputs {
						continue
					}

					assetID := m.assetGp.AssetId.ToString()
					controlAssetDetails, err := s.repoManager.Assets().GetAssetGroupByID(m.ctx, assetID)
					if err != nil {
						return errors.ASSET_VALIDATION_FAILED.New(
							"error retrieving asset %s: %w",
							assetID,
							err,
						).WithMetadata(errors.AssetValidationMetadata{AssetID: assetID})
					}

					if controlAssetDetails == nil {
						return errors.ASSET_NOT_FOUND.New("asset %s does not exist", assetID).
							WithMetadata(errors.AssetValidationMetadata{AssetID: assetID})
					}

					controlAssetId := controlAssetDetails.ControlAssetID
					if controlAssetId == "" {
						return errors.CONTROL_ASSET_INVALID.New(
							"asset %s does not have a control asset",
							assetID,
						).WithMetadata(errors.ControlAssetMetadata{AssetID: assetID})
					}

					decodedControlAssetId, err := extension.AssetIdFromString(controlAssetId)
					if err != nil {
						return errors.CONTROL_ASSET_INVALID.New(
							"error decoding control asset ID %s: %w",
							controlAssetId,
							err,
						).WithMetadata(errors.ControlAssetMetadata{
							AssetID:        assetID,
							ControlAssetID: controlAssetId,
						})
					}

					if decodedControlAssetId == nil {
						return errors.CONTROL_ASSET_INVALID.New("invalid control asset ID %s", controlAssetId).
							WithMetadata(errors.ControlAssetMetadata{
								AssetID:        assetID,
								ControlAssetID: controlAssetId,
							})
					}

					if err := s.ensureAssetPresence(m.ctx, m.assetsList, *decodedControlAssetId); err != nil {
						return err
					}
				}
			}
			m.state = assetOutputDone
		case assetOutputDone:
			return nil
		default:
			return errors.ASSET_OUTPUT_INVALID.New("invalid asset output validation state %d", m.state).
				WithMetadata(errors.AssetOutputMetadata{})
		}
	}
}

func (s *service) validateTeleportInput(
	intentProof psbt.Packet,
	arkTx wire.MsgTx,
	assetId extension.AssetId,
	index uint32,
	script []byte,
) error {
	// validate teleport script exists in intent proof
	assetPacket, _, err := extension.DeriveAssetPacketFromTx(*intentProof.UnsignedTx)
	if err != nil {
		return errors.TELEPORT_VALIDATION_FAILED.New("error deriving asset packet from intent proof: %s", err).
			WithMetadata(errors.TeleportValidationMetadata{AssetID: assetId.ToString()})
	}

	if assetPacket == nil {
		return errors.ASSET_PACKET_INVALID.New("no asset packet found in intent proof").
			WithMetadata(errors.AssetValidationMetadata{})
	}

	teleportOutputFound := false
	for _, assetGroup := range assetPacket.Assets {
		for i, assetOutput := range assetGroup.Outputs {
			if assetOutput.Type == extension.AssetTypeTeleport &&
				bytes.Equal(assetOutput.Script, script) &&
				assetId == *assetGroup.AssetId &&
				index == uint32(i) {
				teleportOutputFound = true
				break
			}
		}
	}

	if !teleportOutputFound {
		return errors.TELEPORT_VALIDATION_FAILED.New(
			"teleport output not found in intent proof for asset %s index %d",
			assetId.ToString(),
			index,
		).WithMetadata(errors.TeleportValidationMetadata{
			AssetID:     assetId.ToString(),
			OutputIndex: int(index),
		})
	}

	return nil

}

func (s *service) verifyAssetInputPrevOut(
	ctx context.Context,
	input extension.AssetInput,
	prev wire.OutPoint,
) error {
	txid := prev.Hash.String()

	offchainTx, err := s.repoManager.OffchainTxs().GetOffchainTx(ctx, txid)
	if err != nil {
		return errors.OFFCHAIN_TX_INVALID.New("error retrieving offchain tx %s: %w", txid, err).
			WithMetadata(errors.OffchainTxValidationMetadata{Txid: txid})
	}
	if offchainTx == nil {
		return errors.OFFCHAIN_TX_INVALID.New("offchain tx %s not found in rounds or offchain storage", txid).
			WithMetadata(errors.OffchainTxValidationMetadata{Txid: txid})
	}
	if !offchainTx.IsFinalized() {
		return errors.OFFCHAIN_TX_INVALID.New("offchain tx %s is failed", txid).
			WithMetadata(errors.OffchainTxValidationMetadata{Txid: txid})
	}

	decodedArkTx, err := psbt.NewFromRawBytes(strings.NewReader(offchainTx.ArkTx), true)
	if err != nil {
		return errors.OFFCHAIN_TX_INVALID.New("error decoding Ark Tx: %s", err).
			WithMetadata(errors.OffchainTxValidationMetadata{Txid: txid})
	}

	var assetGroup *extension.AssetPacket

	for _, output := range decodedArkTx.UnsignedTx.TxOut {
		if extension.ContainsAssetPacket(output.PkScript) {
			assetGp, err := extension.DecodeAssetPacket(*output)
			if err != nil {
				return errors.ASSET_PACKET_INVALID.New("error decoding asset Opreturn: %s", err).
					WithMetadata(errors.AssetValidationMetadata{})
			}
			assetGroup = assetGp
			break
		}
	}
	if assetGroup == nil {
		return errors.ASSET_PACKET_INVALID.New("asset packet missing in offchain tx %s", txid).
			WithMetadata(errors.AssetValidationMetadata{})
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

	return errors.ASSET_OUTPUT_INVALID.New("asset output %d not found", prev.Index).
		WithMetadata(errors.AssetOutputMetadata{OutputIndex: int(prev.Index)})

}

func (s *service) ensureAssetPresence(
	ctx context.Context,
	assets []extension.AssetGroup,
	asset extension.AssetId,
) error {
	if len(assets) == 0 {
		return errors.CONTROL_ASSET_INVALID.New("no assets provided for control asset validation").
			WithMetadata(errors.ControlAssetMetadata{})
	}

	for _, asst := range assets {
		if asst.AssetId != nil && (*asst.AssetId == asset) {
			return nil
		}
	}

	assetID := asset.ToString()
	return errors.CONTROL_ASSET_NOT_FOUND.New("missing control asset %s in transaction", assetID).
		WithMetadata(errors.ControlAssetMetadata{ControlAssetID: assetID})
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
