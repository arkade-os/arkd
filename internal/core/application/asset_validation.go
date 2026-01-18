package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/btcsuite/btcd/btcutil/psbt"
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
				return fmt.Errorf("error decoding asset from opreturn: %s", err)
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
			return fmt.Errorf("invalid asset validation state %d", state)
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
			return fmt.Errorf("invalid control asset validation state %d", m.state)
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
			return fmt.Errorf("control asset group index %d out of range for issuance", m.asset.ControlAsset.GroupIndex)
		}
	case extension.AssetRefByID:
		controlAssetIDStr := m.asset.ControlAsset.AssetId.ToString()
		assetGroup, err := s.repoManager.Assets().GetAssetGroupByID(m.ctx, controlAssetIDStr)
		if err != nil {
			return fmt.Errorf("error retrieving control asset %s for issuance: %w", controlAssetIDStr, err)
		}
		if assetGroup == nil {
			return fmt.Errorf("control asset %s does not exist for issuance", controlAssetIDStr)
		}
	default:
		return fmt.Errorf("invalid control asset reference for issuance")
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
		return fmt.Errorf("missing asset ID")
	}

	assetID := m.asset.AssetId.ToString()
	controlAssetDetails, err := s.repoManager.Assets().GetAssetGroupByID(m.ctx, assetID)
	if err != nil {
		return fmt.Errorf("error retrieving asset %s: %w", assetID, err)
	}
	if controlAssetDetails == nil {
		return fmt.Errorf("asset %s does not exist", assetID)
	}

	controlAssetId := controlAssetDetails.ControlAssetID
	if controlAssetId == "" {
		return fmt.Errorf("asset %s does not have a control asset", assetID)
	}

	decodedControlAssetId, err := extension.AssetIdFromString(controlAssetId)
	if err != nil {
		return fmt.Errorf("error decoding control asset ID %s: %w", controlAssetId, err)
	}
	if decodedControlAssetId == nil {
		return fmt.Errorf("invalid control asset ID %s", controlAssetId)
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
				gp, err := s.repoManager.Assets().GetAssetGroupByID(m.ctx, grpAsset.AssetId.ToString())
				if err != nil {
					return fmt.Errorf("error retrieving asset group %s: %w", grpAsset.AssetId.ToString(), err)
				}
				if gp == nil {
					return fmt.Errorf("asset group %s does not exist", grpAsset.AssetId.ToString())
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
			return fmt.Errorf("invalid asset group validation state %d", m.state)
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
		// TODO : Use Real Input proof
		var intentProof intent.Proof

		if grpAsset.AssetId == nil {
			return fmt.Errorf("asset ID is required for teleport input validation")
		}

		if err := s.validateTeleportInput(intentProof, m.arkTx, *grpAsset.AssetId, uint32(input.Vin), input.Witness.Script); err != nil {
			return err
		}
		return nil
	}

	if int(input.Vin) >= len(m.arkTx.TxIn) {
		return fmt.Errorf("asset input index out of range: %d", input.Vin)
	}

	checkpointOutpoint := m.arkTx.TxIn[input.Vin].PreviousOutPoint
	checkpointTxHex, ok := m.checkpointTxMap[checkpointOutpoint.Hash.String()]
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
					return fmt.Errorf("unknown asset output type %d", assetOut.Type)
				}
			}
			m.state = assetOutputCountCheck
		case assetOutputCountCheck:
			if m.processed != len(m.assetGp.Outputs) {
				return fmt.Errorf("not all asset outputs verified: processed %d of %d",
					m.processed, len(m.assetGp.Outputs))
			}
			m.state = assetOutputTeleportCheck
		case assetOutputTeleportCheck:
			// Teleport redemptions must land on a local output with the same script.
			for scriptHex, inAmount := range m.teleportInputs {
				outAmount, exists := m.localScriptAmts[scriptHex]
				if !exists {
					return fmt.Errorf("teleport input script %s not found in output", scriptHex)
				}
				if outAmount > inAmount {
					// verify if extra amount is covered by existing input
					if m.sumInputs == m.sumOutputs {
						continue
					}

					controlAssetDetails, err := s.repoManager.Assets().GetAssetGroupByID(m.ctx, m.assetGp.AssetId.ToString())
					if err != nil {
						return fmt.Errorf("error retrieving asset %s: %w", m.assetGp.AssetId.ToString(), err)
					}

					if controlAssetDetails == nil {
						return fmt.Errorf("asset %s does not exist", m.assetGp.AssetId.ToString())
					}

					controlAssetId := controlAssetDetails.ControlAssetID
					if controlAssetId == "" {
						return fmt.Errorf("asset %s does not have a control asset", m.assetGp.AssetId.ToString())
					}

					decodedControlAssetId, err := extension.AssetIdFromString(controlAssetId)
					if err != nil {
						return fmt.Errorf("error decoding control asset ID %s: %w", controlAssetId, err)
					}

					if decodedControlAssetId == nil {
						return fmt.Errorf("invalid control asset ID %s", controlAssetId)
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
			return fmt.Errorf("invalid asset output validation state %d", m.state)
		}
	}
}

func (s *service) validateTeleportInput(intentProof intent.Proof, arkTx wire.MsgTx, assetId extension.AssetId, index uint32, script []byte) error {
	// validate teleport script exists in intent proof
	assetPacket, _, err := extension.DeriveAssetPacketFromTx(*intentProof.UnsignedTx)
	if err != nil {
		return fmt.Errorf("error deriving asset packet from intent proof: %s", err)
	}

	if assetPacket == nil {
		return fmt.Errorf("no asset packet found in intent proof")
	}

	teleportOutputFound := false
	for _, assetGroup := range assetPacket.Assets {
		for i, assetOutput := range assetGroup.Outputs {
			if assetOutput.Type == extension.AssetTypeTeleport && bytes.Equal(assetOutput.Script, script) && assetId == *assetGroup.AssetId && index == uint32(i) {
				teleportOutputFound = true
				break
			}
		}
	}

	if !teleportOutputFound {
		return fmt.Errorf("teleport output not found in intent proof for asset %s index %d", assetId.ToString(), index)
	}

	return nil

}

func (s *service) verifyAssetInputPrevOut(
	ctx context.Context,
	input extension.AssetInput,
	prev wire.OutPoint,
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
