package handlers

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

func parseIntentProofTx(i *arkv1.Intent) (*intent.Proof, error) {
	if i == nil {
		return nil, fmt.Errorf("missing intent")
	}
	proof := i.GetProof()
	if len(proof) <= 0 {
		return nil, fmt.Errorf("missing intent proof")
	}
	proofTx, err := psbt.NewFromRawBytes(strings.NewReader(proof), true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intent proof tx: %s", err)
	}
	return &intent.Proof{Packet: *proofTx}, nil
}

func parseRegisterIntent(
	intentProof *arkv1.Intent,
) (*intent.Proof, *intent.RegisterMessage, error) {
	proof, err := parseIntentProofTx(intentProof)
	if err != nil {
		return nil, nil, err
	}

	if len(intentProof.GetMessage()) <= 0 {
		return nil, nil, fmt.Errorf("missing message")
	}
	var message intent.RegisterMessage
	if err := message.Decode(intentProof.GetMessage()); err != nil {
		return nil, nil, fmt.Errorf("invalid intent message")
	}
	return proof, &message, nil
}

func parseEstimateFeeIntent(
	intentProof *arkv1.Intent,
) (*intent.Proof, *intent.EstimateIntentFeeMessage, error) {
	proof, err := parseIntentProofTx(intentProof)
	if err != nil {
		return nil, nil, err
	}

	if len(intentProof.GetMessage()) <= 0 {
		return nil, nil, fmt.Errorf("missing message")
	}
	var message intent.EstimateIntentFeeMessage
	if err := message.Decode(intentProof.GetMessage()); err != nil {
		return nil, nil, fmt.Errorf("invalid intent message")
	}
	return proof, &message, nil
}

func parseDeleteIntent(
	intentProof *arkv1.Intent,
) (*intent.Proof, *intent.DeleteMessage, error) {
	proof, err := parseIntentProofTx(intentProof)
	if err != nil {
		return nil, nil, err
	}

	if len(intentProof.GetMessage()) <= 0 {
		return nil, nil, fmt.Errorf("missing message")
	}
	var message intent.DeleteMessage
	if err := message.Decode(intentProof.GetMessage()); err != nil {
		return nil, nil, fmt.Errorf("invalid delete intent message")
	}
	return proof, &message, nil
}

func parseGetPendingTxIntent(
	intentProof *arkv1.Intent,
) (*intent.Proof, *intent.GetPendingTxMessage, error) {
	proof, err := parseIntentProofTx(intentProof)
	if err != nil {
		return nil, nil, err
	}

	if len(intentProof.GetMessage()) <= 0 {
		return nil, nil, fmt.Errorf("missing message")
	}
	var message intent.GetPendingTxMessage
	if err := message.Decode(intentProof.GetMessage()); err != nil {
		return nil, nil, fmt.Errorf("invalid get-pending-tx intent message")
	}

	return proof, &message, nil
}

func parseIntentId(id string) (string, error) {
	if len(id) <= 0 {
		return "", fmt.Errorf("missing intent id")
	}
	return id, nil
}

func parseBatchId(id string) (string, error) {
	if len(id) <= 0 {
		return "", fmt.Errorf("missing batch id")
	}
	return id, nil
}

func parseECPubkey(pubkey string) (string, error) {
	if len(pubkey) <= 0 {
		return "", fmt.Errorf("missing EC public key")
	}
	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		return "", fmt.Errorf("invalid format, expected hex")
	}
	if len(pubkeyBytes) != 33 {
		return "", fmt.Errorf("invalid length, expected 33 bytes")
	}
	if _, err := btcec.ParsePubKey(pubkeyBytes); err != nil {
		return "", fmt.Errorf("invalid cosigner public key %s", err)
	}
	return pubkey, nil
}

func parseNonces(noncesMap map[string]string) (tree.TreeNonces, error) {
	if len(noncesMap) <= 0 {
		return nil, fmt.Errorf("missing tree nonces")
	}
	nonces, err := tree.NewTreeNonces(noncesMap)
	if err != nil {
		return nil, fmt.Errorf("invalid tree nonces: %s", err)
	}
	return nonces, nil
}

func parseSignatures(signaturesMap map[string]string) (tree.TreePartialSigs, error) {
	if len(signaturesMap) <= 0 {
		return nil, fmt.Errorf("missing tree signatures")
	}
	signatures, err := tree.NewTreePartialSigs(signaturesMap)
	if err != nil {
		return nil, fmt.Errorf("invalid tree signatures %s", err)
	}
	return signatures, nil
}

// convert sats to string BTC
func convertSatsToBTCStr(sats uint64) string {
	btc := float64(sats) * 1e-8
	return fmt.Sprintf("%.8f", btc)
}

func toP2TR(pubkey string) string {
	return fmt.Sprintf("5120%s", pubkey)
}

// From app type to interface type

type vtxoList []domain.Vtxo

func (v vtxoList) toProto() []*arkv1.Vtxo {
	list := make([]*arkv1.Vtxo, 0, len(v))

	toAssets := func(vv domain.Vtxo) []*arkv1.Asset {
		if len(vv.Assets) <= 0 {
			return nil
		}
		assets := make([]*arkv1.Asset, 0)
		for _, asset := range vv.Assets {
			assets = append(assets, &arkv1.Asset{
				AssetId: asset.AssetID,
				// Amount:  asset.Amount,
				// get amount here
			})
		}
		return assets
	}

	for _, vv := range v {
		list = append(list, &arkv1.Vtxo{
			Outpoint: &arkv1.Outpoint{
				Txid: vv.Txid,
				Vout: vv.VOut,
			},
			Amount:          vv.Amount,
			CommitmentTxids: vv.CommitmentTxids,
			IsSpent:         vv.Spent,
			ExpiresAt:       vv.ExpiresAt,
			SpentBy:         vv.SpentBy,
			IsSwept:         vv.Swept,
			IsPreconfirmed:  vv.Preconfirmed,
			IsUnrolled:      vv.Unrolled,
			Script:          toP2TR(vv.PubKey),
			CreatedAt:       vv.CreatedAt,
			SettledBy:       vv.SettledBy,
			ArkTxid:         vv.ArkTxid,
			Assets:          toAssets(vv),
		})
	}

	return list
}

type txEvent application.TransactionEvent

func (t txEvent) toProto() *arkv1.TxNotification {
	var checkpointTxs map[string]*arkv1.TxData
	if len(t.CheckpointTxs) > 0 {
		checkpointTxs = make(map[string]*arkv1.TxData)
		for k, v := range t.CheckpointTxs {
			checkpointTxs[k] = &arkv1.TxData{
				Txid: v.Txid,
				Tx:   v.Tx,
			}
		}
	}
	return &arkv1.TxNotification{
		Txid:           t.Txid,
		Tx:             t.Tx,
		CheckpointTxs:  checkpointTxs,
		SpentVtxos:     vtxoList(t.SpentVtxos).toProto(),
		SpendableVtxos: vtxoList(t.SpendableVtxos).toProto(),
	}
}

type intentsInfo []application.IntentInfo

func (i intentsInfo) toProto() []*arkv1.IntentInfo {
	list := make([]*arkv1.IntentInfo, 0, len(i))
	for _, intent := range i {
		receivers := make([]*arkv1.Output, 0, len(intent.Receivers))

		for _, receiver := range intent.Receivers {
			out := &arkv1.Output{
				Amount: receiver.Amount,
			}
			if receiver.OnchainAddress != "" {
				out.Destination = &arkv1.Output_OnchainAddress{
					OnchainAddress: receiver.OnchainAddress,
				}
			} else {
				out.Destination = &arkv1.Output_VtxoScript{
					VtxoScript: receiver.VtxoScript,
				}
			}
			receivers = append(receivers, out)
		}

		inputs := make([]*arkv1.IntentInput, 0, len(intent.Inputs))
		for _, input := range intent.Inputs {
			inputs = append(inputs, &arkv1.IntentInput{
				Txid:   input.Txid,
				Vout:   input.VOut,
				Amount: input.Amount,
			})
		}

		boardingInputs := make([]*arkv1.IntentInput, 0, len(intent.BoardingInputs))
		for _, input := range intent.BoardingInputs {
			boardingInputs = append(boardingInputs, &arkv1.IntentInput{
				Txid:   input.Txid,
				Vout:   input.VOut,
				Amount: input.Amount,
			})
		}

		list = append(list, &arkv1.IntentInfo{
			Id:                  intent.Id,
			CreatedAt:           intent.CreatedAt.Unix(),
			Receivers:           receivers,
			Inputs:              inputs,
			BoardingInputs:      boardingInputs,
			CosignersPublicKeys: intent.Cosigners,
		})
	}
	return list
}

type scheduledSession struct {
	t *application.NextScheduledSession
}

func (s scheduledSession) toProto() *arkv1.ScheduledSession {
	if s.t == nil {
		return nil
	}
	return &arkv1.ScheduledSession{
		NextStartTime: s.t.StartTime.Unix(),
		NextEndTime:   s.t.EndTime.Unix(),
		Period:        int64(s.t.Period.Minutes()),
		Duration:      int64(s.t.Duration.Seconds()),
		Fees:          fees(s.t.Fees).toProto(),
	}
}

type fees application.FeeInfo

func (f fees) toProto() *arkv1.FeeInfo {
	return &arkv1.FeeInfo{
		TxFeeRate: strconv.FormatFloat(f.TxFeeRate, 'f', -1, 64),
		IntentFee: &arkv1.IntentFeeInfo{
			OffchainInput:  f.IntentFees.OffchainInputFee,
			OffchainOutput: f.IntentFees.OffchainOutputFee,
			OnchainInput:   f.IntentFees.OnchainInputFee,
			OnchainOutput:  f.IntentFees.OnchainOutputFee,
		},
	}
}
