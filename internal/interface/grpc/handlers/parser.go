package handlers

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	arkv1 "github.com/arkade-os/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/bip322"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// From interface type to app type

func parseIntent(intent *arkv1.Bip322Signature) (*bip322.Signature, *bip322.IntentMessage, error) {
	if intent == nil {
		return nil, nil, fmt.Errorf("missing intent")
	}
	if len(intent.GetSignature()) <= 0 {
		return nil, nil, fmt.Errorf("missing intent proof")
	}
	proof, err := bip322.DecodeSignature(intent.GetSignature())
	if err != nil {
		return nil, nil, fmt.Errorf("invalid intent proof: %s", err)
	}

	if len(intent.GetMessage()) <= 0 {
		return nil, nil, fmt.Errorf("missing message")
	}
	var message bip322.IntentMessage
	if err := message.Decode(intent.GetMessage()); err != nil {
		return nil, nil, fmt.Errorf("invalid intent message")
	}
	return proof, &message, nil
}

func parseDeleteIntent(
	intent *arkv1.Bip322Signature,
) (*bip322.Signature, *bip322.DeleteIntentMessage, error) {
	if intent == nil {
		return nil, nil, fmt.Errorf("missing intent")
	}
	if len(intent.GetSignature()) <= 0 {
		return nil, nil, fmt.Errorf("missing intent proof")
	}
	proof, err := bip322.DecodeSignature(intent.GetSignature())
	if err != nil {
		return nil, nil, fmt.Errorf("invalid intent proof: %s", err)
	}

	if len(intent.GetMessage()) <= 0 {
		return nil, nil, fmt.Errorf("missing message")
	}
	var message bip322.DeleteIntentMessage
	if err := message.Decode(intent.GetMessage()); err != nil {
		return nil, nil, fmt.Errorf("invalid delete intent message")
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

func parseNonces(serializedNonces string) (tree.TreeNonces, error) {
	if len(serializedNonces) <= 0 {
		return nil, fmt.Errorf("missing tree nonces")
	}
	var nonces tree.TreeNonces
	if err := json.Unmarshal([]byte(serializedNonces), &nonces); err != nil {
		return nil, fmt.Errorf("invalid tree nonces: %s", err)
	}
	return nonces, nil
}

func parseSignatures(serializedSignatures string) (tree.TreePartialSigs, error) {
	if len(serializedSignatures) <= 0 {
		return nil, fmt.Errorf("missing tree signatures")
	}
	signatures := make(tree.TreePartialSigs)
	if err := json.Unmarshal([]byte(serializedSignatures), &signatures); err != nil {
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
	// nolint
	buf, _ := hex.DecodeString(pubkey)
	// nolint
	key, _ := schnorr.ParsePubKey(buf)
	// nolint
	outScript, _ := script.P2TRScript(key)
	return hex.EncodeToString(outScript)
}

// From app type to interface type

type vtxoList []domain.Vtxo

func (v vtxoList) toProto() []*arkv1.Vtxo {
	list := make([]*arkv1.Vtxo, 0, len(v))
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

type marketHour struct {
	t *application.NextMarketHour
}

func (mh marketHour) toProto() *arkv1.MarketHour {
	if mh.t == nil {
		return nil
	}
	return &arkv1.MarketHour{
		NextStartTime: mh.t.StartTime.Unix(),
		NextEndTime:   mh.t.EndTime.Unix(),
		Period:        int64(mh.t.Period),
		RoundInterval: int64(mh.t.RoundInterval),
	}
}
