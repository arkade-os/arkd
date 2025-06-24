package handlers

import (
	"encoding/hex"
	"fmt"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/server/internal/core/application"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
)

// From interface type to app type

func parseAddress(addr string) (*common.Address, error) {
	if len(addr) <= 0 {
		return nil, fmt.Errorf("missing address")
	}
	return common.DecodeAddressV0(addr)
}

func parseArkAddress(addr string) (string, error) {
	a, err := parseAddress(addr)
	if err != nil {
		return "", err
	}
	if _, err := btcutil.DecodeAddress(addr, nil); err == nil {
		return "", fmt.Errorf("must be an ark address")
	}
	return hex.EncodeToString(schnorr.SerializePubKey(a.VtxoTapKey)), nil
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
			Amount:         vv.Amount,
			CommitmentTxid: vv.CommitmentTxid,
			Spent:          vv.Spent,
			ExpiresAt:      vv.ExpireAt,
			SpentBy:        vv.SpentBy,
			Swept:          vv.Swept,
			Preconfirmed:   len(vv.RedeemTx) > 0,
			Redeemed:       vv.Redeemed,
			Script:         toP2TR(vv.PubKey),
			CreatedAt:      vv.CreatedAt,
		})
	}

	return list
}

type connectorsIndex map[string]domain.Outpoint

func (c connectorsIndex) toProto() map[string]*arkv1.Outpoint {
	proto := make(map[string]*arkv1.Outpoint)
	for vtxo, outpoint := range c {
		proto[vtxo] = &arkv1.Outpoint{
			Txid: outpoint.Txid,
			Vout: outpoint.VOut,
		}
	}
	return proto
}

type txEvent application.TransactionEvent

func (t txEvent) toProto() *arkv1.TxNotification {
	return &arkv1.TxNotification{
		Txid:           t.Txid,
		SpentVtxos:     vtxoList(t.SpentVtxos).toProto(),
		SpendableVtxos: vtxoList(t.SpendableVtxos).toProto(),
		Hex:            t.TxHex,
	}
}

type intentsInfo []application.TxRequestInfo

func (i intentsInfo) toProto() []*arkv1.IntentInfo {
	list := make([]*arkv1.IntentInfo, 0, len(i))
	for _, req := range i {
		receivers := make([]*arkv1.Output, 0, len(req.Receivers))
		for _, receiver := range req.Receivers {
			receivers = append(receivers, &arkv1.Output{
				Address: receiver.Address,
				Amount:  receiver.Amount,
			})
		}

		inputs := make([]*arkv1.IntentInput, 0, len(req.Inputs))
		for _, input := range req.Inputs {
			inputs = append(inputs, &arkv1.IntentInput{
				Txid:   input.Txid,
				Vout:   input.VOut,
				Amount: input.Amount,
			})
		}

		boardingInputs := make([]*arkv1.IntentInput, 0, len(req.BoardingInputs))
		for _, input := range req.BoardingInputs {
			boardingInputs = append(boardingInputs, &arkv1.IntentInput{
				Txid:   input.Txid,
				Vout:   input.VOut,
				Amount: input.Amount,
			})
		}

		list = append(list, &arkv1.IntentInfo{
			Id:                  req.Id,
			CreatedAt:           req.CreatedAt.Unix(),
			Receivers:           receivers,
			Inputs:              inputs,
			BoardingInputs:      boardingInputs,
			CosignersPublicKeys: req.Cosigners,
		})
	}
	return list
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
	script, _ := common.P2TRScript(key)
	return hex.EncodeToString(script)
}
