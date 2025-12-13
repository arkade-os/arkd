package filestore

import (
	"encoding/hex"
	"strconv"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/internal/utils"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2"
)

type feeData struct {
	TxFeeRate  string        `json:"tx_fee_rate"`
	IntentFees intentFeeData `json:"intent_fees"`
}

type intentFeeData struct {
	OffchainInput  string `json:"offchain_input"`
	OffchainOutput string `json:"offchain_output"`
	OnchainInput   string `json:"onchain_input"`
	OnchainOutput  string `json:"onchain_output"`
}

type storeData struct {
	ServerUrl           string  `json:"server_url"`
	SignerPubKey        string  `json:"signer_pubkey"`
	ForfeitPubKey       string  `json:"forfeit_pubkey"`
	WalletType          string  `json:"wallet_type"`
	ClientType          string  `json:"client_type"`
	Network             string  `json:"network"`
	SessionDuration     string  `json:"session_duration"`
	UnilateralExitDelay string  `json:"unilateral_exit_delay"`
	Dust                string  `json:"dust"`
	BoardingExitDelay   string  `json:"boarding_exit_delay"`
	ExplorerURL         string  `json:"explorer_url"`
	ForfeitAddress      string  `json:"forfeit_address"`
	UtxoMinAmount       string  `json:"utxo_min_amount"`
	UtxoMaxAmount       string  `json:"utxo_max_amount"`
	VtxoMinAmount       string  `json:"vtxo_min_amount"`
	VtxoMaxAmount       string  `json:"vtxo_max_amount"`
	CheckpointTapscript string  `json:"checkpoint_tapscript"`
	Fees                feeData `json:"fees"`
}

func (d storeData) isEmpty() bool {
	if d.ServerUrl == "" &&
		d.SignerPubKey == "" {
		return true
	}

	return false
}

func (d storeData) decode() types.Config {
	network := utils.NetworkFromString(d.Network)
	sessionDuration, _ := strconv.Atoi(d.SessionDuration)
	unilateralExitDelay, _ := strconv.Atoi(d.UnilateralExitDelay)
	boardingExitDelay, _ := strconv.Atoi(d.BoardingExitDelay)
	dust, _ := strconv.Atoi(d.Dust)
	buf, _ := hex.DecodeString(d.SignerPubKey)
	signerPubkey, _ := btcec.ParsePubKey(buf)
	buf, _ = hex.DecodeString(d.ForfeitPubKey)
	forfeitPubkey, _ := btcec.ParsePubKey(buf)
	explorerURL := d.ExplorerURL
	utxoMinAmount, _ := strconv.Atoi(d.UtxoMinAmount)
	utxoMaxAmount, _ := strconv.Atoi(d.UtxoMaxAmount)
	vtxoMinAmount, _ := strconv.Atoi(d.VtxoMinAmount)
	vtxoMaxAmount, _ := strconv.Atoi(d.VtxoMaxAmount)

	unilateralExitDelayType := arklib.LocktimeTypeBlock
	if unilateralExitDelay >= 512 {
		unilateralExitDelayType = arklib.LocktimeTypeSecond
	}

	boardingExitDelayType := arklib.LocktimeTypeBlock
	if boardingExitDelay >= 512 {
		boardingExitDelayType = arklib.LocktimeTypeSecond
	}

	txFeeRate, _ := strconv.ParseFloat(d.Fees.TxFeeRate, 64)
	onchainInputFee, _ := strconv.Atoi(d.Fees.IntentFees.OffchainInput)
	onchainOutputFee, _ := strconv.Atoi(d.Fees.IntentFees.OffchainOutput)
	fees := types.FeeInfo{
		TxFeeRate: txFeeRate,
		IntentFees: types.IntentFeeInfo{
			OffchainInput:  d.Fees.IntentFees.OffchainInput,
			OffchainOutput: d.Fees.IntentFees.OffchainOutput,
			OnchainInput:   uint64(onchainInputFee),
			OnchainOutput:  uint64(onchainOutputFee),
		},
	}

	return types.Config{
		ServerUrl:     d.ServerUrl,
		SignerPubKey:  signerPubkey,
		ForfeitPubKey: forfeitPubkey,
		WalletType:    d.WalletType,
		ClientType:    d.ClientType,
		Network:       network,
		UnilateralExitDelay: arklib.RelativeLocktime{
			Type:  unilateralExitDelayType,
			Value: uint32(unilateralExitDelay),
		},
		SessionDuration: int64(sessionDuration),
		Dust:            uint64(dust),
		BoardingExitDelay: arklib.RelativeLocktime{
			Type:  boardingExitDelayType,
			Value: uint32(boardingExitDelay),
		},
		ExplorerURL:         explorerURL,
		ForfeitAddress:      d.ForfeitAddress,
		UtxoMinAmount:       int64(utxoMinAmount),
		UtxoMaxAmount:       int64(utxoMaxAmount),
		VtxoMinAmount:       int64(vtxoMinAmount),
		VtxoMaxAmount:       int64(vtxoMaxAmount),
		CheckpointTapscript: d.CheckpointTapscript,
		Fees:                fees,
	}
}

func (d storeData) asMap() map[string]any {
	return map[string]any{
		"server_url":            d.ServerUrl,
		"signer_pubkey":         d.SignerPubKey,
		"forfeit_pubkey":        d.ForfeitPubKey,
		"wallet_type":           d.WalletType,
		"client_type":           d.ClientType,
		"network":               d.Network,
		"session_duration":      d.SessionDuration,
		"unilateral_exit_delay": d.UnilateralExitDelay,
		"dust":                  d.Dust,
		"boarding_exit_delay":   d.BoardingExitDelay,
		"explorer_url":          d.ExplorerURL,
		"forfeit_address":       d.ForfeitAddress,
		"utxo_min_amount":       d.UtxoMinAmount,
		"utxo_max_amount":       d.UtxoMaxAmount,
		"vtxo_min_amount":       d.VtxoMinAmount,
		"vtxo_max_amount":       d.VtxoMaxAmount,
		"checkpoint_tapscript":  d.CheckpointTapscript,
		"fees": map[string]any{
			"tx_fee_rate": d.Fees.TxFeeRate,
			"intent_fees": map[string]string{
				"offchain_input":  d.Fees.IntentFees.OffchainInput,
				"offchain_output": d.Fees.IntentFees.OffchainOutput,
				"onchain_input":   d.Fees.IntentFees.OnchainInput,
				"onchain_output":  d.Fees.IntentFees.OnchainOutput,
			},
		},
	}
}
