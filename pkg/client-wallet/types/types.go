package types

import (
	"encoding/hex"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	InMemoryStore = "inmemory"
	FileStore     = "file"
)

type FeeInfo clientlib.FeeInfo

type Config struct {
	ServerUrl           string
	SignerPubKey        *btcec.PublicKey
	ForfeitPubKey       *btcec.PublicKey
	Network             arklib.Network
	SessionDuration     int64
	UnilateralExitDelay arklib.RelativeLocktime
	Dust                uint64
	BoardingExitDelay   arklib.RelativeLocktime
	ExplorerURL         string
	ForfeitAddress      string
	UtxoMinAmount       int64
	UtxoMaxAmount       int64
	VtxoMinAmount       int64
	VtxoMaxAmount       int64
	CheckpointTapscript string
	Fees                FeeInfo
}

func (c Config) CheckpointExitPath() []byte {
	// nolint
	buf, _ := hex.DecodeString(c.CheckpointTapscript)
	return buf
}

func (c Config) ClientInfo() clientlib.Info {
	return clientlib.Info{
		SignerPubKey:        hex.EncodeToString(c.SignerPubKey.SerializeCompressed()),
		ForfeitPubKey:       hex.EncodeToString(c.ForfeitPubKey.SerializeCompressed()),
		UnilateralExitDelay: int64(c.UnilateralExitDelay.Seconds()),
		BoardingExitDelay:   int64(c.BoardingExitDelay.Seconds()),
		SessionDuration:     c.SessionDuration,
		Network:             c.Network.Name,
		Dust:                c.Dust,
		ForfeitAddress:      c.ForfeitAddress,
		UtxoMinAmount:       c.UtxoMinAmount,
		UtxoMaxAmount:       c.UtxoMaxAmount,
		VtxoMinAmount:       c.VtxoMinAmount,
		VtxoMaxAmount:       c.VtxoMaxAmount,
		CheckpointTapscript: c.CheckpointTapscript,
	}
}

type Balance struct {
	OnchainBalance  OnchainBalance    `json:"onchain_balance"`
	OffchainBalance OffchainBalance   `json:"offchain_balance"`
	AssetBalances   map[string]uint64 `json:"asset_balances,omitempty"`
}

type OnchainBalance struct {
	SpendableAmount uint64                 `json:"spendable_amount"`
	LockedAmount    []LockedOnchainBalance `json:"locked_amount,omitempty"`
}

type LockedOnchainBalance struct {
	SpendableAt string `json:"spendable_at"`
	Amount      uint64 `json:"amount"`
}

type OffchainBalance struct {
	Total          uint64        `json:"total"`
	NextExpiration string        `json:"next_expiration,omitempty"`
	Details        []VtxoDetails `json:"details"`
}

type VtxoDetails struct {
	ExpiryTime string `json:"expiry_time"`
	Amount     uint64 `json:"amount"`
}
