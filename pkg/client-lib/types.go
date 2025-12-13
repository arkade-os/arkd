package arksdk

import (
	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

type Balance struct {
	OnchainBalance  OnchainBalance  `json:"onchain_balance"`
	OffchainBalance OffchainBalance `json:"offchain_balance"`
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

type balanceRes struct {
	offchainBalance             uint64
	onchainSpendableBalance     uint64
	onchainLockedBalance        map[int64]uint64
	offchainBalanceByExpiration map[int64]uint64
	err                         error
}

type getVtxosFilter struct {
	// If true, will sort coins by expiration (oldest first)
	withoutExpirySorting bool
	// If specified, will select only coins in the list
	outpoints []types.Outpoint
	// If true, will select recoverable (swept but unspent) vtxos first
	withRecoverableVtxos bool
	// If specified, will select only vtxos below the given expiration threshold (seconds)
	expiryThreshold int64
	// If true, will recompute the expiration of all vtxos from their anchestor batch outputs
	recomputeExpiry bool
}
