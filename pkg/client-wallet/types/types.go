package types

import (
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
)

const (
	InMemoryStore = "inmemory"
	FileStore     = "file"
)

type FeeInfo clientlib.FeeInfo

type Balance struct {
	OnchainBalance  OnchainBalance    `json:"onchain_balance"`
	OffchainBalance OffchainBalance   `json:"offchain_balance"`
	AssetBalances   map[string]uint64 `json:"asset_balances,omitempty"`
}

type OnchainBalance struct {
	SpendableAmount uint64 `json:"spendable_amount"`
	// SpendableRedeemAmount is the part of SpendableAmount held by unilateral exit outputs whose
	// exit delay has elapsed. These are the funds CompleteUnroll sweeps, which SpendableAmount
	// can't tell apart from onchain and boarding funds.
	SpendableRedeemAmount uint64                 `json:"spendable_redeem_amount"`
	LockedAmount          []LockedOnchainBalance `json:"locked_amount,omitempty"`
	// LockedRedeemAmount and LockedBoardingAmount split LockedAmount by the address holding the
	// funds, since only the former turns into SpendableRedeemAmount once its exit delay elapses.
	LockedRedeemAmount   []LockedOnchainBalance `json:"locked_redeem_amount,omitempty"`
	LockedBoardingAmount []LockedOnchainBalance `json:"locked_boarding_amount,omitempty"`
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
