package arksdk

import (
	"fmt"

	grpcclient "github.com/ark-network/ark/pkg/client-sdk/client/grpc"
	restclient "github.com/ark-network/ark/pkg/client-sdk/client/rest"
	"github.com/ark-network/ark/pkg/client-sdk/internal/utils"
	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/ark-network/ark/pkg/client-sdk/wallet"
)

var (
	supportedWallets = utils.SupportedType[struct{}]{
		SingleKeyWallet: struct{}{},
	}
	supportedClients = utils.SupportedType[utils.ClientFactory]{
		GrpcClient: grpcclient.NewClient,
		RestClient: restclient.NewClient,
	}
)

type InitArgs struct {
	ClientType          string
	WalletType          string
	ServerUrl           string
	Seed                string
	Password            string
	ExplorerURL         string
	WithTransactionFeed bool
}

func (a InitArgs) validate() error {
	if len(a.WalletType) <= 0 {
		return fmt.Errorf("missing wallet")
	}
	if !supportedWallets.Supports(a.WalletType) {
		return fmt.Errorf(
			"wallet type '%s' not supported, please select one of: %s",
			a.WalletType, supportedClients,
		)
	}

	if len(a.ClientType) <= 0 {
		return fmt.Errorf("missing client type")
	}
	if !supportedClients.Supports(a.ClientType) {
		return fmt.Errorf(
			"client type '%s' not supported, please select one of: %s",
			a.ClientType, supportedClients,
		)
	}

	if len(a.ServerUrl) <= 0 {
		return fmt.Errorf("missing server url")
	}
	if len(a.Password) <= 0 {
		return fmt.Errorf("missing password")
	}
	return nil
}

type InitWithWalletArgs struct {
	ClientType          string
	Wallet              wallet.WalletService
	ServerUrl           string
	Seed                string
	Password            string
	ExplorerURL         string
	WithTransactionFeed bool
}

func (a InitWithWalletArgs) validate() error {
	if a.Wallet == nil {
		return fmt.Errorf("missing wallet")
	}

	if len(a.ClientType) <= 0 {
		return fmt.Errorf("missing client type")
	}
	if !supportedClients.Supports(a.ClientType) {
		return fmt.Errorf("client type not supported, please select one of: %s", supportedClients)
	}

	if len(a.ServerUrl) <= 0 {
		return fmt.Errorf("missing server url")
	}
	if len(a.Password) <= 0 {
		return fmt.Errorf("missing password")
	}
	return nil
}

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

type CoinSelectOptions struct {
	// If true, coin selector will select coins closest to expiry first.
	WithExpirySorting bool
	// If specified, coin selector will select only coins in the list.
	OutpointsFilter []types.Outpoint
	// If true, coin selector will select recoverable (swept but unspent) vtxos first.
	SelectRecoverableVtxos bool
}
