package arksdk

import (
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
)

type ServiceOption func(*service)

func WithVerbose() ServiceOption {
	return func(c *service) {
		c.verbose = true
	}
}

func WithExplorer(explorer explorer.Explorer) ServiceOption {
	return func(c *service) {
		c.explorer = explorer
	}
}

func WithWallet(wallet wallet.WalletService) ServiceOption {
	return func(c *service) {
		c.wallet = wallet
	}
}

func WithoutFinalizePendingTxs() ServiceOption {
	return func(c *service) {
		c.withFinalizePendingTxs = false
	}
}
