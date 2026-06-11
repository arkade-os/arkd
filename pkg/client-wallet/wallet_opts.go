package wallet

import (
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
)

type WalletOption func(*wallet)

func WithVerbose() WalletOption {
	return func(c *wallet) {
		c.verbose = true
	}
}

func WithExplorer(explorer clientlib.Explorer) WalletOption {
	return func(c *wallet) {
		c.explorer = explorer
	}
}

func WithIdentity(identitySvc clientlib.Identity) WalletOption {
	return func(c *wallet) {
		c.identity = identitySvc
	}
}

func WithoutFinalizePendingTxs() WalletOption {
	return func(c *wallet) {
		c.withFinalizePendingTxs = false
	}
}
