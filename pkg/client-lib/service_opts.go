package wallet

import (
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
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

func WithIdentity(identitySvc identity.Identity) ServiceOption {
	return func(c *service) {
		c.identity = identitySvc
	}
}

func WithoutFinalizePendingTxs() ServiceOption {
	return func(c *service) {
		c.withFinalizePendingTxs = false
	}
}
