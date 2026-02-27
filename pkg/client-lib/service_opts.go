package arksdk

import (
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
)

type ServiceOption func(*service)

func WithVerbose() ServiceOption {
	return func(c *service) {
		c.verbose = true
	}
}

// WithRefreshDb enables periodic refresh of the db when WithTransactionFeed is set
func WithExplorer(svc explorer.Explorer) ServiceOption {
	return func(c *service) {
		if svc != nil {
			c.explorer = svc
		}
	}
}

func WithoutFinalizePendingTxs() ServiceOption {
	return func(c *service) {
		c.withFinalizePendingTxs = false
	}
}
