package arksdk

type ServiceOption func(*service)

func WithVerbose() ServiceOption {
	return func(c *service) {
		c.verbose = true
	}
}

func WithoutFinalizePendingTxs() ServiceOption {
	return func(c *service) {
		c.withFinalizePendingTxs = false
	}
}
