package arksdk

type SendOption func(options *sendOptions) error

func WithoutExpirySorting() SendOption {
	return func(o *sendOptions) error {
		o.withoutExpirySorting = true
		return nil
	}
}

type sendOptions struct {
	withoutExpirySorting bool
}

func newDefaultSendOptions() *sendOptions {
	return &sendOptions{}
}
