package wallet

import "fmt"

type ListVtxosOption func(options *listVtxosOptions) error

func WithTimeRange(before, after int64) ListVtxosOption {
	return func(o *listVtxosOptions) error {
		if o.After > 0 || o.Before > 0 {
			return fmt.Errorf("time range already set")
		}
		if before < 0 || after < 0 {
			return fmt.Errorf("negative time bound")
		}
		if before == 0 && after == 0 {
			return fmt.Errorf("missing time range")
		}
		if before > 0 && after > 0 && before <= after {
			return fmt.Errorf("before must be greater than after")
		}
		o.Before = before
		o.After = after
		return nil
	}
}

type listVtxosOptions struct {
	Before int64
	After  int64
}

func ApplyListVtxosOptions(opts ...ListVtxosOption) (*listVtxosOptions, error) {
	o := &listVtxosOptions{}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}
