package arksdk

import (
	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

// SendOption is satisfied by any value whose applySend method mutates a
// sendOptions. Interface-typed options let a single definition satisfy
// multiple option families — see WithKeys in sign_opts.go.
type SendOption interface {
	applySend(*sendOptions) error
}

type sendOptFn func(*sendOptions) error

func (f sendOptFn) applySend(o *sendOptions) error { return f(o) }

func WithoutExpirySorting() SendOption {
	return sendOptFn(func(o *sendOptions) error {
		o.withoutExpirySorting = true
		return nil
	})
}

type sendOptions struct {
	withoutExpirySorting bool
	vtxos                []types.VtxoWithTapTree
	signingKeys          map[string]string
}

func newDefaultSendOptions() *sendOptions {
	return &sendOptions{}
}
