package arksdk

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

type SendOption func(options *sendOptions) error

func WithoutExpirySorting() SendOption {
	return func(o *sendOptions) error {
		o.withoutExpirySorting = true
		return nil
	}
}

func WithVtxos(vtxos []types.VtxoWithTapTree) SendOption {
	return func(o *sendOptions) error {
		if len(o.vtxos) > 0 {
			return fmt.Errorf("vtxos already set")
		}
		if len(vtxos) <= 0 {
			return fmt.Errorf("missing vtxos")
		}
		o.vtxos = make([]types.VtxoWithTapTree, len(vtxos))
		copy(o.vtxos, vtxos)
		return nil
	}
}

type sendOptions struct {
	withoutExpirySorting bool
	vtxos                []types.VtxoWithTapTree
}

func newDefaultSendOptions() *sendOptions {
	return &sendOptions{}
}
