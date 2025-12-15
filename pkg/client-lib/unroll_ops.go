package arksdk

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

type UnrollOption func(options *unrollOptions) error

func WithVtxosToUnroll(vtxos []types.Vtxo) UnrollOption {
	return func(o *unrollOptions) error {
		if len(o.vtxos) > 0 {
			return fmt.Errorf("vtxos already set")
		}
		if len(vtxos) <= 0 {
			return fmt.Errorf("missing vtxos")
		}
		o.vtxos = make([]types.Vtxo, len(vtxos))
		copy(o.vtxos, vtxos)
		return nil
	}
}

type unrollOptions struct {
	vtxos []types.Vtxo
}

func newDefaultUnrollOptions() *unrollOptions {
	return &unrollOptions{}
}
