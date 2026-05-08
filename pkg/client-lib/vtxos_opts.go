package wallet

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

// VtxosOption is the intersection of every option family that accepts a
// caller-supplied set of vtxos. A single WithVtxos satisfies all of
// SendOption, BatchSessionOption, and UnrollOption.
type VtxosOption interface {
	SendOption
	UnrollOption
}

type vtxosOpt struct {
	vtxos []types.VtxoWithTapTree
}

func (v vtxosOpt) applySend(o *sendOptions) error {
	if len(o.vtxos) > 0 {
		return fmt.Errorf("vtxos already set")
	}
	if len(v.vtxos) == 0 {
		return fmt.Errorf("missing vtxos")
	}
	o.vtxos = append([]types.VtxoWithTapTree(nil), v.vtxos...)
	return nil
}

// Unroll does not need tapscripts — they are resolved downstream from the
// explorer when computing redeem branches — so stripping is lossless.
func (v vtxosOpt) applyUnroll(o *unrollOptions) error {
	if len(o.vtxos) > 0 {
		return fmt.Errorf("vtxos already set")
	}
	if len(v.vtxos) == 0 {
		return fmt.Errorf("missing vtxos")
	}
	plain := make([]types.Vtxo, len(v.vtxos))
	for i, vt := range v.vtxos {
		plain[i] = vt.Vtxo
	}
	o.vtxos = plain
	return nil
}

func WithVtxos(vtxos []types.VtxoWithTapTree) VtxosOption {
	return vtxosOpt{vtxos: vtxos}
}
