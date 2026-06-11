package wallet

import (
	"fmt"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
)

type UnrollOption interface {
	applyUnroll(*unrollOptions) error
}

func WithVtxos(vtxos []clientlib.Vtxo) UnrollOption {
	return unrollOptFn(func(o *unrollOptions) error {
		if len(vtxos) <= 0 {
			return fmt.Errorf("missing vtxos")
		}
		if len(o.vtxos) > 0 {
			return fmt.Errorf("vtxos already set")
		}
		o.vtxos = make([]clientlib.Vtxo, len(vtxos))
		copy(o.vtxos, vtxos)
		return nil
	})
}

func WithReceiver(receiver string) UnrollOption {
	return unrollOptFn(func(o *unrollOptions) error {
		if len(receiver) <= 0 {
			return fmt.Errorf("missing receiver")
		}
		if len(o.receiver) > 0 {
			return fmt.Errorf("receiver already set")
		}
		o.receiver = receiver
		return nil
	})
}

type unrollOptFn func(*unrollOptions) error

func (f unrollOptFn) applyUnroll(o *unrollOptions) error { return f(o) }

type unrollOptions struct {
	vtxos    []clientlib.Vtxo
	receiver string
}

func newDefaultUnrollOptions() *unrollOptions {
	return &unrollOptions{}
}
