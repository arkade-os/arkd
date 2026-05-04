package arksdk

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

type UnrollOption interface {
	applyUnroll(*unrollOptions) error
}

type unrollOptFn func(*unrollOptions) error

func (f unrollOptFn) applyUnroll(o *unrollOptions) error { return f(o) }

func WithUtxosToClaim(utxos []types.Utxo) UnrollOption {
	return unrollOptFn(func(o *unrollOptions) error {
		if len(o.utxos) > 0 {
			return fmt.Errorf("utxos already set")
		}
		if len(utxos) <= 0 {
			return fmt.Errorf("missing utxos")
		}
		o.utxos = make([]types.Utxo, len(utxos))
		copy(o.utxos, utxos)
		return nil
	})
}

type unrollOptions struct {
	vtxos       []types.Vtxo
	utxos       []types.Utxo
	signingKeys map[string]string
	receiver    string
}

func newDefaultUnrollOptions() *unrollOptions {
	return &unrollOptions{}
}
