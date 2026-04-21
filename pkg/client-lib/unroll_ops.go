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

func WithUtxosToClaim(utxos []types.Utxo) UnrollOption {
	return func(o *unrollOptions) error {
		if len(o.utxos) > 0 {
			return fmt.Errorf("utxos already set")
		}
		if len(utxos) <= 0 {
			return fmt.Errorf("missing utxos")
		}
		o.utxos = make([]types.Utxo, len(utxos))
		copy(o.utxos, utxos)
		return nil
	}
}

func WithKeysForUnroll(keys map[string]string) UnrollOption {
	return func(o *unrollOptions) error {
		if len(o.signingKeys) > 0 {
			return fmt.Errorf("signing key indexes by script already set")
		}
		if len(keys) <= 0 {
			return fmt.Errorf("missing signing key indexes by script")
		}
		o.signingKeys = keys
		return nil
	}
}

type unrollOptions struct {
	vtxos       []types.Vtxo
	utxos       []types.Utxo
	signingKeys map[string]string
}

func newDefaultUnrollOptions() *unrollOptions {
	return &unrollOptions{}
}
