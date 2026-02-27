package arksdk

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

const defaultExpiryThreshold int64 = 3 * 24 * 60 * 60 // 3 days

type SettleOption func(options *settleOptions) error

// name alias, sub-dust vtxos are recoverable vtxos
var WithSubDustVtxos = WithRecoverableVtxos

func WithRecoverableVtxos() SettleOption {
	return func(o *settleOptions) error {
		o.withRecoverableVtxos = true
		return nil
	}
}

func WithEventsCh(ch chan<- any) SettleOption {
	return func(o *settleOptions) error {
		if o.eventsCh != nil {
			return fmt.Errorf("events channel already set")
		}
		o.eventsCh = ch
		return nil
	}
}

// WithoutWalletSigner disables the wallet signer
func WithoutWalletSigner() SettleOption {
	return func(o *settleOptions) error {
		o.walletSignerDisabled = true
		return nil
	}
}

// WithExtraSigner allows to use a set of custom signer for the vtxo tree signing process
func WithExtraSigner(signerSessions ...tree.SignerSession) SettleOption {
	return func(o *settleOptions) error {
		if len(signerSessions) == 0 {
			return fmt.Errorf("no signer sessions provided")
		}
		o.extraSignerSessions = signerSessions
		return nil
	}
}

// WithCancelCh allows to cancel the settlement process
func WithCancelCh(ch <-chan struct{}) SettleOption {
	return func(o *settleOptions) error {
		o.cancelCh = ch
		return nil
	}
}

func WithExpiryThreshold(threshold int64) SettleOption {
	return func(o *settleOptions) error {
		o.expiryThreshold = threshold
		return nil
	}
}

func WithFunds(boardingUtxos []types.Utxo, vtxos []types.VtxoWithTapTree) SettleOption {
	return func(o *settleOptions) error {
		if len(boardingUtxos) <= 0 && len(vtxos) <= 0 {
			return fmt.Errorf("missing funds")
		}
		if len(boardingUtxos) > 0 {
			if len(o.boardingUtxos) > 0 {
				return fmt.Errorf("boarding utxos already set")
			}
			o.boardingUtxos = make([]types.Utxo, len(boardingUtxos))
			copy(o.boardingUtxos, boardingUtxos)
		}
		if len(vtxos) > 0 {
			if len(o.vtxos) > 0 {
				return fmt.Errorf("vtxos already set")
			}
			o.vtxos = make([]types.VtxoWithTapTree, len(vtxos))
			copy(o.vtxos, vtxos)
		}
		return nil
	}
}

// settleOptions allows to customize the vtxo signing process
type settleOptions struct {
	extraSignerSessions  []tree.SignerSession
	walletSignerDisabled bool
	withRecoverableVtxos bool
	expiryThreshold      int64 // In seconds
	boardingUtxos        []types.Utxo
	vtxos                []types.VtxoWithTapTree

	cancelCh <-chan struct{}
	eventsCh chan<- any
}

func newDefaultSettleOptions() *settleOptions {
	return &settleOptions{
		expiryThreshold: defaultExpiryThreshold,
	}
}
