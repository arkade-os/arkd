package arksdk

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
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

// settleOptions allows to customize the vtxo signing process
type settleOptions struct {
	extraSignerSessions  []tree.SignerSession
	walletSignerDisabled bool
	withRecoverableVtxos bool
	expiryThreshold      int64 // In seconds

	cancelCh <-chan struct{}
	eventsCh chan<- any
}

func newDefaultSettleOptions() *settleOptions {
	return &settleOptions{
		expiryThreshold: defaultExpiryThreshold,
	}
}
