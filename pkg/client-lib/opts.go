package arksdk

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
)

const defaultExpiryThreshold int64 = 3 * 24 * 60 * 60 // 3 days

type Option func(options any) error

// name alias, sub-dust vtxos are recoverable vtxos
var WithSubDustVtxos = WithRecoverableVtxos

func WithRecoverableVtxos() Option {
	return func(o any) error {
		opts, err := checkSettleOptionsType(o)
		if err != nil {
			return err
		}

		opts.withRecoverableVtxos = true
		return nil
	}
}

func WithEventsCh(ch chan<- any) Option {
	return func(o any) error {
		opts, err := checkSettleOptionsType(o)
		if err != nil {
			return err
		}

		opts.eventsCh = ch
		return nil
	}
}

// WithoutWalletSigner disables the wallet signer
func WithoutWalletSigner() Option {
	return func(o any) error {
		opts, err := checkSettleOptionsType(o)
		if err != nil {
			return err
		}

		opts.walletSignerDisabled = true
		return nil
	}
}

// WithExtraSigner allows to use a set of custom signer for the vtxo tree signing process
func WithExtraSigner(signerSessions ...tree.SignerSession) Option {
	return func(o any) error {
		opts, err := checkSettleOptionsType(o)
		if err != nil {
			return err
		}

		if len(signerSessions) == 0 {
			return fmt.Errorf("no signer sessions provided")
		}

		opts.extraSignerSessions = signerSessions
		return nil
	}
}

// WithCancelCh allows to cancel the settlement process
func WithCancelCh(ch <-chan struct{}) Option {
	return func(o any) error {
		opts, err := checkSettleOptionsType(o)
		if err != nil {
			return err
		}

		opts.cancelCh = ch
		return nil
	}
}

func WithExpiryThreshold(threshold int64) Option {
	return func(o any) error {

		opts, err := checkSettleOptionsType(o)
		if err != nil {
			return err
		}

		opts.expiryThreshold = threshold
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

type sendOffChainOptions struct {
	withoutExpirySorting bool
}

func newDefaultSendOffChainOptions() *sendOffChainOptions {
	return &sendOffChainOptions{}
}

func WithoutExpirySorting() Option {
	return func(o any) error {
		opts, err := checkSendOffChainOptionsType(o)
		if err != nil {
			return err
		}

		opts.withoutExpirySorting = true
		return nil
	}
}
