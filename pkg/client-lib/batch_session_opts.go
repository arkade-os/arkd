package arksdk

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

const (
	defaultExpiryThreshold int64 = 3 * 24 * 60 * 60 // 3 days
	maxRetries             int   = 3
)

type BatchSessionOption interface {
	applyBatch(*batchSessionOptions) error
}

type batchOptFn func(*batchSessionOptions) error

func (f batchOptFn) applyBatch(o *batchSessionOptions) error { return f(o) }

// name alias, sub-dust vtxos are recoverable vtxos
var WithSubDustVtxos = WithRecoverableVtxos

func WithRecoverableVtxos() BatchSessionOption {
	return batchOptFn(func(o *batchSessionOptions) error {
		o.withRecoverableVtxos = true
		return nil
	})
}

func WithEventsCh(ch chan<- any) BatchSessionOption {
	return batchOptFn(func(o *batchSessionOptions) error {
		if o.eventsCh != nil {
			return fmt.Errorf("events channel already set")
		}
		o.eventsCh = ch
		return nil
	})
}

// WithoutWalletSigner disables the wallet signer
func WithoutWalletSigner() BatchSessionOption {
	return batchOptFn(func(o *batchSessionOptions) error {
		o.walletSignerDisabled = true
		return nil
	})
}

// WithExtraSigner allows to use a set of custom signer for the vtxo tree signing process
func WithExtraSigner(signerSessions ...tree.SignerSession) BatchSessionOption {
	return batchOptFn(func(o *batchSessionOptions) error {
		if len(signerSessions) == 0 {
			return fmt.Errorf("no signer sessions provided")
		}
		o.extraSignerSessions = signerSessions
		return nil
	})
}

// WithCancelCh allows to cancel the settlement process
func WithCancelCh(ch <-chan struct{}) BatchSessionOption {
	return batchOptFn(func(o *batchSessionOptions) error {
		o.cancelCh = ch
		return nil
	})
}

func WithExpiryThreshold(threshold int64) BatchSessionOption {
	return batchOptFn(func(o *batchSessionOptions) error {
		o.expiryThreshold = threshold
		return nil
	})
}

func WithRetries(num int) BatchSessionOption {
	return batchOptFn(func(o *batchSessionOptions) error {
		if o.retryNum > 0 {
			return fmt.Errorf("retry num already set")
		}
		if num <= 0 || num > maxRetries {
			return fmt.Errorf("retry num must be in range [1, %d]", maxRetries)
		}
		o.retryNum = num
		return nil
	})
}

func WithFunds(boardingUtxos []types.Utxo, vtxos []types.VtxoWithTapTree) BatchSessionOption {
	return batchOptFn(func(o *batchSessionOptions) error {
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
	})
}

// batchSessionOptions allows to customize the vtxo signing process
type batchSessionOptions struct {
	extraSignerSessions  []tree.SignerSession
	walletSignerDisabled bool
	withRecoverableVtxos bool
	expiryThreshold      int64 // In seconds
	retryNum             int
	boardingUtxos        []types.Utxo
	vtxos                []types.VtxoWithTapTree
	keyIdsByScript       map[string]string

	cancelCh <-chan struct{}
	eventsCh chan<- any
}

func newDefaultSettleOptions() *batchSessionOptions {
	return &batchSessionOptions{
		expiryThreshold: defaultExpiryThreshold,
	}
}
