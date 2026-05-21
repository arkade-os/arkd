package batchsession

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	batchsessionhandler "github.com/arkade-os/arkd/pkg/client-lib/batch-session/handler"
)

const (
	defaultExpiryThreshold int64 = 3 * 24 * 60 * 60 // 3 days
	maxRetries             int   = 3
)

// Option customizes the behavior of a batch-session operation
// (Settle, CollaborativeExit, RedeemNotes, JoinBatch). Use the With* helpers
// in this package to construct instances.
type Option interface {
	apply(*options) error
}

type optFn func(*options) error

func (f optFn) apply(o *options) error { return f(o) }

// name alias, sub-dust vtxos are recoverable vtxos
var WithSubDustVtxos = WithRecoverableVtxos

// WithRecoverableVtxos opts the session into spending sub-dust (recoverable)
// vtxos as inputs alongside regular vtxos.
func WithRecoverableVtxos() Option {
	return optFn(func(o *options) error {
		o.withRecoverableVtxos = true
		return nil
	})
}

// WithEventsCh registers a channel that receives a copy of every batch event
// observed by the session handler. Useful for tests or for surfacing
// progress to the caller. Can only be set once per session.
func WithEventsCh(ch chan<- any) Option {
	return optFn(func(o *options) error {
		if o.eventsCh != nil {
			return fmt.Errorf("events channel already set")
		}
		o.eventsCh = ch
		return nil
	})
}

// WithoutTreeSigner disables the tree signer for the batch session
func WithoutTreeSigner() Option {
	return optFn(func(o *options) error {
		o.treeSignerDisabled = true
		return nil
	})
}

// WithExtraSigner allows to use a set of custom signer for the vtxo tree signing process
func WithExtraSigner(signerSessions ...tree.SignerSession) Option {
	return optFn(func(o *options) error {
		if len(signerSessions) == 0 {
			return fmt.Errorf("no signer sessions provided")
		}
		o.extraSignerSessions = signerSessions
		return nil
	})
}

// WithCancelCh allows to cancel the settlement process
func WithCancelCh(ch <-chan struct{}) Option {
	return optFn(func(o *options) error {
		o.cancelCh = ch
		return nil
	})
}

// WithExpiryThreshold overrides the default vtxo-expiry filter (in seconds):
// vtxos expiring sooner than the threshold are excluded from coin selection.
func WithExpiryThreshold(threshold int64) Option {
	return optFn(func(o *options) error {
		o.expiryThreshold = threshold
		return nil
	})
}

// WithRetries sets the maximum number of attempts to join a batch on transient
// failures. Must be in the range [1, maxRetries]. Can only be set once.
func WithRetries(num int) Option {
	return optFn(func(o *options) error {
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

// WithHandler allows to make use of a custom batch-event handler in place of the default one.
// Handler cannot be nil and can only be set once per session.
func WithHandler(handler batchsessionhandler.Handler) Option {
	return optFn(func(o *options) error {
		if handler == nil {
			return fmt.Errorf("handler cannot be nil")
		}
		if o.handler != nil {
			return fmt.Errorf("handler already set")
		}
		o.handler = handler
		return nil
	})
}

// options allows to customize the vtxo signing process
type options struct {
	extraSignerSessions  []tree.SignerSession
	treeSignerDisabled   bool
	withRecoverableVtxos bool
	expiryThreshold      int64 // In seconds
	retryNum             int
	handler              batchsessionhandler.Handler

	cancelCh <-chan struct{}
	eventsCh chan<- any
}

func newOptions() *options {
	return &options{
		expiryThreshold: defaultExpiryThreshold,
	}
}

func (o options) treeSigners() ([]tree.SignerSession, []string, error) {
	sessions := make([]tree.SignerSession, 0)
	if !o.treeSignerDisabled {
		signerSession, err := tree.NewVtxoTreeSigner()
		if err != nil {
			return nil, nil, err
		}
		sessions = append(sessions, signerSession)
	}
	sessions = append(sessions, o.extraSignerSessions...)

	if len(sessions) <= 0 {
		return nil, nil, fmt.Errorf("no signer sessions")
	}

	signerPubKeys := make([]string, 0)
	for _, session := range sessions {
		signerPubKeys = append(signerPubKeys, session.GetPublicKey())
	}

	return sessions, signerPubKeys, nil
}
