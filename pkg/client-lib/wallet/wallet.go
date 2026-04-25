package wallet

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	SingleKeyWallet = "singlekey"
)

type KeyRef struct {
	// Id can be anything and it's up to implementation whether it is, for example, a derivation
	// path or just a derivation index
	Id     string
	PubKey *btcec.PublicKey
}

type KeyOption func(options any) error

type WalletService interface {
	GetType() string
	Create(ctx context.Context, password, seed string) (walletSeed string, err error)
	Lock(ctx context.Context) (err error)
	Unlock(ctx context.Context, password string) (alreadyUnlocked bool, err error)
	IsLocked() bool
	NewKey(ctx context.Context, opts ...KeyOption) (key *KeyRef, err error)
	GetKey(ctx context.Context, opts ...KeyOption) (key *KeyRef, err error)
	ListKeys(ctx context.Context) (keys []KeyRef, err error)
	SignTransaction(
		ctx context.Context, explorerSvc explorer.Explorer, tx string, keys map[string]string,
	) (signedTx string, err error)
	SignMessage(ctx context.Context, message []byte) (signature string, err error)
	Dump(ctx context.Context) (seed string, err error)
	NewVtxoTreeSigner(ctx context.Context, derivationPath string) (tree.SignerSession, error)
}
