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

type KeyBranch string

const (
	KeyBranchReceive KeyBranch = "receive"
	KeyBranchChange  KeyBranch = "change"
)

type KeyRef struct {
	// ID is the stable wallet-local handle for this key.
	// Single-key wallets use a fixed constant; HD wallets can use a derivation
	// path or another persistent key identifier.
	ID     string
	PubKey *btcec.PublicKey
}

type WalletService interface {
	GetType() string
	Create(ctx context.Context, password, seed string) (walletSeed string, err error)
	Lock(ctx context.Context) (err error)
	Unlock(ctx context.Context, password string) (alreadyUnlocked bool, err error)
	IsLocked() bool
	GetKey(ctx context.Context, id string) (key KeyRef, err error)
	NewKey(ctx context.Context, branch KeyBranch) (key KeyRef, err error)
	ListKeys(ctx context.Context, branch KeyBranch) (keys []KeyRef, err error)
	SignTransaction(
		ctx context.Context, explorerSvc explorer.Explorer, tx string,
	) (signedTx string, err error)
	SignMessage(ctx context.Context, message []byte) (signature string, err error)
	Dump(ctx context.Context) (seed string, err error)
	NewVtxoTreeSigner(ctx context.Context, derivationPath string) (tree.SignerSession, error)
}
