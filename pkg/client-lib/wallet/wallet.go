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

type WalletService interface {
	GetType() string
	Create(ctx context.Context, password, seed string) (walletSeed string, err error)
	Lock(ctx context.Context) (err error)
	Unlock(ctx context.Context, password string) (alreadyUnlocked bool, err error)
	IsLocked() bool
	GetKeyPair(
		ctx context.Context, path string,
	) (prvkey *btcec.PrivateKey, pubkey *btcec.PublicKey, err error)
	NewKeyPair(ctx context.Context) (prvkey *btcec.PrivateKey, pubkey *btcec.PublicKey, err error)
	SignTransaction(
		ctx context.Context, explorerSvc explorer.Explorer, tx string,
	) (signedTx string, err error)
	SignMessage(ctx context.Context, message []byte) (signature string, err error)
	Dump(ctx context.Context) (seed string, err error)
	NewVtxoTreeSigner(ctx context.Context, derivationPath string) (tree.SignerSession, error)
}
