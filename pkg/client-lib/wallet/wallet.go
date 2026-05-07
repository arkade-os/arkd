package wallet

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
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

type WalletService interface {
	GetType() string
	Create(
		ctx context.Context, network chaincfg.Params, password, seed string,
	) (walletSeed string, err error)
	Lock(ctx context.Context) (err error)
	Unlock(ctx context.Context, password string) (alreadyUnlocked bool, err error)
	IsLocked() bool
	NextKeyId(ctx context.Context, id string) (string, error)
	GetKeyIndex(ctx context.Context, id string) (index uint32, err error)
	NewKey(ctx context.Context) (key *KeyRef, err error)
	GetKey(ctx context.Context, id string) (key *KeyRef, err error)
	ListKeys(ctx context.Context) (keys []KeyRef, err error)
	SignTransaction(
		ctx context.Context, tx string, keys map[string]string,
	) (signedTx string, err error)
	SignMessage(ctx context.Context, message []byte) (signature string, err error)
	Dump(ctx context.Context) (seed string, err error)
	NewVtxoTreeSigner(ctx context.Context) (tree.SignerSession, error)
}
