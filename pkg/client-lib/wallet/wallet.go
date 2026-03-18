package wallet

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
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
	GetAddresses(ctx context.Context) (
		onchainAddresses []string,
		offchainAddresses, boardingAddresses, redemptionAddresses []types.Address, err error,
	)
	NewAddress(ctx context.Context, change bool) (
		onchainAddr string, offchainAddr, boardingAddr *types.Address, err error,
	)
	NewAddresses(ctx context.Context, change bool, num int) (
		onchainAddresses []string,
		offchainAddresses, boardingAddresses []types.Address, err error,
	)
	SignTransaction(
		ctx context.Context, explorerSvc explorer.Explorer, tx string,
	) (signedTx string, err error)
	SignMessage(ctx context.Context, message []byte) (signature string, err error)
	Dump(ctx context.Context) (seed string, err error)
	NewVtxoTreeSigner(ctx context.Context, derivationPath string) (tree.SignerSession, error)
}
