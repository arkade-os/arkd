package arksdk

import (
	"context"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

var Version string

type ArkClient interface {
	GetVersion() string
	GetConfigData(ctx context.Context) (*types.Config, error)
	Init(ctx context.Context, args InitArgs) error
	InitWithWallet(ctx context.Context, args InitWithWalletArgs) error
	IsLocked(ctx context.Context) bool
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context) error
	IsSynced(ctx context.Context) <-chan types.SyncEvent
	Balance(ctx context.Context) (*Balance, error)
	Receive(ctx context.Context) (onchainAddr, offchainAddr, boardingAddr string, err error)
	GetAddresses(ctx context.Context) (
		onchainAddresses, offchainAddresses, boardingAddresses, redemptionAddresses []string,
		err error,
	)
	NewOffchainAddress(ctx context.Context) (string, error)
	SendOffChain(ctx context.Context, receivers []types.Receiver, opt ...Option) (string, error)
	RegisterIntent(
		ctx context.Context, vtxos []types.Vtxo, boardingUtxos []types.Utxo, notes []string,
		outputs []types.Receiver, cosignersPublicKeys []string,
	) (intentID string, err error)
	DeleteIntent(
		ctx context.Context, vtxos []types.Vtxo, boardingUtxos []types.Utxo, notes []string,
	) error
	Settle(ctx context.Context, opts ...Option) (string, error)
	CollaborativeExit(
		ctx context.Context, addr string, amount uint64, opts ...Option,
	) (string, error)
	Unroll(ctx context.Context) error
	CompleteUnroll(ctx context.Context, to string) (string, error)
	OnboardAgainAllExpiredBoardings(ctx context.Context) (string, error)
	WithdrawFromAllExpiredBoardings(ctx context.Context, to string) (string, error)
	ListVtxos(ctx context.Context) (spendable, spent []types.Vtxo, err error)
	ListSpendableVtxos(ctx context.Context) ([]types.Vtxo, error)
	Dump(ctx context.Context) (seed string, err error)
	GetTransactionHistory(ctx context.Context) ([]types.Transaction, error)
	GetTransactionEventChannel(ctx context.Context) <-chan types.TransactionEvent
	GetVtxoEventChannel(ctx context.Context) <-chan types.VtxoEvent
	GetUtxoEventChannel(ctx context.Context) <-chan types.UtxoEvent
	RedeemNotes(ctx context.Context, notes []string, opts ...Option) (string, error)
	SignTransaction(ctx context.Context, tx string) (string, error)
	NotifyIncomingFunds(ctx context.Context, address string) ([]types.Vtxo, error)
	FinalizePendingTxs(ctx context.Context, createdAfter *time.Time) ([]string, error)
	Reset(ctx context.Context)
	Stop()
}
