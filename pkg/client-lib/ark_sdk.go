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
	Dump(ctx context.Context) (seed string, err error)
	SignTransaction(ctx context.Context, tx string) (string, error)
	Reset(ctx context.Context)
	Stop()
	// ** Funding **
	Receive(ctx context.Context) (onchainAddr, offchainAddr, boardingAddr string, err error)
	GetAddresses(ctx context.Context) (
		onchainAddresses, offchainAddresses, boardingAddresses, redemptionAddresses []string,
		err error,
	)
	Balance(ctx context.Context) (*Balance, error)
	ListVtxos(ctx context.Context) (spendable, spent []types.Vtxo, err error)
	GetTransactionHistory(ctx context.Context) ([]types.Transaction, error)
	NotifyIncomingFunds(ctx context.Context, address string) ([]types.Vtxo, error)
	// ** Offchain txs **
	SendOffChain(
		ctx context.Context, receivers []types.Receiver, opts ...SendOption,
	) (string, error)
	FinalizePendingTxs(ctx context.Context, createdAfter *time.Time) ([]string, error)
	// ** Batch session *+
	Settle(ctx context.Context, opts ...SettleOption) (string, error)
	CollaborativeExit(
		ctx context.Context, addr string, amount uint64, opts ...SettleOption,
	) (string, error)
	RedeemNotes(ctx context.Context, notes []string, opts ...SettleOption) (string, error)
	RegisterIntent(
		ctx context.Context, vtxos []types.Vtxo, boardingUtxos []types.Utxo, notes []string,
		outputs []types.Receiver, cosignersPublicKeys []string,
	) (intentID string, err error)
	DeleteIntent(
		ctx context.Context, vtxos []types.Vtxo, boardingUtxos []types.Utxo, notes []string,
	) error
	// ** Unroll **
	Unroll(ctx context.Context, opts ...UnrollOption) error
	CompleteUnroll(ctx context.Context, to string) (string, error)
	OnboardAgainAllExpiredBoardings(ctx context.Context) (string, error)
	WithdrawFromAllExpiredBoardings(ctx context.Context, to string) (string, error)
}
