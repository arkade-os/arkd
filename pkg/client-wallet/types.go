package wallet

import (
	"context"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsession "github.com/arkade-os/arkd/pkg/client-lib/batch-session"
	offchaintx "github.com/arkade-os/arkd/pkg/client-lib/offchain-tx"
	"github.com/arkade-os/arkd/pkg/client-wallet/types"
)

var Version string

type Wallet interface {
	Identity() clientlib.Identity
	Client() clientlib.Client
	Indexer() clientlib.Indexer
	Explorer() clientlib.Explorer

	GetVersion() string
	GetConfigData(ctx context.Context) (*types.Config, error)
	Init(ctx context.Context, args InitArgs) error
	IsLocked(ctx context.Context) bool
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context) error
	Dump(ctx context.Context) (seed string, err error)
	SignTransaction(ctx context.Context, tx string) (string, error)
	Reset(ctx context.Context)
	Stop()
	// ** Funding **
	Receive(
		ctx context.Context,
	) (onchainAddr string, offchainAddr, boardingAddr *clientlib.Address, err error)
	GetAddresses(ctx context.Context) (
		onchainAddresses []string,
		offchainAddresses, boardingAddresses, redemptionAddresses []clientlib.Address, err error,
	)
	Balance(ctx context.Context) (*types.Balance, error)
	ListVtxos(
		ctx context.Context, opts ...ListVtxosOption,
	) (spendable, spent []clientlib.Vtxo, err error)
	GetTransactionHistory(ctx context.Context) ([]clientlib.Transaction, error)
	NotifyIncomingFunds(ctx context.Context, address string) ([]clientlib.Vtxo, error)
	// ** Assets **
	IssueAsset(
		ctx context.Context, amount uint64, controlAsset clientlib.ControlAsset,
		metadata []asset.Metadata, opts ...offchaintx.Option,
	) (*IssueAssetRes, error)
	ReissueAsset(
		ctx context.Context, assetId string, amount uint64, opts ...offchaintx.Option,
	) (*ReissueAssetRes, error)
	BurnAsset(
		ctx context.Context, assetId string, amount uint64, opts ...offchaintx.Option,
	) (*BurnAssetRes, error)
	// ** Offchain txs **
	SendOffChain(
		ctx context.Context, receivers []clientlib.Receiver, opts ...offchaintx.Option,
	) (*SendOffChainRes, error)
	FinalizePendingTxs(ctx context.Context, createdAfter *time.Time) ([]string, error)
	// ** Batch session **
	Settle(ctx context.Context, opts ...batchsession.Option) (*SettleRes, error)
	CollaborativeExit(
		ctx context.Context, addr string, amount uint64, opts ...batchsession.Option,
	) (*CollaborativeExitRes, error)
	RedeemNotes(
		ctx context.Context, notes []string, opts ...batchsession.Option,
	) (*RedeemNotesRes, error)
	RegisterIntent(
		ctx context.Context, vtxos []clientlib.Vtxo, boardingUtxos []clientlib.Utxo, notes []string,
		outputs []clientlib.Receiver, cosignersPublicKeys []string,
	) (intentID string, err error)
	DeleteIntent(
		ctx context.Context, vtxos []clientlib.Vtxo, boardingUtxos []clientlib.Utxo, notes []string,
	) error
	// ** Unroll **
	Unroll(ctx context.Context, opts ...UnrollOption) ([]UnrollRes, error)
	CompleteUnroll(ctx context.Context, opts ...UnrollOption) (string, error)
	OnboardAgainAllExpiredBoardings(ctx context.Context) (string, error)
	WithdrawFromAllExpiredBoardings(ctx context.Context, opts ...UnrollOption) (string, error)
}

type SendOffChainRes = offchaintx.OffchainTxRes

type ReissueAssetRes = offchaintx.OffchainTxRes

type BurnAssetRes = offchaintx.OffchainTxRes

type IssueAssetRes = offchaintx.IssueAssetRes

type SettleRes = batchsession.BatchTxRes

type CollaborativeExitRes = batchsession.BatchTxRes

type RedeemNotesRes = batchsession.BatchTxRes

type UnrollRes struct {
	ParentTx   string
	ParentTxid string
	ChildTx    string
	ChildTxid  string
}
