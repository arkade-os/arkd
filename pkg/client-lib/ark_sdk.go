package arksdk

import (
	"context"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
)

var Version string

type ArkClient interface {
	Wallet() wallet.WalletService
	Transport() client.TransportClient
	Indexer() indexer.Indexer
	Explorer() explorer.Explorer

	GetVersion() string
	GetConfigData(ctx context.Context) (*types.Config, error)
	Init(ctx context.Context, args InitArgs) error
	InitWithWallet(ctx context.Context, args InitWithWalletArgs) error
	IsLocked(ctx context.Context) bool
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context) error
	Dump(ctx context.Context) (seed string, err error)
	SignTransaction(ctx context.Context, tx string, opts ...SignOption) (string, error)
	Reset(ctx context.Context)
	Stop()
	// ** Funding **
	Receive(
		ctx context.Context,
	) (onchainAddr string, offchainAddr, boardingAddr *types.Address, err error)
	GetAddresses(ctx context.Context) (
		onchainAddresses []string,
		offchainAddresses, boardingAddresses, redemptionAddresses []types.Address, err error,
	)
	Balance(ctx context.Context) (*Balance, error)
	ListVtxos(
		ctx context.Context, opts ...ListVtxosOption,
	) (spendable, spent []types.Vtxo, err error)
	GetTransactionHistory(ctx context.Context) ([]types.Transaction, error)
	NotifyIncomingFunds(ctx context.Context, address string) ([]types.Vtxo, error)
	// ** Assets **
	IssueAsset(
		ctx context.Context, amount uint64, controlAsset types.ControlAsset,
		metadata []asset.Metadata, opts ...SendOption,
	) (*IssueAssetRes, error)
	ReissueAsset(
		ctx context.Context, assetId string, amount uint64, opts ...SendOption,
	) (*ReissueAssetRes, error)
	BurnAsset(
		ctx context.Context, assetID string, amount uint64, opts ...SendOption,
	) (*BurnAssetRes, error)
	// ** Offchain txs **
	SendOffChain(
		ctx context.Context, receivers []types.Receiver, opts ...SendOption,
	) (*SendOffChainRes, error)
	FinalizePendingTxs(
		ctx context.Context, createdAfter *time.Time, opts ...SendOption,
	) ([]string, error)
	// ** Batch session **
	Settle(ctx context.Context, opts ...BatchSessionOption) (*SettleRes, error)
	CollaborativeExit(
		ctx context.Context, addr string, amount uint64, opts ...BatchSessionOption,
	) (*CollaborativeExitRes, error)
	RedeemNotes(
		ctx context.Context, notes []string, opts ...BatchSessionOption,
	) (*RedeemNotesRes, error)
	RegisterIntent(
		ctx context.Context, vtxos []types.Vtxo, boardingUtxos []types.Utxo, notes []string,
		outputs []types.Receiver, cosignersPublicKeys []string, opts ...SignOption,
	) (intentID string, err error)
	DeleteIntent(
		ctx context.Context, vtxos []types.Vtxo, boardingUtxos []types.Utxo,
		notes []string, opts ...SignOption,
	) error
	// ** Unroll **
	Unroll(ctx context.Context, opts ...UnrollOption) ([]UnrollRes, error)
	CompleteUnroll(ctx context.Context, to string, opts ...UnrollOption) (string, error)
	OnboardAgainAllExpiredBoardings(ctx context.Context, opts ...UnrollOption) (string, error)
	WithdrawFromAllExpiredBoardings(
		ctx context.Context, to string, opts ...UnrollOption,
	) (string, error)
}

type ReissueAssetRes = OffchainTxRes

type BurnAssetRes = OffchainTxRes

type SendOffChainRes = OffchainTxRes

type FinalizePendingTxsRes = []OffchainTxRes

type SettleRes = BatchTxRes

type CollaborativeExitRes = BatchTxRes

type RedeemNotesRes = BatchTxRes

type UnrollRes struct {
	ParentTx   string
	ParentTxid string
	ChildTx    string
	ChildTxid  string
}

type IssueAssetRes struct {
	OffchainTxRes
	IssuedAssets []asset.AssetId
}

type BatchTxRes struct {
	CommitmentTxid string
	CommitmentTx   string
	IntentTx       string
	ForfeitTxs     []string
	VtxoInputs     []types.Vtxo
	UtxoInputs     []types.Utxo
	VtxoOutputs    []types.Vtxo
	UtxoOutputs    []types.Receiver
	Extension      extension.Extension
}

type OffchainTxRes struct {
	Txid        string
	Tx          string
	Checkpoints []string
	Inputs      []types.Vtxo
	Outputs     []types.Receiver
	Extension   extension.Extension
}
