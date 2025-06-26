package ports

import (
	"context"
	"errors"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	// ErrNonFinalBIP68 is returned when a transaction spending a CSV-locked output is not final.
	ErrNonFinalBIP68 = errors.New("non-final BIP68 sequence")
)

type WalletService interface {
	BlockchainScanner
	GetReadyUpdate(ctx context.Context) (<-chan struct{}, error)
	GenSeed(ctx context.Context) (string, error)
	Create(ctx context.Context, seed, password string) error
	Restore(ctx context.Context, seed, password string) error
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context) error
	Status(ctx context.Context) (WalletStatus, error)
	GetPubkey(ctx context.Context) (*secp256k1.PublicKey, error)
	GetNetwork(ctx context.Context) (*common.Network, error)
	GetForfeitAddress(ctx context.Context) (string, error)
	DeriveConnectorAddress(ctx context.Context) (string, error)
	DeriveAddresses(ctx context.Context, num int) ([]string, error)
	SignTransaction(
		ctx context.Context, partialTx string, extractRawTx bool,
	) (string, error)
	SignTransactionTapscript(ctx context.Context, partialTx string, inputIndexes []int) (string, error) // inputIndexes == nil means sign all inputs
	SelectUtxos(ctx context.Context, asset string, amount uint64, confirmedOnly bool) ([]TxInput, uint64, error)
	BroadcastTransaction(ctx context.Context, txs ...string) (string, error)
	WaitForSync(ctx context.Context, txid string) error
	EstimateFees(ctx context.Context, psbt string) (uint64, error)
	FeeRate(ctx context.Context) (uint64, error)
	ListConnectorUtxos(ctx context.Context, connectorAddress string) ([]TxInput, error)
	MainAccountBalance(ctx context.Context) (uint64, uint64, error)
	ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error)
	LockConnectorUtxos(ctx context.Context, utxos []domain.Outpoint) error
	GetDustAmount(ctx context.Context) (uint64, error)
	GetTransaction(ctx context.Context, txid string) (string, error)
	GetCurrentBlockTime(ctx context.Context) (*BlockTimestamp, error)
	Withdraw(ctx context.Context, address string, amount uint64) (string, error)
	Close()
}

type WalletStatus interface {
	IsInitialized() bool
	IsUnlocked() bool
	IsSynced() bool
}

type TxInput interface {
	GetTxid() string
	GetIndex() uint32
	GetScript() string
	GetValue() uint64
}

type BlockTimestamp struct {
	Height uint32
	Time   int64
}
