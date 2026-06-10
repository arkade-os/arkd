package ports

import (
	"context"
	"errors"

	"github.com/arkade-os/arkd/internal/core/domain"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
)

var (
	// ErrNonFinalBIP68 is returned when a transaction spending a CSV-locked output is not final.
	ErrNonFinalBIP68 = errors.New("non-final BIP68 sequence")
)

type WalletService interface {
	BlockchainScanner
	GetReadyUpdate(ctx context.Context) (<-chan bool, error)
	GenSeed(ctx context.Context) (string, error)
	Create(ctx context.Context, seed, password string) error
	Restore(ctx context.Context, seed, password string) error
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context) error
	Status(ctx context.Context) (WalletStatus, error)
	GetNetwork(ctx context.Context) (*arklib.Network, error)
	GetForfeitPubkey(ctx context.Context) (*btcec.PublicKey, error)
	DeriveConnectorAddress(ctx context.Context) (string, error)
	DeriveAddresses(ctx context.Context, num int) ([]string, error)
	SignTransaction(ctx context.Context, partialTx string, extractRawTx bool) (string, error)
	SignTransactionTapscript(
		ctx context.Context, partialTx string, inputIndexes []int, // inputIndexes == nil means sign all inputs
	) (string, error)
	SelectUtxos(
		ctx context.Context, asset string, amount uint64, confirmedOnly bool,
	) ([]TxInput, uint64, error)
	BroadcastTransaction(ctx context.Context, txs ...string) (string, error)
	EstimateFees(ctx context.Context, psbt string) (uint64, error)
	FeeRate(ctx context.Context) (uint64, error)
	ListConnectorUtxos(ctx context.Context, connectorAddress string) ([]TxInput, error)
	// GetMainAccountUtxos lists the whole UTXO set of the main account,
	// including locked and unconfirmed UTXOs, each flagged accordingly.
	GetMainAccountUtxos(ctx context.Context) ([]WalletUtxo, error)
	MainAccountBalance(ctx context.Context) (uint64, uint64, error)
	ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error)
	LockConnectorUtxos(ctx context.Context, utxos []domain.Outpoint) error
	GetDustAmount(ctx context.Context) (uint64, error)
	GetTransaction(ctx context.Context, txid string) (string, error)
	GetOutpointStatus(ctx context.Context, outpoint domain.Outpoint) (spent bool, err error)
	GetCurrentBlockTime(ctx context.Context) (*BlockTimestamp, error)
	Withdraw(ctx context.Context, address string, amount uint64, all bool) (string, error)
	LoadSignerKey(ctx context.Context, prvkey string) error
	Close()
}

type WalletStatus interface {
	IsInitialized() bool
	IsUnlocked() bool
	IsSynced() bool
}

type TxInput struct {
	Txid          string
	Index         uint32
	Script        string // hex encoded
	Value         uint64
	TapscriptLeaf *Tapscript // nil if not tapscript spend
}

type Tapscript struct {
	InternalKey  string // hex encoded
	ControlBlock string // hex encoded
	Tapscript    string // hex encoded
}

// WalletUtxo describes a single UTXO of the main account, including its
// confirmation count and whether it is currently locked by a pending operation.
type WalletUtxo struct {
	Txid          string
	Vout          uint32
	Value         uint64
	Script        string // hex encoded
	Address       string
	Confirmations uint32
	Locked        bool
}

type BlockTimestamp struct {
	Height uint32
	Time   int64
}
