package application

import (
	"context"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

var (
	// ErrNonFinalBIP68 is returned when a transaction spending a CSV-locked output is not final.
	ErrNonFinalBIP68 = errors.New("non-final BIP68 sequence")
)

type WalletService interface {
	BlockchainScanner
	GetReadyUpdate(ctx context.Context) <-chan struct{}
	GenSeed(ctx context.Context) (string, error)
	Create(ctx context.Context, seed, password string) error
	Restore(ctx context.Context, seed, password string) error
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context) error
	Status(ctx context.Context) (WalletStatus, error)
	GetPubkey(ctx context.Context) (*btcec.PublicKey, error)
	GetNetwork(ctx context.Context) string
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
	FeeRate(ctx context.Context) (chainfee.SatPerKVByte, error)
	ListConnectorUtxos(ctx context.Context, connectorAddress string) ([]TxInput, error)
	MainAccountBalance(ctx context.Context) (uint64, uint64, error)
	ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error)
	LockConnectorUtxos(ctx context.Context, utxos []TxOutpoint) error
	GetDustAmount(ctx context.Context) uint64
	GetTransaction(ctx context.Context, txid string) (string, error)
	SignMessage(ctx context.Context, message []byte) ([]byte, error)
	VerifyMessageSignature(ctx context.Context, message, signature []byte) (bool, error)
	GetCurrentBlockTime(ctx context.Context) (*BlockTimestamp, error)
	Withdraw(ctx context.Context, address string, amount uint64) (string, error)
	Close()
}

type BlockchainScanner interface {
	WatchScripts(ctx context.Context, scripts []string) error
	UnwatchScripts(ctx context.Context, scripts []string) error
	GetNotificationChannel(ctx context.Context) <-chan map[string][]VtxoWithValue
	IsTransactionConfirmed(ctx context.Context, txid string) (isConfirmed bool, blocknumber int64, blocktime int64, err error)
}

type WalletStatus struct {
	IsInitialized bool
	IsUnlocked    bool
	IsSynced      bool
}

type TxInput struct {
	Txid   string
	Index  uint32
	Script string
	Value  uint64
}

type TxOutpoint struct {
	Txid  string
	Index uint32
}

type VtxoWithValue struct {
	Key   VtxoKey
	Value uint64
}

type VtxoKey struct {
	Txid string
	VOut uint32
}

type BlockTimestamp struct {
	Height uint32
	Time   int64
}
