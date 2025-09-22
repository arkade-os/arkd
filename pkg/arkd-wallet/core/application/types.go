package application

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

const (
	SignModeLiquidityProvider = "liquidity_provider"
	SignModeSigner            = "signer"
)

type WalletService interface {
	GetReadyUpdate(ctx context.Context) <-chan struct{}
	GenSeed(ctx context.Context) (string, error)
	Create(ctx context.Context, seed, password string) error
	Restore(ctx context.Context, seed, password string) error
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context) error
	Status(ctx context.Context) WalletStatus
	GetNetwork(ctx context.Context) string
	GetSignerPubkey(ctx context.Context) (string, error)
	GetForfeitPubkey(ctx context.Context) (string, error)
	DeriveConnectorAddress(ctx context.Context) (string, error)
	DeriveAddresses(ctx context.Context, num int) ([]string, error)
	SignTransaction(
		ctx context.Context, signMode, partialTx string, extractRawTx bool, inputIndexes []int,
	) (string, error)
	SelectUtxos(ctx context.Context, amount uint64, confirmedOnly bool) ([]Utxo, uint64, error)
	BroadcastTransaction(ctx context.Context, txs ...string) (string, error)
	EstimateFees(ctx context.Context, psbt string) (uint64, error)
	FeeRate(ctx context.Context) (chainfee.SatPerKVByte, error)
	ListConnectorUtxos(ctx context.Context, connectorAddress string) ([]Utxo, error)
	MainAccountBalance(ctx context.Context) (uint64, uint64, error)
	ConnectorsAccountBalance(ctx context.Context) (uint64, uint64, error)
	LockConnectorUtxos(ctx context.Context, utxos []wire.OutPoint) error
	GetDustAmount(ctx context.Context) uint64
	GetTransaction(ctx context.Context, txid string) (string, error)
	GetCurrentBlockTime(ctx context.Context) (*BlockTimestamp, error)
	Withdraw(ctx context.Context, destinationAddress string, amount uint64) (string, error)
	LoadSignerKey(ctx context.Context, prvkey *btcec.PrivateKey) error
	Close()
}

type BlockchainScanner interface {
	WatchScripts(ctx context.Context, scripts []string) error
	UnwatchScripts(ctx context.Context, scripts []string) error
	GetNotificationChannel(ctx context.Context) <-chan map[string][]Utxo
	IsTransactionConfirmed(
		ctx context.Context, txid string,
	) (isConfirmed bool, blockHeight, blockTime int64, err error)
	Close()
}

type WalletStatus struct {
	IsInitialized bool
	IsUnlocked    bool
	IsSynced      bool
}

type Utxo struct {
	Txid   string
	Index  uint32
	Script string
	Value  uint64
}

type BlockTimestamp struct {
	Height uint32
	Time   int64
}

var ErrTransactionNotFound = fmt.Errorf("transaction not found")
