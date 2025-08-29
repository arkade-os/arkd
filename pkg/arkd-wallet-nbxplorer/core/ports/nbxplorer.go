package ports

import (
	"context"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

type BitcoinStatus struct {
	ChainTipHeight uint32
	ChainTipTime   int64
	Synced         bool
	MinRelayTxFee  chainfee.SatPerKVByte
}

type TransactionDetails struct {
	TxID          string
	Hex           string
	Height        uint32
	Timestamp     int64
	Confirmations uint32
}

type Utxo struct {
	wire.OutPoint
	Value         uint64
	Script        string
	Address       string
	Confirmations uint32
}

type ScriptPubKeyDetails struct {
	KeyPath string
}

type ScanUtxoSetProgress struct {
	Progress int
	Done     bool
}

// Nbxplorer acts as the "backend" for the wallet Service
type Nbxplorer interface {
	GetBitcoinStatus(ctx context.Context) (*BitcoinStatus, error)
	GetTransaction(ctx context.Context, txid string) (*TransactionDetails, error)
	ScanUtxoSet(ctx context.Context, derivationScheme string, gapLimit int) <-chan ScanUtxoSetProgress
	Track(ctx context.Context, derivationScheme string) error
	GetUtxos(ctx context.Context, derivationScheme string) ([]Utxo, error)
	GetScriptPubKeyDetails(ctx context.Context, derivationScheme string, script string) (*ScriptPubKeyDetails, error)
	GetNewUnusedAddress(ctx context.Context, derivationScheme string, change bool, skip int) (string, error)
	EstimateFeeRate(ctx context.Context) (chainfee.SatPerKVByte, error)
	BroadcastTransaction(ctx context.Context, txs ...string) (string, error)

	WatchAddresses(ctx context.Context, addresses ...string) error
	UnwatchAddresses(ctx context.Context, addresses ...string) error
	GetAddressNotifications(ctx context.Context) (<-chan []Utxo, error)

	Close() error
}
