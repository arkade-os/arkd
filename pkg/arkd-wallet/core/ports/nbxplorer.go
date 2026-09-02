package ports

import (
	"context"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
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

// Spend is a tracked output that has been spent, together with the transaction
// spending it. Confirmations is 0 while the spend is only in the mempool.
type Spend struct {
	wire.OutPoint
	SpendingTxid  string
	Confirmations uint32
}

// ChainNotification is one transaction's effect on the tracked scripts: the
// outputs it created, and the tracked outputs it spent. Both halves come from
// the same event, so a caller sees them together.
type ChainNotification struct {
	Utxos  []Utxo
	Spends []Spend
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
	RescanUtxos(ctx context.Context, outpoints []wire.OutPoint) error

	IsSpent(ctx context.Context, outpoint wire.OutPoint) (spent bool, err error)
	// GetSpends returns every tracked output spent by a confirmed or unconfirmed
	// transaction. When from is non-nil the query is windowed from that instant,
	// which keeps the response bounded on a group with a long history.
	GetSpends(ctx context.Context, from *time.Time) ([]Spend, error)
	// GetTxSpends returns the tracked outputs spent by a single transaction. It
	// returns no spends, and no error, for a transaction that touches nothing
	// tracked.
	GetTxSpends(ctx context.Context, txid string) ([]Spend, error)
	// GetUnspentOutpoints returns the tracked outputs currently unspent. Presence
	// here is positive evidence both that an outpoint is unspent and that its
	// script is still tracked, which is what makes it safe to retract a spend.
	GetUnspentOutpoints(ctx context.Context) (map[wire.OutPoint]struct{}, error)
	WatchAddresses(ctx context.Context, addresses ...string) error
	UnwatchAddresses(ctx context.Context, addresses ...string) error
	GetAddressNotifications(ctx context.Context) (<-chan ChainNotification, error)

	Close() error
}
