package ports

import (
	"context"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/wire"
)

type VtxoWithValue struct {
	domain.Outpoint
	Value uint64
}

// Spend is a watched output that has been spent onchain, and the transaction
// spending it. Confirmations is 0 while the spend is only in the mempool.
type Spend struct {
	domain.Outpoint
	SpendingTxid  string
	Confirmations uint32
}

type BlockchainScanner interface {
	WatchScripts(ctx context.Context, scripts []string) error
	UnwatchScripts(ctx context.Context, scripts []string) error
	GetNotificationChannel(ctx context.Context) <-chan map[string][]VtxoWithValue
	// GetSpendNotificationChannel streams spends of watched outputs. It is
	// separate from GetNotificationChannel so existing consumers are unaffected.
	GetSpendNotificationChannel(ctx context.Context) <-chan []Spend
	IsTransactionConfirmed(
		ctx context.Context, txid string,
	) (isConfirmed bool, blockTimestamp *BlockTimestamp, err error)
	// GetSpends returns every watched output spent by a confirmed or unconfirmed
	// transaction, windowed from the given instant when one is supplied.
	GetSpends(ctx context.Context, from *time.Time) ([]Spend, error)
	// GetUnspentOutpoints returns the watched outputs currently unspent. Presence
	// here is positive evidence both that an outpoint is unspent and that its
	// script is still watched, which is what makes it safe to retract a spend.
	GetUnspentOutpoints(ctx context.Context) (map[domain.Outpoint]struct{}, error)
	RescanUtxos(ctx context.Context, outpoints []wire.OutPoint) error
}
