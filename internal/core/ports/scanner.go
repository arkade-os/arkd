package ports

import (
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/wire"
	"golang.org/x/net/context"
)

type VtxoWithValue struct {
	domain.Outpoint
	Value uint64
}

type BlockchainScanner interface {
	WatchScripts(ctx context.Context, scripts []string) error
	UnwatchScripts(ctx context.Context, scripts []string) error
	GetNotificationChannel(ctx context.Context) <-chan map[string][]VtxoWithValue
	IsTransactionConfirmed(
		ctx context.Context, txid string,
	) (isConfirmed bool, blocknumber int64, blocktime int64, err error)
	RescanUtxos(ctx context.Context, outpoints []wire.OutPoint) error
}
