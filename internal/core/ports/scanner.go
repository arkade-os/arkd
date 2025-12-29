package ports

import (
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/wire"
	"golang.org/x/net/context"
)

type OutpointWithValue struct {
	domain.Outpoint
	Value uint64
}

type BlockchainScanner interface {
	WatchScripts(ctx context.Context, scripts []string) error
	UnwatchScripts(ctx context.Context, scripts []string) error
	UnwatchAllScripts(ctx context.Context) error
	GetNotificationChannel(ctx context.Context) <-chan map[string][]OutpointWithValue
	IsTransactionConfirmed(
		ctx context.Context, txid string,
	) (isConfirmed bool, blockTimestamp *BlockTimestamp, err error)
	RescanUtxos(ctx context.Context, outpoints []wire.OutPoint) error
}
