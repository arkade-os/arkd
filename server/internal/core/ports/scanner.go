package ports

import (
	"github.com/ark-network/ark/server/internal/core/domain"
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
	IsTransactionConfirmed(ctx context.Context, txid string) (isConfirmed bool, blocknumber int64, blocktime int64, err error)
}
