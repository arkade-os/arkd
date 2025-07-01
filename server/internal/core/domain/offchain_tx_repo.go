package domain

import "context"

type OffchainTxRepository interface {
	AddOrUpdateOffchainTx(ctx context.Context, offchainTx *OffchainTx) error
	GetOffchainTx(ctx context.Context, txid string) (*OffchainTx, error)
	Close()
}
