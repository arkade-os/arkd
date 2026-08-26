package domain

import "context"

type OffchainTxRepository interface {
	AddOrUpdateOffchainTx(ctx context.Context, offchainTx *OffchainTx) error
	GetOffchainTx(ctx context.Context, txid string) (*OffchainTx, error)
	GetOffchainTxsByTxids(ctx context.Context, txids []string) ([]*OffchainTx, error)
	// GetAnyOffchainTx returns the offchain tx whatever its stage, including the ones that
	// failed before being accepted. Unlike GetOffchainTx it must not be used to detect
	// duplicates, as a tx failed at request stage is meant to be retriable.
	GetAnyOffchainTx(ctx context.Context, txid string) (*OffchainTx, error)
	// GetOffchainTxsInRange returns the offchain txs started within the given time range
	// (0 means unbounded). When limit is > 0 only the most recent ones are returned, but
	// the order of the returned slice is unspecified.
	GetOffchainTxsInRange(
		ctx context.Context, after, before int64, onlyFailed, onlyCompleted bool, limit int64,
	) ([]*OffchainTx, error)
	Close()
}
