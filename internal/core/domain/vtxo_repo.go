package domain

import "context"

// Page bounds a query in the db layer. A Limit of 0 or less means no limit,
// which is how a request without a page reads the whole set.
type Page struct {
	Limit  int32
	Offset int32
}

type VtxoRepository interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) error
	SettleVtxos(ctx context.Context, spentVtxos map[Outpoint]string, commitmentTxid string) error
	SpendVtxos(ctx context.Context, spentVtxos map[Outpoint]string, arkTxid string) error
	UnrollVtxos(ctx context.Context, outpoints []Outpoint) error
	GetVtxos(ctx context.Context, outpoints []Outpoint) ([]Vtxo, error)
	GetAllNonUnrolledVtxos(ctx context.Context, pubkey string) ([]Vtxo, []Vtxo, error)
	GetAllSweepableUnrolledVtxos(ctx context.Context) ([]Vtxo, error)
	GetExpiringLiquidity(ctx context.Context, after, before int64) (uint64, error)
	GetRecoverableLiquidity(ctx context.Context) (uint64, error)
	UpdateVtxosExpiration(ctx context.Context, outpoints []Outpoint, expiresAt int64) error
	GetLeafVtxosForBatch(ctx context.Context, txid string) ([]Vtxo, error)
	GetCheckpointTxsByVtxoPubKeys(ctx context.Context, pubkeys []string) ([]Tx, error)
	GetSweepableVtxosByCommitmentTxid(
		ctx context.Context, commitmentTxid string,
	) ([]Outpoint, error)
	// GetSweepableVtxosByCommitmentTxids is GetSweepableVtxosByCommitmentTxid
	// over a set of batches in one read, for the startup reconciliation.
	GetSweepableVtxosByCommitmentTxids(
		ctx context.Context, commitmentTxids []string,
	) ([]Outpoint, error)
	GetAllChildrenVtxos(ctx context.Context, outpoint Outpoint) ([]Outpoint, error)
	GetVtxoPubKeysByCommitmentTxid(
		ctx context.Context, commitmentTxid string, withMinimumAmount uint64,
	) (
		[]string, error,
	)
	GetVtxoPubKeysByCommitmentTxids(
		ctx context.Context, commitmentTxids []string, withMinimumAmount uint64,
	) (
		[]string, error,
	)
	GetPendingSpentVtxosWithOutpoints(ctx context.Context, outpoints []Outpoint) ([]Vtxo, error)
	GetVtxosWithPubKeys(
		ctx context.Context, filter VtxoFilter, page Page,
	) ([]Vtxo, int32, error)
	GetVtxosWithAssets(ctx context.Context, filter VtxoFilter, page Page) ([]Vtxo, int32, error)
	Close()
}
