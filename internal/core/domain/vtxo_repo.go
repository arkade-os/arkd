package domain

import "context"

type VtxoRepository interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) error
	SettleVtxos(ctx context.Context, spentVtxos map[Outpoint]string, commitmentTxid string) error
	SpendVtxos(ctx context.Context, spentVtxos map[Outpoint]string, arkTxid string) error
	UnrollVtxos(ctx context.Context, outpoints []Outpoint) error
	GetVtxos(ctx context.Context, outpoints []Outpoint) ([]Vtxo, error)
	GetAllNonUnrolledVtxos(ctx context.Context, pubkey string) ([]Vtxo, []Vtxo, error)
	GetAllSweepableUnrolledVtxos(ctx context.Context) ([]Vtxo, error)
	GetAllVtxos(ctx context.Context) ([]Vtxo, error)
	GetAllVtxosWithPubKeys(
		ctx context.Context,
		pubkeys []string,
		after, before int64,
	) ([]Vtxo, error)
	GetExpiringLiquidity(ctx context.Context, after, before int64) (uint64, error)
	GetRecoverableLiquidity(ctx context.Context) (uint64, error)
	UpdateVtxosExpiration(ctx context.Context, outpoints []Outpoint, expiresAt int64) error
	GetLeafVtxosForBatch(ctx context.Context, txid string) ([]Vtxo, error)
	GetCheckpointTxsByVtxoPubKeys(ctx context.Context, pubkeys []string) ([]Tx, error)
	// returns only the preconfirmed vtxos of the batch, leaves are excluded
	GetSweepablePreconfirmedVtxosByCommitmentTxid(
		ctx context.Context, commitmentTxid string,
	) ([]Outpoint, error)
	// returns the vtxo of the given outpoint plus all its descendants
	GetAllChildrenVtxos(ctx context.Context, outpoint Outpoint) ([]Outpoint, error)
	// returns only the descendants, the vtxo of the given outpoint is excluded
	GetDescendantVtxos(ctx context.Context, outpoint Outpoint) ([]Outpoint, error)
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
	GetPendingSpentVtxosWithPubKeys(
		ctx context.Context,
		pubkeys []string,
		after, before int64,
	) ([]Vtxo, error)
	GetPendingSpentVtxosWithOutpoints(ctx context.Context, outpoints []Outpoint) ([]Vtxo, error)
	Close()
}
