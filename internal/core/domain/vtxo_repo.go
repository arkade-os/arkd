package domain

import "context"

type VtxoRepository interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) error
	SettleVtxos(ctx context.Context, spentVtxos map[Outpoint]string, commitmentTxid string) error
	SpendVtxos(ctx context.Context, spentVtxos map[Outpoint]string, arkTxid string) error
	UnrollVtxos(ctx context.Context, outpoints []Outpoint) error
	SweepVtxos(ctx context.Context, outpoints []Outpoint) (int, error)
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
	GetSweepableVtxosByCommitmentTxid(
		ctx context.Context, commitmentTxid string,
	) ([]Outpoint, error)
	GetAllChildrenVtxos(ctx context.Context, txid string) ([]Outpoint, error)
	GetVtxoPubKeysByCommitmentTxid(
		ctx context.Context, commitmentTxid string, withMinimumAmount uint64,
	) (
		[]string, error,
	)
	GetPendingSpentVtxosWithPubKeys(
		ctx context.Context,
		pubkeys []string,
		after, before int64,
	) ([]Vtxo, error)
	GetPendingSpentVtxosWithOutpoints(ctx context.Context, outpoints []Outpoint) ([]Vtxo, error)
	AddVirtualTxsRequest(ctx context.Context, expiry int64) (string, error)
	ValidateVirtualTxsRequest(ctx context.Context, authCode string) (bool, error)
	Close()
}
