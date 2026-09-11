package domain

import "context"

type VtxoRepository interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) error
	SettleVtxos(ctx context.Context, spentVtxos map[Outpoint]string, commitmentTxid string) error
	SpendVtxos(ctx context.Context, spentVtxos map[Outpoint]string, arkTxid string) error
	UnrollVtxos(ctx context.Context, outpoints []Outpoint) error
	// RecordCosignedTx records a transaction arkd cosigned in one durable write.
	// The inputs are marked spent by txid and left with no ark txid, which is
	// what distinguishes an onchain spend from an in-Ark one. The outputs are
	// inserted as VtxoKindOnchainPending regardless of the kind the caller set,
	// since nothing arkd has only cosigned is spendable yet.
	//
	// Both halves land together or not at all. The caller holds a claim on the
	// inputs across this write and releases it afterwards, so a partial write
	// would free an input whose spend was never recorded.
	RecordCosignedTx(ctx context.Context, txid string, inputs []Outpoint, outputs []Vtxo) error
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
	GetSweepableVtxosByCommitmentTxid(
		ctx context.Context, commitmentTxid string,
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
	GetPendingSpentVtxosWithPubKeys(
		ctx context.Context,
		pubkeys []string,
		after, before int64,
	) ([]Vtxo, error)
	GetPendingSpentVtxosWithOutpoints(ctx context.Context, outpoints []Outpoint) ([]Vtxo, error)
	Close()
}
