package domain

import "context"

type VtxoRepository interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) error
	SettleVtxos(ctx context.Context, spentVtxos map[Outpoint]string, commitmentTxid string) error
	SpendVtxos(ctx context.Context, spentVtxos map[Outpoint]string, arkTxid string) error
	UnrollVtxos(ctx context.Context, outpoints []Outpoint) error
	// MarkVtxosOnchainSpent records unrolled vtxos spent onchain, outside the
	// Ark, mapping each outpoint to the txid that spent it. It also re-points an
	// already onchain-spent vtxo at a new spender, so an RBF replacement is
	// picked up. It never touches a vtxo spent offchain or settled in a batch.
	MarkVtxosOnchainSpent(ctx context.Context, spentBy map[Outpoint]string) error
	// UnmarkVtxosOnchainSpent retracts an onchain spend whose transaction was
	// evicted from the mempool or reorged out. Scoped to onchain-spent vtxos, so
	// it can never undo an offchain spend or a settlement.
	UnmarkVtxosOnchainSpent(ctx context.Context, outpoints []Outpoint) error
	GetVtxos(ctx context.Context, outpoints []Outpoint) ([]Vtxo, error)
	GetAllNonUnrolledVtxos(ctx context.Context, pubkey string) ([]Vtxo, []Vtxo, error)
	GetAllSweepableUnrolledVtxos(ctx context.Context) ([]Vtxo, error)
	// GetUnrolledUnspentVtxos returns unrolled vtxos currently believed unspent:
	// the candidate set the onchain-spend reconciler checks against the chain.
	GetUnrolledUnspentVtxos(ctx context.Context) ([]Vtxo, error)
	// GetOnchainSpentVtxos returns vtxos currently recorded as spent onchain, so
	// the reconciler can re-point or retract them.
	GetOnchainSpentVtxos(ctx context.Context) ([]Vtxo, error)
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
