package domain

import "context"

type VtxoRepository interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) error
	SettleVtxos(ctx context.Context, spentVtxos map[Outpoint]string, commitmentTxid string) error
	SpendVtxos(ctx context.Context, spentVtxos map[Outpoint]string, arkTxid string) error
	UnrollVtxos(ctx context.Context, outpoints []Outpoint) error
	SweepVtxos(ctx context.Context, outpoints []Outpoint) error
	GetVtxos(ctx context.Context, outpoints []Outpoint) ([]Vtxo, error)
	GetVtxosForRound(ctx context.Context, txid string) ([]Vtxo, error)
	GetAllNonUnrolledVtxos(ctx context.Context, pubkey string) ([]Vtxo, []Vtxo, error)
	GetAllSweepableVtxos(ctx context.Context) ([]Vtxo, error)
	GetAllSweepableUnrolledVtxos(ctx context.Context) ([]Vtxo, error)
	GetAllVtxos(ctx context.Context) ([]Vtxo, error)
	GetAllVtxosWithPubKeys(ctx context.Context, pubkeys []string) ([]Vtxo, error)
	UpdateVtxosExpiration(ctx context.Context, outpoints []Outpoint, expiresAt int64) error
	GetLeafVtxosForBatch(ctx context.Context, txid string) ([]Vtxo, error)
	Close()
}
