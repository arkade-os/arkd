package domain

import "context"

type VtxoRepository interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) error
	SettleVtxos(ctx context.Context, spentVtxos map[Outpoint]string, commitmentTxid string) error
	SpendVtxos(ctx context.Context, spentVtxos map[Outpoint]string, arkTxid string) error
	RedeemVtxos(ctx context.Context, vtxos []Outpoint) error
	GetVtxos(ctx context.Context, vtxos []Outpoint) ([]Vtxo, error)
	GetVtxosForRound(ctx context.Context, txid string) ([]Vtxo, error)
	SweepVtxos(ctx context.Context, vtxos []Outpoint) error
	GetAllNonRedeemedVtxos(ctx context.Context, pubkey string) ([]Vtxo, []Vtxo, error)
	GetAllSweepableVtxos(ctx context.Context) ([]Vtxo, error)
	GetSpendableVtxosWithPubKey(ctx context.Context, pubkey string) ([]Vtxo, error)
	GetAll(ctx context.Context) ([]Vtxo, error)
	GetAllVtxosWithPubKeys(ctx context.Context, pubkeys []string) ([]Vtxo, error)
	UpdateExpireAt(ctx context.Context, vtxos []Outpoint, expireAt int64) error
	GetLeafVtxosForRound(ctx context.Context, txid string) ([]Vtxo, error)
	Close()
}
