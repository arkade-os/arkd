package domain

import "context"

type VtxoRepository interface {
	AddVtxos(ctx context.Context, vtxos []Vtxo) error
	SpendVtxos(ctx context.Context, vtxos []Outpoint, txid string) error
	RedeemVtxos(ctx context.Context, vtxos []Outpoint) error
	GetVtxos(ctx context.Context, vtxos []Outpoint) ([]Vtxo, error)
	GetVtxosForRound(ctx context.Context, txid string) ([]Vtxo, error)
	SweepVtxos(ctx context.Context, vtxos []Outpoint) error
	GetAllNonRedeemedVtxos(ctx context.Context, pubkey string) ([]Vtxo, []Vtxo, error)
	GetAllSweepableVtxos(ctx context.Context) ([]Vtxo, error)
	GetSpendableVtxosWithPubKey(ctx context.Context, pubkey string) ([]Vtxo, error)
	GetAll(ctx context.Context) ([]Vtxo, error)
	GetAllVtxosWithPubKey(ctx context.Context, pubkey string) ([]Vtxo, []Vtxo, error)
	GetAllVtxosWithPubKeys(ctx context.Context, pubkeys []string, spendableOnly, spentOnly bool) ([]Vtxo, error)
	UpdateExpireAt(ctx context.Context, vtxos []Outpoint, expireAt int64) error
	GetLeafVtxosForRound(ctx context.Context, txid string) ([]Vtxo, error)
	Close()
}
