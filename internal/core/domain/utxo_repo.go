package domain

import (
	"context"
)

type UtxoRepository interface {
	AddUtxos(ctx context.Context, utxos []Utxo, tx string) error
	UpdateUtxos(ctx context.Context, utxos []Utxo) error
	GetUtxos(ctx context.Context, outpoints []Outpoint) ([]Utxo, error)
	GetUtxosWithPubKeys(ctx context.Context, pubkeys []string, page Page) ([]Utxo, int32, error)
	GetUnconfirmedUtxos(
		ctx context.Context,
	) (cosignedUtxos, boardingUtxos, unrolledVtxos []Utxo, err error)
	GetUnconfirmedUtxosWithSpendingTxid(ctx context.Context, txid string) ([]Utxo, error)
	GetOnchainTxs(ctx context.Context, txids []string) ([]string, error)
}
