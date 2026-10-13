package pgdb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/postgres/sqlc/queries"
)

type utxoRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewUtxoRepository(config ...interface{}) (domain.UtxoRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open vtxo repository: invalid config")
	}

	return &utxoRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (v *utxoRepository) Close() {
	_ = v.db.Close()
}

func (r *utxoRepository) AddUtxos(ctx context.Context, utxos []domain.Utxo, tx string) error {
	if len(utxos) <= 0 {
		return nil
	}

	txBody := func(querierWithTx *queries.Queries) error {
		if len(tx) > 0 {
			if err := querierWithTx.InsertOnchainTx(ctx, queries.InsertOnchainTxParams{
				Txid: utxos[0].Spend.Txid,
				Tx:   tx,
			}); err != nil {
				return err
			}
		}
		for _, utxo := range utxos {

			if err := querierWithTx.InsertUtxo(
				ctx, queries.InsertUtxoParams{
					Txid:      utxo.Txid,
					Vout:      int32(utxo.VOut),
					Pubkey:    sql.NullString{String: utxo.PubKey, Valid: len(utxo.PubKey) > 0},
					Amount:    sql.NullInt64{Int64: int64(utxo.Amount), Valid: utxo.Amount > 0},
					SpentBy:   utxo.Spend.Txid,
					CreatedAt: utxo.CreatedAt,
				},
			); err != nil {
				return err
			}
		}
		return nil
	}

	return execTx(ctx, r.db, txBody)
}

func (r *utxoRepository) UpdateUtxos(ctx context.Context, utxos []domain.Utxo) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for _, utxo := range utxos {

			if utxo.Spend.ConfirmedAtHeight == 0 || utxo.Spend.ConfirmedAtTime <= 0 {
				return fmt.Errorf(
					"utxo %s has invalid confirmation info (time: %d, height: %d)",
					utxo.Outpoint, utxo.Spend.ConfirmedAtTime, utxo.Spend.ConfirmedAtHeight,
				)
			}

			n, err := querierWithTx.UpdateUtxo(
				ctx, queries.UpdateUtxoParams{
					Txid: utxo.Txid,
					Vout: int32(utxo.VOut),
					SpendConfirmedAtTime: sql.NullInt64{
						Int64: utxo.Spend.ConfirmedAtTime,
						Valid: true,
					},
					SpendConfirmedAtHeight: sql.NullInt64{
						Int64: int64(utxo.Spend.ConfirmedAtHeight),
						Valid: true,
					},
				},
			)
			if err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("utxo %s not found or already confirmed", utxo.Outpoint)
			}
		}
		return nil
	}

	return execTx(ctx, r.db, txBody)
}

func (r *utxoRepository) GetUtxos(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Utxo, error) {
	txids := make([]string, 0, len(outpoints))
	vouts := make([]int32, 0, len(outpoints))
	for _, o := range outpoints {
		txids = append(txids, o.Txid)
		vouts = append(vouts, int32(o.VOut))
	}
	rows, err := r.querier.SelectUtxosByOutpoints(ctx, queries.SelectUtxosByOutpointsParams{
		Txids: txids,
		Vouts: vouts,
	})
	if err != nil {
		return nil, err
	}
	return readUtxos(rows), nil
}

func (r *utxoRepository) GetUtxosWithPubKeys(
	ctx context.Context, pubkeys []string, page domain.Page,
) ([]domain.Utxo, int32, error) {
	res, err := r.selectUtxosPage(ctx, pubkeys, page.Limit, page.Offset)
	if err != nil {
		return nil, 0, err
	}

	// The total rides on the returned rows: a page past the end needs a second
	// read to recover it.
	if len(res) == 0 {
		first, err := r.selectUtxosPage(ctx, pubkeys, 1, 0)
		if err != nil {
			return nil, 0, err
		}
		if len(first) == 0 {
			return nil, 0, nil
		}
		return nil, first[0].Total, nil
	}

	total := res[0].Total
	rows := make([]queries.UtxoVw, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.UtxoVw)
	}

	return readUtxos(rows), total, nil
}

func (r *utxoRepository) GetUnconfirmedUtxosWithSpendingTxid(
	ctx context.Context, txid string,
) ([]domain.Utxo, error) {
	rows, err := r.querier.SelectUnconfirmedUtxosWithSpendingTxid(ctx, txid)
	if err != nil {
		return nil, err
	}
	return readUtxos(rows), nil
}

// GetUnconfirmedUtxos returns the utxos whose spend is not confirmed yet, split by the kind of
// spending tx: a tx cosigned by us, recorded along with the utxos, a commitment tx spending a
// boarding utxo, or a checkpoint, forfeit or exit path tx spending an unrolled vtxo. An
// unrolled vtxo spent by a cosigned tx counts as cosigned.
func (r *utxoRepository) GetUnconfirmedUtxos(
	ctx context.Context,
) (cosignedUtxos, boardingUtxos, unrolledVtxos []domain.Utxo, err error) {
	rows, err := r.querier.SelectUnconfirmedSpentUtxos(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, row := range rows {
		utxo := rowToUtxo(row.UtxoVw)
		isVtxo, _ := row.UtxoVw.IsVtxo.(bool)
		switch {
		case row.IsCosigned:
			cosignedUtxos = append(cosignedUtxos, utxo)
		case isVtxo:
			unrolledVtxos = append(unrolledVtxos, utxo)
		default:
			boardingUtxos = append(boardingUtxos, utxo)
		}
	}
	return cosignedUtxos, boardingUtxos, unrolledVtxos, nil
}

func (r *utxoRepository) GetOnchainTxs(ctx context.Context, txids []string) ([]string, error) {
	if len(txids) <= 0 {
		return nil, nil
	}
	return r.querier.SelectOnchainTxs(ctx, txids)
}

func (r *utxoRepository) selectUtxosPage(
	ctx context.Context, pubkeys []string, limit, offset int32,
) ([]queries.SelectUtxosWithPubkeysPageRow, error) {
	if len(pubkeys) <= 0 {
		return nil, nil
	}

	res, err := r.querier.SelectUtxosWithPubkeysPage(
		ctx, queries.SelectUtxosWithPubkeysPageParams{
			Pubkeys: pubkeys,
			Lim:     limit,
			Off:     offset,
		},
	)
	return res, err
}

func readUtxos(rows []queries.UtxoVw) []domain.Utxo {
	utxos := make([]domain.Utxo, 0, len(rows))
	for _, row := range rows {
		utxos = append(utxos, rowToUtxo(row))
	}

	return utxos
}

func rowToUtxo(row queries.UtxoVw) domain.Utxo {
	return domain.Utxo{
		Outpoint: domain.Outpoint{
			Txid: row.Txid,
			VOut: uint32(row.Vout),
		},
		Amount:    uint64(row.Amount),
		PubKey:    row.Pubkey,
		CreatedAt: row.CreatedAt,
		Spend: domain.UtxoSpend{
			Txid:              row.SpentBy,
			ConfirmedAtTime:   row.SpendConfirmedAtTime.Int64,
			ConfirmedAtHeight: uint64(row.SpendConfirmedAtHeight.Int64),
		},
	}
}
