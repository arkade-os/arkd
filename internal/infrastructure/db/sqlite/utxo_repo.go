package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
)

type utxoRepository struct {
	db SQLiteDB
}

func NewUtxoRepository(config ...interface{}) (domain.UtxoRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(SQLiteDB)
	if !ok {
		return nil, fmt.Errorf("failed to open utxo repository: invalid config")
	}

	return &utxoRepository{
		db: db,
	}, nil
}

func (r *utxoRepository) Close() {
	_ = r.db.Close()
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

		for i := range utxos {
			utxo := utxos[i]

			pubkeySet := len(utxo.PubKey) > 0
			amountSet := utxo.Amount > 0
			if pubkeySet != amountSet {
				return fmt.Errorf(
					"utxo %s has invalid amount (%d) and pubkey (%s), they must be "+
						"either defined or null", utxo.Outpoint, utxo.Amount, utxo.PubKey,
				)
			}

			if err := querierWithTx.InsertUtxo(
				ctx, queries.InsertUtxoParams{
					Txid:      utxo.Txid,
					Vout:      int64(utxo.VOut),
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

	return execTx(ctx, r.db.Write(), txBody)
}

func (r *utxoRepository) UpdateUtxos(ctx context.Context, utxos []domain.Utxo) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for i := range utxos {
			utxo := utxos[i]

			if utxo.Spend.ConfirmedAtHeight == 0 || utxo.Spend.ConfirmedAtTime <= 0 {
				return fmt.Errorf(
					"utxo %s has invalid confirmation info (time: %d, height: %d)",
					utxo.Outpoint, utxo.Spend.ConfirmedAtTime, utxo.Spend.ConfirmedAtHeight,
				)
			}

			n, err := querierWithTx.UpdateUtxo(
				ctx, queries.UpdateUtxoParams{
					Txid: utxo.Txid,
					Vout: int64(utxo.VOut),
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

	return execTx(ctx, r.db.Write(), txBody)
}

func (r *utxoRepository) GetUtxos(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Utxo, error) {
	if len(outpoints) == 0 {
		return nil, nil
	}

	var rows []queries.UtxoVw
	if err := withReadQuerier(ctx, r.db, func(q *queries.Queries) error {
		var err error
		rows, err = q.SelectUtxosByTxids(ctx, uniqueTxids(outpoints))
		return err
	}); err != nil {
		return nil, err
	}
	return keepUtxoOutpoints(readUtxos(rows), outpoints), nil
}

func (r *utxoRepository) GetUnconfirmedUtxos(ctx context.Context) ([]domain.Utxo, error) {
	var rows []queries.UtxoVw
	if err := withReadQuerier(ctx, r.db, func(q *queries.Queries) error {
		var err error
		rows, err = q.SelectUnconfirmedSpentUtxos(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	return readUtxos(rows), nil
}

func (r *utxoRepository) GetUtxosWithPubKeys(
	ctx context.Context, pubkeys []string, page domain.Page,
) ([]domain.Utxo, int32, error) {
	var res []queries.SelectUtxosWithPubkeysPageRow
	var total int32
	if err := withReadQuerier(ctx, r.db, func(q *queries.Queries) error {
		rows, err := selectUtxosPage(ctx, q, pubkeys, page.Limit, page.Offset)
		if err != nil {
			return err
		}
		if len(rows) > 0 {
			res, total = rows, int32(rows[0].Total)
			return nil
		}

		// The total rides on the returned rows: a page past the end needs a
		// second read to recover it.
		first, err := selectUtxosPage(ctx, q, pubkeys, 1, 0)
		if err != nil {
			return err
		}
		if len(first) > 0 {
			total = int32(first[0].Total)
		}
		return nil
	}); err != nil {
		return nil, 0, err
	}

	if len(res) == 0 {
		return nil, total, nil
	}

	rows := make([]queries.UtxoVw, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.UtxoVw)
	}

	return readUtxos(rows), total, nil
}

func (r *utxoRepository) GetOnchainTxs(ctx context.Context, txids []string) ([]string, error) {
	var txs []string
	if err := withReadQuerier(ctx, r.db, func(q *queries.Queries) error {
		var err error
		txs, err = q.SelectOnchainTxs(ctx, txids)
		return err
	}); err != nil {
		return nil, err
	}
	return txs, nil
}

func selectUtxosPage(
	ctx context.Context, q *queries.Queries, pubkeys []string, limit, offset int32,
) ([]queries.SelectUtxosWithPubkeysPageRow, error) {
	return q.SelectUtxosWithPubkeysPage(ctx, queries.SelectUtxosWithPubkeysPageParams{
		Pubkeys: pubkeys,
		Lim:     int64(limit),
		Off:     int64(offset),
	})
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

func keepUtxoOutpoints(utxos []domain.Utxo, outpoints []domain.Outpoint) []domain.Utxo {
	wanted := make(map[domain.Outpoint]struct{}, len(outpoints))
	for _, o := range outpoints {
		wanted[o] = struct{}{}
	}
	kept := utxos[:0]
	for _, utxo := range utxos {
		if _, ok := wanted[utxo.Outpoint]; ok {
			kept = append(kept, utxo)
		}
	}
	return kept
}
