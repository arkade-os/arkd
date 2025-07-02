package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/infrastructure/db/sqlite/sqlc/queries"
)

type vtxoRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewVtxoRepository(config ...interface{}) (domain.VtxoRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open vtxo repository: invalid config")
	}

	return &vtxoRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (v *vtxoRepository) Close() {
	_ = v.db.Close()
}

func (v *vtxoRepository) AddVtxos(ctx context.Context, vtxos []domain.Vtxo) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for i := range vtxos {
			vtxo := vtxos[i]

			if err := querierWithTx.UpsertVtxo(
				ctx, queries.UpsertVtxoParams{
					Txid:         vtxo.Txid,
					Vout:         int64(vtxo.VOut),
					Pubkey:       vtxo.PubKey,
					Amount:       int64(vtxo.Amount),
					RoundTx:      vtxo.RootCommitmentTxid,
					SpentBy:      sql.NullString{String: vtxo.SpentBy, Valid: len(vtxo.SpentBy) > 0},
					Spent:        vtxo.Spent,
					Redeemed:     vtxo.Redeemed,
					Swept:        vtxo.Swept,
					Preconfirmed: vtxo.Preconfirmed,
					ExpireAt:     vtxo.ExpireAt,
					CreatedAt:    vtxo.CreatedAt,
					ArkTxid:      sql.NullString{String: vtxo.ArkTxid, Valid: len(vtxo.ArkTxid) > 0},
					SettledBy:    sql.NullString{String: vtxo.SettledBy, Valid: len(vtxo.SettledBy) > 0},
				},
			); err != nil {
				return err
			}
			for _, txid := range vtxo.CommitmentTxids {
				if err := querierWithTx.InsertVtxoCommitmentTxid(ctx, queries.InsertVtxoCommitmentTxidParams{
					VtxoTxid:       vtxo.Txid,
					VtxoVout:       int64(vtxo.VOut),
					CommitmentTxid: txid,
				}); err != nil {
					return err
				}
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *vtxoRepository) GetAllSweepableVtxos(ctx context.Context) ([]domain.Vtxo, error) {
	res, err := v.querier.SelectSweepableVtxos(ctx)
	if err != nil {
		return nil, err
	}

	rows := make([]queries.VtxoVw, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.VtxoVw)
	}
	return readRows(rows)
}

func (v *vtxoRepository) GetAllNonRedeemedVtxos(ctx context.Context, pubkey string) ([]domain.Vtxo, []domain.Vtxo, error) {
	withPubkey := len(pubkey) > 0

	var rows []queries.VtxoVw
	if withPubkey {
		res, err := v.querier.SelectNotRedeemedVtxosWithPubkey(ctx, pubkey)
		if err != nil {
			return nil, nil, err
		}
		rows = make([]queries.VtxoVw, 0, len(res))
		for _, row := range res {
			rows = append(rows, row.VtxoVw)
		}
	} else {
		res, err := v.querier.SelectNotRedeemedVtxos(ctx)
		if err != nil {
			return nil, nil, err
		}
		rows = make([]queries.VtxoVw, 0, len(res))
		for _, row := range res {
			rows = append(rows, row.VtxoVw)
		}
	}

	vtxos, err := readRows(rows)
	if err != nil {
		return nil, nil, err
	}

	unspentVtxos := make([]domain.Vtxo, 0)
	spentVtxos := make([]domain.Vtxo, 0)

	for _, vtxo := range vtxos {
		if vtxo.Spent || vtxo.Swept {
			spentVtxos = append(spentVtxos, vtxo)
		} else {
			unspentVtxos = append(unspentVtxos, vtxo)
		}
	}

	return unspentVtxos, spentVtxos, nil
}

func (v *vtxoRepository) GetVtxos(ctx context.Context, outpoints []domain.Outpoint) ([]domain.Vtxo, error) {
	vtxos := make([]domain.Vtxo, 0, len(outpoints))
	for _, o := range outpoints {
		res, err := v.querier.SelectVtxoByOutpoint(
			ctx,
			queries.SelectVtxoByOutpointParams{
				Txid: o.Txid,
				Vout: int64(o.VOut),
			},
		)
		if err != nil {
			return nil, err
		}

		result, err := readRows([]queries.VtxoVw{res.VtxoVw})
		if err != nil {
			return nil, err
		}

		if len(result) == 0 {
			return nil, fmt.Errorf("vtxo not found")
		}

		vtxos = append(vtxos, result[0])
	}

	return vtxos, nil
}

func (v *vtxoRepository) GetAll(ctx context.Context) ([]domain.Vtxo, error) {
	res, err := v.querier.SelectAllVtxos(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]queries.VtxoVw, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.VtxoVw)
	}

	return readRows(rows)
}

func (v *vtxoRepository) GetVtxosForRound(ctx context.Context, txid string) ([]domain.Vtxo, error) {
	res, err := v.querier.SelectVtxosByRoundTxid(ctx, txid)
	if err != nil {
		return nil, err
	}
	rows := make([]queries.VtxoVw, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.VtxoVw)
	}

	return readRows(rows)
}

func (v *vtxoRepository) GetLeafVtxosForRound(ctx context.Context, txid string) ([]domain.Vtxo, error) {
	res, err := v.querier.SelectLeafVtxosByRoundTxid(ctx, txid)
	if err != nil {
		return nil, err
	}
	rows := make([]queries.VtxoVw, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.VtxoVw)
	}

	return readRows(rows)
}

func (v *vtxoRepository) GetSpendableVtxosWithPubKey(ctx context.Context, pubkey string) ([]domain.Vtxo, error) {
	rows, err := v.querier.GetSpendableVtxosWithPubKey(ctx, pubkey)
	if err != nil {
		return nil, err
	}

	return readRows(rows)
}

func (v *vtxoRepository) RedeemVtxos(ctx context.Context, vtxos []domain.Outpoint) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for _, vtxo := range vtxos {
			if err := querierWithTx.MarkVtxoAsRedeemed(
				ctx,
				queries.MarkVtxoAsRedeemedParams{
					Txid: vtxo.Txid,
					Vout: int64(vtxo.VOut),
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *vtxoRepository) SettleVtxos(
	ctx context.Context, spentVtxos map[domain.Outpoint]string, settledBy string,
) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for vtxo, spentBy := range spentVtxos {
			if err := querierWithTx.MarkVtxoAsSettled(
				ctx,
				queries.MarkVtxoAsSettledParams{
					SpentBy:   sql.NullString{String: spentBy, Valid: len(spentBy) > 0},
					SettledBy: sql.NullString{String: settledBy, Valid: true},
					Txid:      vtxo.Txid,
					Vout:      int64(vtxo.VOut),
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *vtxoRepository) SpendVtxos(
	ctx context.Context, spentVtxos map[domain.Outpoint]string, arkTxid string,
) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for vtxo, spentBy := range spentVtxos {
			if err := querierWithTx.MarkVtxoAsSpent(
				ctx,
				queries.MarkVtxoAsSpentParams{
					SpentBy: sql.NullString{String: spentBy, Valid: len(spentBy) > 0},
					ArkTxid: sql.NullString{String: arkTxid, Valid: true},
					Txid:    vtxo.Txid,
					Vout:    int64(vtxo.VOut),
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *vtxoRepository) SweepVtxos(ctx context.Context, vtxos []domain.Outpoint) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for _, vtxo := range vtxos {
			if err := querierWithTx.MarkVtxoAsSwept(
				ctx,
				queries.MarkVtxoAsSweptParams{
					Txid: vtxo.Txid,
					Vout: int64(vtxo.VOut),
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *vtxoRepository) UpdateExpireAt(ctx context.Context, vtxos []domain.Outpoint, expireAt int64) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for _, vtxo := range vtxos {
			if err := querierWithTx.UpdateVtxoExpireAt(
				ctx,
				queries.UpdateVtxoExpireAtParams{
					ExpireAt: expireAt,
					Txid:     vtxo.Txid,
					Vout:     int64(vtxo.VOut),
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *vtxoRepository) GetAllVtxosWithPubKeys(
	ctx context.Context, pubkeys []string,
) ([]domain.Vtxo, error) {
	res, err := v.querier.SelectVtxosWithPubkeys(ctx, pubkeys)
	if err != nil {
		return nil, err
	}
	rows := make([]queries.VtxoVw, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.VtxoVw)
	}

	vtxos, err := readRows(rows)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(vtxos, func(i, j int) bool {
		return vtxos[i].CreatedAt > vtxos[j].CreatedAt
	})

	return vtxos, nil
}

func rowToVtxo(row queries.VtxoVw) domain.Vtxo {
	var commitmentTxids []string
	if commitments, ok := row.Commitments.(string); ok && commitments != "" {
		commitmentTxids = strings.Split(commitments, ",")
	}
	return domain.Vtxo{
		Outpoint: domain.Outpoint{
			Txid: row.Txid,
			VOut: uint32(row.Vout),
		},
		Amount:             uint64(row.Amount),
		PubKey:             row.Pubkey,
		RootCommitmentTxid: row.RoundTx,
		CommitmentTxids:    commitmentTxids,
		SettledBy:          row.SettledBy.String,
		ArkTxid:            row.ArkTxid.String,
		SpentBy:            row.SpentBy.String,
		Spent:              row.Spent,
		Redeemed:           row.Redeemed,
		Swept:              row.Swept,
		Preconfirmed:       row.Preconfirmed,
		ExpireAt:           row.ExpireAt,
		CreatedAt:          row.CreatedAt,
	}
}

func readRows(rows []queries.VtxoVw) ([]domain.Vtxo, error) {
	vtxos := make([]domain.Vtxo, 0, len(rows))
	for _, vtxo := range rows {
		vtxos = append(vtxos, rowToVtxo(vtxo))
	}

	return vtxos, nil
}
