package sqlitedb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
)

type vtxoRepository struct {
	db SQLiteDB
}

func NewVtxoRepository(config ...interface{}) (domain.VtxoRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(SQLiteDB)
	if !ok {
		return nil, fmt.Errorf("cannot open vtxo repository: invalid config")
	}

	return &vtxoRepository{
		db: db,
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
					Txid:           vtxo.Txid,
					Vout:           int64(vtxo.VOut),
					Pubkey:         vtxo.PubKey,
					Amount:         int64(vtxo.Amount),
					CommitmentTxid: vtxo.RootCommitmentTxid,
					SpentBy: sql.NullString{
						String: vtxo.SpentBy,
						Valid:  len(vtxo.SpentBy) > 0,
					},
					Spent:        vtxo.Spent,
					Unrolled:     vtxo.Unrolled,
					Swept:        vtxo.Swept,
					Preconfirmed: vtxo.Preconfirmed,
					ExpiresAt:    vtxo.ExpiresAt,
					CreatedAt:    vtxo.CreatedAt,
					ArkTxid: sql.NullString{
						String: vtxo.ArkTxid,
						Valid:  len(vtxo.ArkTxid) > 0,
					},
					SettledBy: sql.NullString{
						String: vtxo.SettledBy,
						Valid:  len(vtxo.SettledBy) > 0,
					},
				},
			); err != nil {
				return err
			}
			for _, txid := range vtxo.CommitmentTxids {
				if err := querierWithTx.InsertVtxoCommitmentTxid(
					ctx, queries.InsertVtxoCommitmentTxidParams{
						VtxoTxid:       vtxo.Txid,
						VtxoVout:       int64(vtxo.VOut),
						CommitmentTxid: txid,
					},
				); err != nil {
					return err
				}
			}

			for _, asset := range vtxo.Assets {
				if err := querierWithTx.InsertVtxoAssetProjection(
					ctx, queries.InsertVtxoAssetProjectionParams{
						AssetID: asset.AssetId,
						Txid:    vtxo.Txid,
						Vout:    int64(vtxo.VOut),
						Amount:  strconv.FormatUint(asset.Amount, 10),
					},
				); err != nil {
					return err
				}
			}
		}

		return nil
	}

	return execTx(ctx, v.db.Write(), txBody)
}

func (v *vtxoRepository) GetAllSweepableUnrolledVtxos(
	ctx context.Context,
) ([]domain.Vtxo, error) {
	var res []queries.SelectSweepableUnrolledVtxosRow
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		var err error
		res, err = q.SelectSweepableUnrolledVtxos(ctx)
		return err
	}); err != nil {
		return nil, err
	}

	rows := make([]queries.VtxoVw, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.VtxoVw)
	}
	return readRows(rows)
}

func (v *vtxoRepository) GetAllNonUnrolledVtxos(
	ctx context.Context, pubkey string,
) ([]domain.Vtxo, []domain.Vtxo, error) {
	withPubkey := len(pubkey) > 0

	var rows []queries.VtxoVw
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		if withPubkey {
			res, err := q.SelectNotUnrolledVtxosWithPubkey(ctx, pubkey)
			if err != nil {
				return err
			}
			rows = make([]queries.VtxoVw, 0, len(res))
			for _, row := range res {
				rows = append(rows, row.VtxoVw)
			}
			return nil
		}

		res, err := q.SelectNotUnrolledVtxos(ctx)
		if err != nil {
			return err
		}
		rows = make([]queries.VtxoVw, 0, len(res))
		for _, row := range res {
			rows = append(rows, row.VtxoVw)
		}
		return nil
	}); err != nil {
		return nil, nil, err
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

func (v *vtxoRepository) GetVtxos(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	vtxos := make([]domain.Vtxo, 0, len(outpoints))
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		for _, o := range outpoints {
			res, err := q.SelectVtxo(
				ctx,
				queries.SelectVtxoParams{Txid: o.Txid, Vout: int64(o.VOut)},
			)
			if err != nil {
				return err
			}

			if len(res) == 0 {
				continue
			}

			rows := make([]queries.VtxoVw, 0, len(res))
			for _, row := range res {
				rows = append(rows, row.VtxoVw)
			}

			result, err := readRows(rows)
			if err != nil {
				return err
			}

			if len(result) == 0 {
				continue
			}

			vtxos = append(vtxos, result[0])
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return vtxos, nil
}

func (v *vtxoRepository) GetAllVtxos(ctx context.Context) ([]domain.Vtxo, error) {
	var res []queries.SelectAllVtxosRow
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		var err error
		res, err = q.SelectAllVtxos(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	rows := make([]queries.VtxoVw, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.VtxoVw)
	}

	return readRows(rows)
}

func (v *vtxoRepository) GetExpiringLiquidity(
	ctx context.Context, after, before int64,
) (uint64, error) {
	var amount interface{}
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		var err error
		amount, err = q.SelectExpiringLiquidityAmount(
			ctx,
			queries.SelectExpiringLiquidityAmountParams{After: after, Before: before},
		)
		return err
	}); err != nil {
		return 0, err
	}

	n, ok := amount.(int64)
	if !ok {
		return 0, fmt.Errorf("unexpected sqlite amount type: %T", amount)
	}
	if n < 0 {
		return 0, fmt.Errorf("data integrity issue: got negative value %d", n)
	}
	return uint64(n), nil
}

func (v *vtxoRepository) GetRecoverableLiquidity(ctx context.Context) (uint64, error) {
	var amount interface{}
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		var err error
		amount, err = q.SelectRecoverableLiquidityAmount(ctx)
		return err
	}); err != nil {
		return 0, err
	}
	n, ok := amount.(int64)
	if !ok {
		return 0, nil
	}
	if n < 0 {
		return 0, fmt.Errorf("data integrity issue: got negative value %d", n)
	}
	return uint64(n), nil
}

func (v *vtxoRepository) GetLeafVtxosForBatch(
	ctx context.Context, txid string,
) ([]domain.Vtxo, error) {
	var res []queries.SelectRoundVtxoTreeLeavesRow
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		var err error
		res, err = q.SelectRoundVtxoTreeLeaves(ctx, txid)
		return err
	}); err != nil {
		return nil, err
	}
	rows := make([]queries.VtxoVw, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.VtxoVw)
	}

	return readRows(rows)
}

func (v *vtxoRepository) UnrollVtxos(ctx context.Context, vtxos []domain.Outpoint) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for _, vtxo := range vtxos {
			if err := querierWithTx.UpdateVtxoUnrolled(
				ctx, queries.UpdateVtxoUnrolledParams{Txid: vtxo.Txid, Vout: int64(vtxo.VOut)},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db.Write(), txBody)
}

func (v *vtxoRepository) SettleVtxos(
	ctx context.Context, spentVtxos map[domain.Outpoint]string, settledBy string,
) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for vtxo, spentBy := range spentVtxos {
			if err := querierWithTx.UpdateVtxoSettled(
				ctx,
				queries.UpdateVtxoSettledParams{
					SpentBy:   sql.NullString{String: spentBy, Valid: len(spentBy) > 0},
					SettledBy: sql.NullString{String: settledBy, Valid: len(settledBy) > 0},
					Txid:      vtxo.Txid,
					Vout:      int64(vtxo.VOut),
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db.Write(), txBody)
}

func (v *vtxoRepository) SpendVtxos(
	ctx context.Context, spentVtxos map[domain.Outpoint]string, arkTxid string,
) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for vtxo, spentBy := range spentVtxos {
			if err := querierWithTx.UpdateVtxoSpent(
				ctx,
				queries.UpdateVtxoSpentParams{
					SpentBy: sql.NullString{String: spentBy, Valid: len(spentBy) > 0},
					ArkTxid: sql.NullString{String: arkTxid, Valid: len(arkTxid) > 0},
					Txid:    vtxo.Txid,
					Vout:    int64(vtxo.VOut),
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db.Write(), txBody)
}

func (v *vtxoRepository) SweepVtxos(ctx context.Context, vtxos []domain.Outpoint) (int, error) {
	sweptCount := 0
	txBody := func(querierWithTx *queries.Queries) error {
		for _, outpoint := range vtxos {
			affectedRows, err := querierWithTx.UpdateVtxoSweptIfNotSwept(
				ctx,
				queries.UpdateVtxoSweptIfNotSweptParams{
					Txid: outpoint.Txid,
					Vout: int64(outpoint.VOut),
				},
			)
			if err != nil {
				return err
			}
			if affectedRows > 0 {
				sweptCount++
			}
		}

		return nil
	}

	if err := execTx(ctx, v.db.Write(), txBody); err != nil {
		return -1, err
	}

	return sweptCount, nil
}

func (v *vtxoRepository) UpdateVtxosExpiration(
	ctx context.Context, vtxos []domain.Outpoint, expiresAt int64,
) error {
	txBody := func(querierWithTx *queries.Queries) error {
		for _, vtxo := range vtxos {
			if err := querierWithTx.UpdateVtxoExpiration(
				ctx,
				queries.UpdateVtxoExpirationParams{
					ExpiresAt: expiresAt,
					Txid:      vtxo.Txid,
					Vout:      int64(vtxo.VOut),
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db.Write(), txBody)
}

func (v *vtxoRepository) GetAllVtxosWithPubKeys(
	ctx context.Context, pubkeys []string, after, before int64,
) ([]domain.Vtxo, error) {
	if err := validateTimeRange(after, before); err != nil {
		return nil, err
	}
	var res []queries.SelectVtxosWithPubkeysRow
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		var err error
		res, err = q.SelectVtxosWithPubkeys(ctx, queries.SelectVtxosWithPubkeysParams{
			Pubkeys: pubkeys,
			After:   sql.NullInt64{Int64: after, Valid: true},
			Before:  before,
		})
		return err
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
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

func (v *vtxoRepository) GetSweepableVtxosByCommitmentTxid(
	ctx context.Context,
	commitmentTxid string,
) (
	[]domain.Outpoint, error,
) {
	var res []queries.SelectSweepableVtxoOutpointsByCommitmentTxidRow
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		var err error
		res, err = q.SelectSweepableVtxoOutpointsByCommitmentTxid(ctx, commitmentTxid)
		return err
	}); err != nil {
		return nil, err
	}

	outpoints := make([]domain.Outpoint, 0, len(res))
	for _, row := range res {
		outpoints = append(outpoints, domain.Outpoint{
			Txid: row.VtxoTxid,
			VOut: uint32(row.VtxoVout),
		})
	}

	return outpoints, nil
}

func (v *vtxoRepository) GetAllChildrenVtxos(
	ctx context.Context, txid string,
) ([]domain.Outpoint, error) {
	var res []queries.SelectVtxosOutpointsByArkTxidRecursiveRow
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		var err error
		res, err = q.SelectVtxosOutpointsByArkTxidRecursive(ctx, txid)
		return err
	}); err != nil {
		return nil, err
	}

	outpoints := make([]domain.Outpoint, 0, len(res))
	for _, row := range res {
		outpoints = append(outpoints, domain.Outpoint{
			Txid: row.Txid,
			VOut: uint32(row.Vout),
		})
	}

	return outpoints, nil
}

func (v *vtxoRepository) GetVtxoPubKeysByCommitmentTxid(
	ctx context.Context, commitmentTxid string, withMinimumAmount uint64,
) ([]string, error) {
	if commitmentTxid == "" {
		return nil, nil
	}

	var taprootKeys []string
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		var err error
		taprootKeys, err = q.SelectVtxoPubKeysByCommitmentTxid(ctx,
			queries.SelectVtxoPubKeysByCommitmentTxidParams{
				MinAmount:      int64(withMinimumAmount),
				CommitmentTxid: commitmentTxid,
			})
		return err
	}); err != nil {
		return nil, err
	}

	return taprootKeys, nil
}

func (v *vtxoRepository) GetPendingSpentVtxosWithPubKeys(
	ctx context.Context, pubkeys []string, after, before int64,
) ([]domain.Vtxo, error) {
	if err := validateTimeRange(after, before); err != nil {
		return nil, err
	}
	var rows []queries.VtxoVw
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		var err error
		rows, err = q.SelectPendingSpentVtxosWithPubkeys(
			ctx,
			queries.SelectPendingSpentVtxosWithPubkeysParams{
				Pubkeys: pubkeys,
				After:   sql.NullInt64{Int64: after, Valid: true},
				Before:  before,
			},
		)
		return err
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
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

func (v *vtxoRepository) GetPendingSpentVtxosWithOutpoints(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	var vtxos []domain.Vtxo
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		for _, outpoint := range outpoints {
			res, err := q.SelectPendingSpentVtxo(
				ctx, queries.SelectPendingSpentVtxoParams{Txid: outpoint.Txid, Vout: int64(outpoint.VOut)},
			)
			if err != nil {
				return err
			}

			if len(res) == 0 {
				continue
			}

			result, err := readRows(res)
			if err != nil {
				return err
			}

			vtxos = append(vtxos, result...)
		}

		return nil
	}); err != nil {
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
	assets := make([]domain.AssetDenomination, 0)
	if row.AssetID != "" {
		assets = append(assets, rowToAsset(row))
	}
	return domain.Vtxo{
		Outpoint: domain.Outpoint{
			Txid: row.Txid,
			VOut: uint32(row.Vout),
		},
		Amount:             uint64(row.Amount),
		PubKey:             row.Pubkey,
		RootCommitmentTxid: row.CommitmentTxid,
		CommitmentTxids:    commitmentTxids,
		SettledBy:          row.SettledBy.String,
		ArkTxid:            row.ArkTxid.String,
		SpentBy:            row.SpentBy.String,
		Spent:              row.Spent,
		Unrolled:           row.Unrolled,
		Swept:              row.Swept,
		Preconfirmed:       row.Preconfirmed,
		ExpiresAt:          row.ExpiresAt,
		CreatedAt:          row.CreatedAt,
		Assets:             assets,
	}
}

func rowToAsset(row queries.VtxoVw) domain.AssetDenomination {
	// nolint
	amount, _ := strconv.ParseUint(row.AssetAmount, 10, 64)
	return domain.AssetDenomination{
		AssetId: row.AssetID,
		Amount:  amount,
	}
}

func readRows(rows []queries.VtxoVw) ([]domain.Vtxo, error) {
	vtxosByOutpoint := make(map[string]domain.Vtxo)
	for _, row := range rows {
		key := fmt.Sprintf("%s:%d", row.Txid, row.Vout)
		if _, ok := vtxosByOutpoint[key]; !ok {
			vtxosByOutpoint[key] = rowToVtxo(row)
			continue
		}

		asset := rowToAsset(row)
		emptyAsset := domain.AssetDenomination{}
		if asset != emptyAsset {
			vtxo := vtxosByOutpoint[key]
			vtxo.Assets = append(
				vtxosByOutpoint[key].Assets, asset,
			)
			vtxosByOutpoint[key] = vtxo
		}
	}

	vtxos := make([]domain.Vtxo, 0, len(rows))
	for _, vtxo := range vtxosByOutpoint {
		vtxos = append(vtxos, vtxo)
	}

	return vtxos, nil
}
