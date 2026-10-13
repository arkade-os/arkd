package pgdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/postgres/sqlc/queries"
	log "github.com/sirupsen/logrus"
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

			markersToMarshal := vtxo.MarkerIDs
			if markersToMarshal == nil {
				markersToMarshal = []string{}
			}
			data, err := json.Marshal(markersToMarshal)
			if err != nil {
				return fmt.Errorf("failed to marshal markers: %w", err)
			}
			markersJSON := json.RawMessage(data)

			if err := querierWithTx.UpsertVtxo(
				ctx, queries.UpsertVtxoParams{
					Txid:           vtxo.Txid,
					Vout:           int32(vtxo.VOut),
					Pubkey:         vtxo.PubKey,
					Amount:         int64(vtxo.Amount),
					CommitmentTxid: vtxo.RootCommitmentTxid,
					Spent:          vtxo.Spent,
					Unrolled:       vtxo.Unrolled,
					Preconfirmed:   vtxo.Preconfirmed,
					ExpiresAt:      vtxo.ExpiresAt,
					CreatedAt:      vtxo.CreatedAt,
					SpentBy: sql.NullString{
						String: vtxo.SpentBy, Valid: len(vtxo.SpentBy) > 0,
					},
					SettledBy: sql.NullString{
						String: vtxo.SettledBy, Valid: len(vtxo.SettledBy) > 0,
					},
					ArkTxid: sql.NullString{
						String: vtxo.ArkTxid, Valid: len(vtxo.ArkTxid) > 0,
					},
					Depth:   int32(vtxo.Depth),
					Markers: markersJSON,
				},
			); err != nil {
				return err
			}

			for _, txid := range vtxo.CommitmentTxids {
				if err := querierWithTx.InsertVtxoCommitmentTxid(
					ctx, queries.InsertVtxoCommitmentTxidParams{
						VtxoTxid:       vtxo.Txid,
						VtxoVout:       int32(vtxo.VOut),
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
						Vout:    int32(vtxo.VOut),
						Amount:  strconv.FormatUint(asset.Amount, 10),
					},
				); err != nil {
					return err
				}
			}
		}
		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *vtxoRepository) GetAllSweepableUnrolledVtxos(
	ctx context.Context,
) ([]domain.Vtxo, error) {
	res, err := v.querier.SelectSweepableUnrolledVtxos(ctx)
	if err != nil {
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
	if withPubkey {
		res, err := v.querier.SelectNotUnrolledVtxosWithPubkey(ctx, pubkey)
		if err != nil {
			return nil, nil, err
		}
		rows = make([]queries.VtxoVw, 0, len(res))
		for _, row := range res {
			rows = append(rows, row.VtxoVw)
		}
	} else {
		res, err := v.querier.SelectNotUnrolledVtxos(ctx)
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

func (v *vtxoRepository) GetVtxos(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	if len(outpoints) == 0 {
		return []domain.Vtxo{}, nil
	}

	txids, vouts := splitOutpoints(outpoints)
	res, err := v.querier.SelectVtxosByOutpoints(ctx, queries.SelectVtxosByOutpointsParams{
		Txids: txids,
		Vouts: vouts,
	})
	if err != nil {
		return nil, err
	}

	rows := make([]queries.VtxoVw, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.VtxoVw)
	}

	result, err := readRows(rows)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (v *vtxoRepository) GetExpiringLiquidity(
	ctx context.Context, after, before int64,
) (uint64, error) {
	amount, err := v.querier.SelectExpiringLiquidityAmount(
		ctx,
		queries.SelectExpiringLiquidityAmountParams{
			After:  after,
			Before: before,
		},
	)
	if err != nil {
		return 0, err
	}
	if amount < 0 {
		return 0, fmt.Errorf("data integrity issue: got negative value %d", amount)
	}
	return uint64(amount), nil
}

func (v *vtxoRepository) GetRecoverableLiquidity(ctx context.Context) (uint64, error) {
	amount, err := v.querier.SelectRecoverableLiquidityAmount(ctx)
	if err != nil {
		return 0, err
	}
	if amount < 0 {
		return 0, fmt.Errorf("data integrity issue: got negative value %d", amount)
	}
	return uint64(amount), nil
}

func (v *vtxoRepository) GetLeafVtxosForBatch(
	ctx context.Context, txid string,
) ([]domain.Vtxo, error) {
	res, err := v.querier.SelectRoundVtxoTreeLeaves(ctx, txid)
	if err != nil {
		return nil, err
	}
	rows := make([]queries.VtxoVw, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.VtxoVw)
	}

	return readRows(rows)
}

func (v *vtxoRepository) GetCheckpointTxsByVtxoPubKeys(
	ctx context.Context, pubkeys []string,
) ([]domain.Tx, error) {
	rows, err := v.querier.SelectCheckpointTxsByVtxoPubKeys(ctx, pubkeys)
	if err != nil {
		return nil, err
	}

	txs := make([]domain.Tx, 0, len(rows))
	for _, row := range rows {
		txs = append(txs, domain.Tx{Txid: row.Txid, Str: row.Data})
	}

	return txs, nil
}

func (v *vtxoRepository) UnrollVtxos(ctx context.Context, vtxos []domain.Outpoint) error {
	txBody := func(querierWithTx *queries.Queries) error {
		txids := make([]string, 0, len(vtxos))
		vouts := make([]int32, 0, len(vtxos))
		for _, vtxo := range vtxos {
			txids = append(txids, vtxo.Txid)
			vouts = append(vouts, int32(vtxo.VOut))
		}
		records, err := querierWithTx.UpdateVtxosUnrolled(ctx, queries.UpdateVtxosUnrolledParams{
			Txids: txids,
			Vouts: vouts,
		})
		if err != nil {
			return err
		}

		// For any vtxo already spent offchain, add a ref to the utxo table.
		for _, record := range records {
			if len(record.SpentBy.String) <= 0 {
				continue
			}
			if err := querierWithTx.InsertUtxo(
				ctx, queries.InsertUtxoParams{
					Txid:      record.Txid,
					Vout:      record.Vout,
					SpentBy:   record.SpentBy.String,
					CreatedAt: time.Now().Unix(),
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
			if err := querierWithTx.UpdateVtxoSettled(
				ctx,
				queries.UpdateVtxoSettledParams{
					SpentBy:   sql.NullString{String: spentBy, Valid: len(spentBy) > 0},
					SettledBy: sql.NullString{String: settledBy, Valid: len(settledBy) > 0},
					Txid:      vtxo.Txid,
					Vout:      int32(vtxo.VOut),
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
			if err := querierWithTx.UpdateVtxoSpent(
				ctx,
				queries.UpdateVtxoSpentParams{
					SpentBy: sql.NullString{String: spentBy, Valid: len(spentBy) > 0},
					ArkTxid: sql.NullString{String: arkTxid, Valid: true},
					Txid:    vtxo.Txid,
					Vout:    int32(vtxo.VOut),
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
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
					Vout:      int32(vtxo.VOut),
				},
			); err != nil {
				return err
			}
		}

		return nil
	}

	return execTx(ctx, v.db, txBody)
}

func (v *vtxoRepository) GetVtxosWithPubKeys(
	ctx context.Context, filter domain.VtxoFilter, page domain.Page,
) ([]domain.Vtxo, int32, error) {
	if err := validateTimeRange(filter.After, filter.Before); err != nil {
		return nil, 0, err
	}

	res, err := v.selectVtxosPage(ctx, filter, page.Limit, page.Offset)
	if err != nil {
		return nil, 0, err
	}

	// The total rides on the returned rows: a page past the end needs a second
	// read to recover it.
	if len(res) == 0 {
		first, err := v.selectVtxosPage(ctx, filter, 1, 0)
		if err != nil {
			return nil, 0, err
		}
		if len(first) == 0 {
			return nil, 0, nil
		}
		return nil, first[0].Total, nil
	}

	total := res[0].Total
	rows := make([]queries.VtxoVw, 0, len(res))
	for _, row := range res {
		rows = append(rows, row.VtxoVw)
	}

	vtxos, err := readRows(rows)
	if err != nil {
		return nil, 0, err
	}
	return vtxos, total, nil
}

func (v *vtxoRepository) selectVtxosPage(
	ctx context.Context, filter domain.VtxoFilter, limit, offset int32,
) ([]queries.SelectVtxosWithPubkeysPageRow, error) {
	res, err := v.querier.SelectVtxosWithPubkeysPage(
		ctx, queries.SelectVtxosWithPubkeysPageParams{
			Pubkeys:         filter.Pubkeys,
			After:           filter.After,
			Before:          filter.Before,
			SpendableOnly:   filter.SpendableOnly,
			SpentOnly:       filter.SpentOnly,
			RecoverableOnly: filter.RecoverableOnly,
			RenewableOnly:   filter.RenewableOnly,
			PendingOnly:     filter.PendingOnly,
			Lim:             limit,
			Off:             offset,
		},
	)
	return res, err
}

func (v *vtxoRepository) GetSweepableVtxosByCommitmentTxid(
	ctx context.Context,
	commitmentTxid string,
) ([]domain.Outpoint, error) {
	res, err := v.querier.SelectSweepableVtxoOutpointsByCommitmentTxid(ctx, commitmentTxid)
	if err != nil {
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

func (v *vtxoRepository) GetSweepableVtxosByCommitmentTxids(
	ctx context.Context, commitmentTxids []string,
) ([]domain.Outpoint, error) {
	if len(commitmentTxids) == 0 {
		return nil, nil
	}
	res, err := v.querier.SelectSweepableVtxoOutpointsByCommitmentTxids(ctx, commitmentTxids)
	if err != nil {
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
	ctx context.Context, outpoint domain.Outpoint,
) ([]domain.Outpoint, error) {
	res, err := v.querier.SelectVtxosOutpointsByArkTxidRecursive(
		ctx,
		queries.SelectVtxosOutpointsByArkTxidRecursiveParams{
			Txid: outpoint.Txid,
			Vout: int32(outpoint.VOut),
		},
	)
	if err != nil {
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

	taprootKeys, err := v.querier.SelectVtxoPubKeysByCommitmentTxid(ctx,
		queries.SelectVtxoPubKeysByCommitmentTxidParams{
			MinAmount:      int64(withMinimumAmount),
			CommitmentTxid: commitmentTxid,
		})
	if err != nil {
		return nil, err
	}

	return taprootKeys, nil
}

// GetVtxoPubKeysByCommitmentTxids is the bulk variant of
// GetVtxoPubKeysByCommitmentTxid. It returns the deduplicated set of vtxo
// pubkeys whose root commitment_txid is in the given list, or whose
// vtxo_commitment_txid join row references one of those commitment txids.
// This replaces a per-round loop in restoreWatchingVtxos / stopWatchingVtxos
// that previously fired one query per sweepable round (the N+1 pattern).
func (v *vtxoRepository) GetVtxoPubKeysByCommitmentTxids(
	ctx context.Context, commitmentTxids []string, withMinimumAmount uint64,
) ([]string, error) {
	if len(commitmentTxids) == 0 {
		return nil, nil
	}

	taprootKeys, err := v.querier.SelectVtxoPubKeysByCommitmentTxids(ctx,
		queries.SelectVtxoPubKeysByCommitmentTxidsParams{
			MinAmount:       int64(withMinimumAmount),
			CommitmentTxids: commitmentTxids,
		})
	if err != nil {
		return nil, err
	}

	return taprootKeys, nil
}

func (v *vtxoRepository) GetPendingSpentVtxosWithOutpoints(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	if len(outpoints) == 0 {
		return nil, nil
	}

	txids, vouts := splitOutpoints(outpoints)
	res, err := v.querier.SelectPendingSpentVtxosByOutpoints(
		ctx, queries.SelectPendingSpentVtxosByOutpointsParams{
			Txids: txids,
			Vouts: vouts,
		},
	)
	if err != nil {
		return nil, err
	}

	vtxos, err := readRows(res)
	if err != nil {
		return nil, err
	}

	return vtxos, nil
}

func rowToVtxo(row queries.VtxoVw) domain.Vtxo {
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
		CommitmentTxids:    parseCommitments(row.Commitments, []byte(",")),
		SettledBy:          row.SettledBy.String,
		ArkTxid:            row.ArkTxid.String,
		SpentBy:            row.SpentBy.String,
		Spent:              row.Spent,
		Unrolled:           row.Unrolled,
		Swept:              row.Swept.Bool,
		Preconfirmed:       row.Preconfirmed,
		ExpiresAt:          row.ExpiresAt,
		CreatedAt:          row.CreatedAt,
		Depth:              uint32(row.Depth),
		MarkerIDs:          parseMarkersJSONBFromVtxo(row.Markers),
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

// parseMarkersJSONBFromVtxo parses a JSONB array into a slice of strings for vtxo repo.
// Logs and returns nil if the JSON is malformed so that corrupt markers are
// surfaced instead of silently treated as empty.
func parseMarkersJSONBFromVtxo(markers json.RawMessage) []string {
	if len(markers) == 0 {
		return nil
	}
	var markerIDs []string
	if err := json.Unmarshal(markers, &markerIDs); err != nil {
		log.WithError(err).Warnf("failed to parse markers JSONB: %q", string(markers))
		return nil
	}
	return markerIDs
}

func splitOutpoints(outpoints []domain.Outpoint) ([]string, []int32) {
	txids := make([]string, 0, len(outpoints))
	vouts := make([]int32, 0, len(outpoints))
	for _, o := range outpoints {
		txids = append(txids, o.Txid)
		vouts = append(vouts, int32(o.VOut))
	}
	return txids, vouts
}

func readRows(rows []queries.VtxoVw) ([]domain.Vtxo, error) {
	vtxos := make([]domain.Vtxo, 0, len(rows))
	indexByOutpoint := make(map[string]int, len(rows))
	for _, row := range rows {
		key := fmt.Sprintf("%s:%d", row.Txid, row.Vout)
		i, ok := indexByOutpoint[key]
		if !ok {
			indexByOutpoint[key] = len(vtxos)
			vtxos = append(vtxos, rowToVtxo(row))
			continue
		}

		if asset := rowToAsset(row); asset != (domain.AssetDenomination{}) {
			vtxos[i].Assets = append(vtxos[i].Assets, asset)
		}
	}

	return vtxos, nil
}
