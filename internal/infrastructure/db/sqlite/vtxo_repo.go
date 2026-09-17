package sqlitedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
	log "github.com/sirupsen/logrus"
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

			markersToMarshal := vtxo.MarkerIDs
			if markersToMarshal == nil {
				markersToMarshal = []string{}
			}
			markersData, err := json.Marshal(markersToMarshal)
			if err != nil {
				return fmt.Errorf("failed to marshal markers: %w", err)
			}
			markersJSON := string(markersData)

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
					Depth:   int64(vtxo.Depth),
					Markers: markersJSON,
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
	if len(outpoints) == 0 {
		return []domain.Vtxo{}, nil
	}

	var vtxos []domain.Vtxo
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		res, err := q.SelectVtxosByTxids(ctx, uniqueTxids(outpoints))
		if err != nil {
			return err
		}

		rows := make([]queries.VtxoVw, 0, len(res))
		for _, row := range res {
			rows = append(rows, row.VtxoVw)
		}

		vtxos, err = readRows(rows)
		return err
	}); err != nil {
		return nil, err
	}

	return keepOutpoints(vtxos, outpoints), nil
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
		return 0, fmt.Errorf("unexpected type for recoverable liquidity: %T", amount)
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

func (v *vtxoRepository) GetCheckpointTxsByVtxoPubKeys(
	ctx context.Context, pubkeys []string,
) ([]domain.Tx, error) {
	var rows []queries.SelectCheckpointTxsByVtxoPubKeysRow
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		var err error
		rows, err = q.SelectCheckpointTxsByVtxoPubKeys(ctx, pubkeys)
		return err
	}); err != nil {
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

func (v *vtxoRepository) GetVtxosWithPubKeys(
	ctx context.Context, filter domain.VtxoFilter, page domain.Page,
) ([]domain.Vtxo, int32, error) {
	if err := validateTimeRange(filter.After, filter.Before); err != nil {
		return nil, 0, err
	}

	var res []queries.SelectVtxosWithPubkeysPageRow
	var total int32
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		rows, err := selectVtxosPage(ctx, q, filter, page.Limit, page.Offset)
		if err != nil {
			return err
		}
		if len(rows) > 0 {
			res, total = rows, int32(rows[0].Total)
			return nil
		}

		// The total rides on the returned rows: a page past the end needs a
		// second read to recover it.
		first, err := selectVtxosPage(ctx, q, filter, 1, 0)
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

func selectVtxosPage(
	ctx context.Context, q *queries.Queries, filter domain.VtxoFilter, limit, offset int32,
) ([]queries.SelectVtxosWithPubkeysPageRow, error) {
	return q.SelectVtxosWithPubkeysPage(ctx, queries.SelectVtxosWithPubkeysPageParams{
		Pubkeys:         filter.Pubkeys,
		After:           filter.After,
		Before:          filter.Before,
		SpendableOnly:   filter.SpendableOnly,
		SpentOnly:       filter.SpentOnly,
		RecoverableOnly: filter.RecoverableOnly,
		RenewableOnly:   filter.RenewableOnly,
		PendingOnly:     filter.PendingOnly,
		Lim:             int64(limit),
		Off:             int64(offset),
	})
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

// sqliteSweepableVtxosBatchSize keeps each of the two slice placeholders under
// the bound parameter cap described at sqliteVtxoPubKeysBatchSize.
const sqliteSweepableVtxosBatchSize = 5000

func (v *vtxoRepository) GetSweepableVtxosByCommitmentTxids(
	ctx context.Context, commitmentTxids []string,
) ([]domain.Outpoint, error) {
	seen := make(map[domain.Outpoint]struct{})
	outpoints := make([]domain.Outpoint, 0)
	add := func(txid string, vout int64) {
		outpoint := domain.Outpoint{Txid: txid, VOut: uint32(vout)}
		if _, dup := seen[outpoint]; dup {
			return
		}
		seen[outpoint] = struct{}{}
		outpoints = append(outpoints, outpoint)
	}

	for start := 0; start < len(commitmentTxids); start += sqliteSweepableVtxosBatchSize {
		chunk := commitmentTxids[start:min(start+sqliteSweepableVtxosBatchSize, len(commitmentTxids))]
		if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
			roots, err := q.SelectSweepableVtxoOutpointsByRootCommitmentTxids(ctx, chunk)
			if err != nil {
				return err
			}
			for _, row := range roots {
				add(row.VtxoTxid, row.VtxoVout)
			}
			linked, err := q.SelectSweepableVtxoOutpointsByLinkedCommitmentTxids(ctx, chunk)
			if err != nil {
				return err
			}
			for _, row := range linked {
				add(row.VtxoTxid, row.VtxoVout)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return outpoints, nil
}

func (v *vtxoRepository) GetAllChildrenVtxos(
	ctx context.Context, outpoint domain.Outpoint,
) ([]domain.Outpoint, error) {
	var res []queries.SelectVtxosOutpointsByArkTxidRecursiveRow
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		var err error
		res, err = q.SelectVtxosOutpointsByArkTxidRecursive(
			ctx,
			queries.SelectVtxosOutpointsByArkTxidRecursiveParams{
				Txid: outpoint.Txid,
				Vout: int64(outpoint.VOut),
			},
		)
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

// sqliteVtxoPubKeysBatchSize bounds the number of commitment_txids bound to
// a single SelectVtxoPubKeysByCommitmentTxids invocation. Because the query
// expands the same slice into two IN clauses, each call binds (1 + 2N)
// parameters: one for the amount filter, plus N for each of the two slice
// placeholders. modernc.org/sqlite caps total bound parameters at
// SQLITE_MAX_VARIABLE_NUMBER = 32766; with batchSize = 5000 a single call
// binds at most 10001 params, leaving generous headroom. The wrapper below
// splits the input slice into batches of this size and merges the
// deduplicated results in Go.
const sqliteVtxoPubKeysBatchSize = 5000

// GetVtxoPubKeysByCommitmentTxids is the bulk variant of
// GetVtxoPubKeysByCommitmentTxid. It returns the deduplicated set of vtxo
// pubkeys whose root commitment_txid is in the given list, or whose
// vtxo_commitment_txid join row references one of those commitment txids.
// This replaces a per-round loop in restoreWatchingVtxos / stopWatchingVtxos
// that previously fired one query per sweepable round (the N+1 pattern).
//
// The input slice is split into batches of sqliteVtxoPubKeysBatchSize to
// stay below the sqlite parameter cap (see the const doc above). For inputs
// up to 5000 txids the loop iterates once and the behaviour is identical
// to a single underlying query call.
//
// The generated SelectVtxoPubKeysByCommitmentTxidsParams struct exposes two
// CommitmentTxids* fields, but the public API of this method takes a single
// slice and binds it to both. Both fields MUST receive the same slice; the
// query template has two distinct slice placeholders only because sqlc's
// sqlite generator expands a slice placeholder only once per generated
// query, and the bulk query needs to look in two places (the root column
// and the join table). Passing different slices to the two fields would
// silently produce wrong results, so all calls to the generated method
// must go through this wrapper.
func (v *vtxoRepository) GetVtxoPubKeysByCommitmentTxids(
	ctx context.Context, commitmentTxids []string, withMinimumAmount uint64,
) ([]string, error) {
	return v.getVtxoPubKeysByCommitmentTxidsBatched(
		ctx, commitmentTxids, withMinimumAmount, sqliteVtxoPubKeysBatchSize,
	)
}

// getVtxoPubKeysByCommitmentTxidsBatched is the testable inner of
// GetVtxoPubKeysByCommitmentTxids that splits commitmentTxids into chunks of
// batchSize, issues one query per chunk, and merges the deduplicated union
// of results in Go. Kept as a method (not a free function) so the
// underlying querier is the live one from the repository. batchSize <= 0 is
// treated as "no batching" and runs a single call. This differs from
// chunkStrings (which panics on size <= 0) because the production caller
// always passes sqliteVtxoPubKeysBatchSize > 0; the permissive fallback
// only matters when tests reach this method directly with batchSize=0.
func (v *vtxoRepository) getVtxoPubKeysByCommitmentTxidsBatched(
	ctx context.Context,
	commitmentTxids []string,
	withMinimumAmount uint64,
	batchSize int,
) ([]string, error) {
	if len(commitmentTxids) == 0 {
		return nil, nil
	}
	if batchSize <= 0 {
		batchSize = len(commitmentTxids)
	}

	seen := make(map[string]struct{})
	for start := 0; start < len(commitmentTxids); start += batchSize {
		end := start + batchSize
		if end > len(commitmentTxids) {
			end = len(commitmentTxids)
		}
		batch := commitmentTxids[start:end]
		// Same slice in both fields by construction; see public method
		// doc for the sqlc dual-placeholder explanation.
		var keys []string
		if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
			res, err := q.SelectVtxoPubKeysByCommitmentTxids(
				ctx, queries.SelectVtxoPubKeysByCommitmentTxidsParams{
					MinAmount:          int64(withMinimumAmount),
					CommitmentTxids:    batch,
					CommitmentTxidsAlt: batch,
				},
			)
			if err != nil {
				return err
			}
			keys = res
			return nil
		}); err != nil {
			return nil, err
		}
		for _, k := range keys {
			seen[k] = struct{}{}
		}
	}

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out, nil
}

func (v *vtxoRepository) GetPendingSpentVtxosWithOutpoints(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	if len(outpoints) == 0 {
		return nil, nil
	}

	var vtxos []domain.Vtxo
	if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
		res, err := q.SelectPendingSpentVtxosByTxids(ctx, uniqueTxids(outpoints))
		if err != nil {
			return err
		}

		vtxos, err = readRows(res)
		return err
	}); err != nil {
		return nil, err
	}

	return keepOutpoints(vtxos, outpoints), nil
}

func uniqueTxids(outpoints []domain.Outpoint) []string {
	seen := make(map[string]struct{}, len(outpoints))
	txids := make([]string, 0, len(outpoints))
	for _, o := range outpoints {
		if _, ok := seen[o.Txid]; !ok {
			seen[o.Txid] = struct{}{}
			txids = append(txids, o.Txid)
		}
	}
	return txids
}

// keepOutpoints drops the sibling vouts SelectVtxosByTxids over-fetches.
func keepOutpoints(vtxos []domain.Vtxo, outpoints []domain.Outpoint) []domain.Vtxo {
	wanted := make(map[domain.Outpoint]struct{}, len(outpoints))
	for _, o := range outpoints {
		wanted[o] = struct{}{}
	}
	kept := vtxos[:0]
	for _, vtxo := range vtxos {
		if _, ok := wanted[vtxo.Outpoint]; ok {
			kept = append(kept, vtxo)
		}
	}
	return kept
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
		Swept:              toBool(row.Swept),
		Preconfirmed:       row.Preconfirmed,
		ExpiresAt:          row.ExpiresAt,
		CreatedAt:          row.CreatedAt,
		Depth:              uint32(row.Depth),
		MarkerIDs:          parseMarkersJSONFromVtxo(row.Markers),
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

// toBool converts an interface{} (from a SQLite view expression that sqlc types
// as interface{}) to a Go bool. Handles int64(0/1) from SQLite.
func toBool(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	case int64:
		return val != 0
	case int:
		return val != 0
	default:
		return false
	}
}

// parseMarkersJSONFromVtxo parses a JSON array string into a slice of strings for vtxo repo.
// Logs and returns nil if the JSON is malformed so that corrupt markers are
// surfaced instead of silently treated as empty.
func parseMarkersJSONFromVtxo(markersJSON string) []string {
	if markersJSON == "" {
		return nil
	}
	var markerIDs []string
	if err := json.Unmarshal([]byte(markersJSON), &markerIDs); err != nil {
		log.WithError(err).Warnf("failed to parse markers JSON: %q", markersJSON)
		return nil
	}
	return markerIDs
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
