package sqlitedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
	log "github.com/sirupsen/logrus"
)

type markerRepository struct {
	db SQLiteDB
}

func NewMarkerRepository(config ...interface{}) (domain.MarkerRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(SQLiteDB)
	if !ok {
		return nil, fmt.Errorf("cannot open marker repository: invalid config")
	}

	return &markerRepository{
		db: db,
	}, nil
}

func (m *markerRepository) Close() {
	_ = m.db.Close()
}

func (m *markerRepository) AddMarker(ctx context.Context, marker domain.Marker) error {
	parentMarkersJSON, err := json.Marshal(marker.ParentMarkerIDs)
	if err != nil {
		return fmt.Errorf("failed to marshal parent markers: %w", err)
	}

	return withWriteQuerier(ctx, m.db, func(q *queries.Queries) error {
		return q.UpsertMarker(ctx, queries.UpsertMarkerParams{
			ID:            marker.ID,
			Depth:         int64(marker.Depth),
			ParentMarkers: sql.NullString{String: string(parentMarkersJSON), Valid: true},
		})
	})
}

func (m *markerRepository) GetMarker(ctx context.Context, id string) (*domain.Marker, error) {
	var row queries.Marker
	if err := withReadQuerier(ctx, m.db, func(q *queries.Queries) error {
		var err error
		row, err = q.SelectMarker(ctx, id)
		return err
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	marker, err := rowToMarker(row)
	if err != nil {
		return nil, err
	}
	return &marker, nil
}

func (m *markerRepository) GetMarkersByDepthRange(
	ctx context.Context,
	minDepth, maxDepth uint32,
) ([]domain.Marker, error) {
	var rows []queries.Marker
	if err := withReadQuerier(ctx, m.db, func(q *queries.Queries) error {
		var err error
		rows, err = q.SelectMarkersByDepthRange(ctx, queries.SelectMarkersByDepthRangeParams{
			MinDepth: int64(minDepth),
			MaxDepth: int64(maxDepth),
		})
		return err
	}); err != nil {
		return nil, err
	}

	markers := make([]domain.Marker, 0, len(rows))
	for _, row := range rows {
		marker, err := rowToMarker(row)
		if err != nil {
			return nil, err
		}
		markers = append(markers, marker)
	}
	return markers, nil
}

func (m *markerRepository) GetMarkersByIds(
	ctx context.Context,
	ids []string,
) ([]domain.Marker, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	var rows []queries.Marker
	if err := withReadQuerier(ctx, m.db, func(q *queries.Queries) error {
		var err error
		rows, err = q.SelectMarkersByIds(ctx, ids)
		return err
	}); err != nil {
		return nil, err
	}

	markers := make([]domain.Marker, 0, len(rows))
	for _, row := range rows {
		marker, err := rowToMarker(row)
		if err != nil {
			return nil, err
		}
		markers = append(markers, marker)
	}
	return markers, nil
}

func (m *markerRepository) BulkSweepMarkers(
	ctx context.Context,
	markerIDs []string,
	sweptAt int64,
) error {
	if len(markerIDs) == 0 {
		return nil
	}
	txBody := func(querierWithTx *queries.Queries) error {
		for _, markerID := range markerIDs {
			if err := querierWithTx.InsertSweptMarker(ctx, queries.InsertSweptMarkerParams{
				MarkerID: markerID,
				SweptAt:  sweptAt,
			}); err != nil {
				return err
			}
		}
		return nil
	}
	return execTx(ctx, m.db.Write(), txBody)
}

func (m *markerRepository) SweepVtxoOutpoints(
	ctx context.Context,
	outpoints []domain.Outpoint,
	sweptAt int64,
) error {
	if len(outpoints) == 0 {
		return nil
	}
	txBody := func(qtx *queries.Queries) error {
		for _, op := range outpoints {
			if err := qtx.InsertSweptVtxo(ctx, queries.InsertSweptVtxoParams{
				Txid:    op.Txid,
				Vout:    int64(op.VOut),
				SweptAt: sweptAt,
			}); err != nil {
				return err
			}
		}
		return nil
	}
	return execTx(ctx, m.db.Write(), txBody)
}

func (m *markerRepository) IsMarkerSwept(ctx context.Context, markerID string) (bool, error) {
	var result int64
	if err := withReadQuerier(ctx, m.db, func(q *queries.Queries) error {
		var err error
		result, err = q.IsMarkerSwept(ctx, markerID)
		return err
	}); err != nil {
		return false, err
	}
	return result == 1, nil
}

func (m *markerRepository) GetSweptMarkers(
	ctx context.Context,
	markerIDs []string,
) ([]domain.SweptMarker, error) {
	if len(markerIDs) == 0 {
		return nil, nil
	}

	var rows []queries.SweptMarker
	if err := withReadQuerier(ctx, m.db, func(q *queries.Queries) error {
		var err error
		rows, err = q.SelectSweptMarkersByIds(ctx, markerIDs)
		return err
	}); err != nil {
		return nil, err
	}

	sweptMarkers := make([]domain.SweptMarker, 0, len(rows))
	for _, row := range rows {
		sweptMarkers = append(sweptMarkers, domain.SweptMarker{
			MarkerID: row.MarkerID,
			SweptAt:  row.SweptAt,
		})
	}
	return sweptMarkers, nil
}

func (m *markerRepository) UpdateVtxoMarkers(
	ctx context.Context,
	outpoint domain.Outpoint,
	markerIDs []string,
) error {
	markersJSON, err := json.Marshal(markerIDs)
	if err != nil {
		return fmt.Errorf("failed to marshal markers: %w", err)
	}
	return withWriteQuerier(ctx, m.db, func(q *queries.Queries) error {
		return q.UpdateVtxoMarkers(ctx, queries.UpdateVtxoMarkersParams{
			Markers: string(markersJSON),
			Txid:    outpoint.Txid,
			Vout:    int64(outpoint.VOut),
		})
	})
}

func (m *markerRepository) GetVtxosByMarker(
	ctx context.Context,
	markerID string,
) ([]domain.Vtxo, error) {
	var rows []queries.SelectVtxosByMarkerIdRow
	if err := withReadQuerier(ctx, m.db, func(q *queries.Queries) error {
		var err error
		rows, err = q.SelectVtxosByMarkerId(
			ctx,
			sql.NullString{String: markerID, Valid: len(markerID) > 0},
		)
		return err
	}); err != nil {
		return nil, err
	}

	vtxos := make([]domain.Vtxo, 0, len(rows))
	for _, row := range rows {
		vtxos = append(vtxos, rowToVtxoFromMarkerQuery(row))
	}
	return vtxos, nil
}

func (m *markerRepository) CreateRootMarkersForVtxos(
	ctx context.Context,
	vtxos []domain.Vtxo,
) error {
	if len(vtxos) == 0 {
		return nil
	}

	txBody := func(querierWithTx *queries.Queries) error {
		for _, vtxo := range vtxos {
			markerID := vtxo.Outpoint.String()

			// Create the root marker (depth 0, no parents)
			// Note: vtxo.MarkerIDs should already be set before AddVtxos is called
			if err := querierWithTx.UpsertMarker(ctx, queries.UpsertMarkerParams{
				ID:            markerID,
				Depth:         0,
				ParentMarkers: sql.NullString{String: "[]", Valid: true},
			}); err != nil {
				return fmt.Errorf("failed to create marker for vtxo %s: %w", markerID, err)
			}
		}
		return nil
	}

	return execTx(ctx, m.db.Write(), txBody)
}

func (m *markerRepository) GetVtxosByDepthRange(
	ctx context.Context,
	minDepth, maxDepth uint32,
) ([]domain.Vtxo, error) {
	var rows []queries.SelectVtxosByDepthRangeRow
	if err := withReadQuerier(ctx, m.db, func(q *queries.Queries) error {
		var err error
		rows, err = q.SelectVtxosByDepthRange(ctx, queries.SelectVtxosByDepthRangeParams{
			MinDepth: int64(minDepth),
			MaxDepth: int64(maxDepth),
		})
		return err
	}); err != nil {
		return nil, err
	}

	vtxos := make([]domain.Vtxo, 0, len(rows))
	for _, row := range rows {
		vtxos = append(vtxos, rowToVtxoFromDepthRangeQuery(row))
	}
	return vtxos, nil
}

func (m *markerRepository) GetVtxosByArkTxid(
	ctx context.Context,
	arkTxid string,
) ([]domain.Vtxo, error) {
	var rows []queries.SelectVtxosByArkTxidRow
	if err := withReadQuerier(ctx, m.db, func(q *queries.Queries) error {
		var err error
		rows, err = q.SelectVtxosByArkTxid(
			ctx,
			sql.NullString{String: arkTxid, Valid: arkTxid != ""},
		)
		return err
	}); err != nil {
		return nil, err
	}

	vtxos := make([]domain.Vtxo, 0, len(rows))
	for _, row := range rows {
		vtxos = append(vtxos, rowToVtxoFromArkTxidQuery(row))
	}
	return vtxos, nil
}

func (m *markerRepository) GetVtxoChainByMarkers(
	ctx context.Context,
	markerIDs []string,
) ([]domain.Vtxo, error) {
	if len(markerIDs) == 0 {
		return nil, nil
	}

	// Since SQLite query handles one marker at a time, we need to query for each marker
	// and deduplicate results
	seen := make(map[string]bool)
	vtxos := make([]domain.Vtxo, 0)

	for _, markerID := range markerIDs {
		var rows []queries.SelectVtxoChainByMarkerRow
		if err := withReadQuerier(ctx, m.db, func(q *queries.Queries) error {
			var err error
			rows, err = q.SelectVtxoChainByMarker(
				ctx,
				sql.NullString{String: markerID, Valid: len(markerID) > 0},
			)
			return err
		}); err != nil {
			return nil, err
		}

		for _, row := range rows {
			key := row.VtxoVw.Txid + ":" + fmt.Sprintf("%d", row.VtxoVw.Vout)
			if !seen[key] {
				seen[key] = true
				vtxos = append(vtxos, rowToVtxoFromChainQuery(row))
			}
		}
	}
	return vtxos, nil
}

func rowToMarker(row queries.Marker) (domain.Marker, error) {
	var parentMarkerIDs []string
	if row.ParentMarkers.Valid && row.ParentMarkers.String != "" {
		if err := json.Unmarshal([]byte(row.ParentMarkers.String), &parentMarkerIDs); err != nil {
			return domain.Marker{}, fmt.Errorf("failed to unmarshal parent markers: %w", err)
		}
	}

	return domain.Marker{
		ID:              row.ID,
		Depth:           uint32(row.Depth),
		ParentMarkerIDs: parentMarkerIDs,
	}, nil
}

func rowToVtxoFromMarkerQuery(row queries.SelectVtxosByMarkerIdRow) domain.Vtxo {
	var commitmentTxids []string
	if commitments, ok := row.VtxoVw.Commitments.(string); ok && commitments != "" {
		commitmentTxids = strings.Split(commitments, ",")
	}
	return domain.Vtxo{
		Outpoint: domain.Outpoint{
			Txid: row.VtxoVw.Txid,
			VOut: uint32(row.VtxoVw.Vout),
		},
		Amount:             uint64(row.VtxoVw.Amount),
		PubKey:             row.VtxoVw.Pubkey,
		RootCommitmentTxid: row.VtxoVw.CommitmentTxid,
		CommitmentTxids:    commitmentTxids,
		SettledBy:          row.VtxoVw.SettledBy.String,
		ArkTxid:            row.VtxoVw.ArkTxid.String,
		SpentBy:            row.VtxoVw.SpentBy.String,
		Spent:              row.VtxoVw.Spent,
		Unrolled:           row.VtxoVw.Unrolled,
		Swept:              toBool(row.VtxoVw.Swept),
		Preconfirmed:       row.VtxoVw.Preconfirmed,
		ExpiresAt:          row.VtxoVw.ExpiresAt,
		CreatedAt:          row.VtxoVw.CreatedAt,
		Depth:              uint32(row.VtxoVw.Depth),
		MarkerIDs:          parseMarkersJSON(row.VtxoVw.Markers),
	}
}

func rowToVtxoFromDepthRangeQuery(row queries.SelectVtxosByDepthRangeRow) domain.Vtxo {
	var commitmentTxids []string
	if commitments, ok := row.VtxoVw.Commitments.(string); ok && commitments != "" {
		commitmentTxids = strings.Split(commitments, ",")
	}
	return domain.Vtxo{
		Outpoint: domain.Outpoint{
			Txid: row.VtxoVw.Txid,
			VOut: uint32(row.VtxoVw.Vout),
		},
		Amount:             uint64(row.VtxoVw.Amount),
		PubKey:             row.VtxoVw.Pubkey,
		RootCommitmentTxid: row.VtxoVw.CommitmentTxid,
		CommitmentTxids:    commitmentTxids,
		SettledBy:          row.VtxoVw.SettledBy.String,
		ArkTxid:            row.VtxoVw.ArkTxid.String,
		SpentBy:            row.VtxoVw.SpentBy.String,
		Spent:              row.VtxoVw.Spent,
		Unrolled:           row.VtxoVw.Unrolled,
		Swept:              toBool(row.VtxoVw.Swept),
		Preconfirmed:       row.VtxoVw.Preconfirmed,
		ExpiresAt:          row.VtxoVw.ExpiresAt,
		CreatedAt:          row.VtxoVw.CreatedAt,
		Depth:              uint32(row.VtxoVw.Depth),
		MarkerIDs:          parseMarkersJSON(row.VtxoVw.Markers),
	}
}

func rowToVtxoFromArkTxidQuery(row queries.SelectVtxosByArkTxidRow) domain.Vtxo {
	var commitmentTxids []string
	if commitments, ok := row.VtxoVw.Commitments.(string); ok && commitments != "" {
		commitmentTxids = strings.Split(commitments, ",")
	}
	return domain.Vtxo{
		Outpoint: domain.Outpoint{
			Txid: row.VtxoVw.Txid,
			VOut: uint32(row.VtxoVw.Vout),
		},
		Amount:             uint64(row.VtxoVw.Amount),
		PubKey:             row.VtxoVw.Pubkey,
		RootCommitmentTxid: row.VtxoVw.CommitmentTxid,
		CommitmentTxids:    commitmentTxids,
		SettledBy:          row.VtxoVw.SettledBy.String,
		ArkTxid:            row.VtxoVw.ArkTxid.String,
		SpentBy:            row.VtxoVw.SpentBy.String,
		Spent:              row.VtxoVw.Spent,
		Unrolled:           row.VtxoVw.Unrolled,
		Swept:              toBool(row.VtxoVw.Swept),
		Preconfirmed:       row.VtxoVw.Preconfirmed,
		ExpiresAt:          row.VtxoVw.ExpiresAt,
		CreatedAt:          row.VtxoVw.CreatedAt,
		Depth:              uint32(row.VtxoVw.Depth),
		MarkerIDs:          parseMarkersJSON(row.VtxoVw.Markers),
	}
}

func rowToVtxoFromChainQuery(row queries.SelectVtxoChainByMarkerRow) domain.Vtxo {
	var commitmentTxids []string
	if commitments, ok := row.VtxoVw.Commitments.(string); ok && commitments != "" {
		commitmentTxids = strings.Split(commitments, ",")
	}
	return domain.Vtxo{
		Outpoint: domain.Outpoint{
			Txid: row.VtxoVw.Txid,
			VOut: uint32(row.VtxoVw.Vout),
		},
		Amount:             uint64(row.VtxoVw.Amount),
		PubKey:             row.VtxoVw.Pubkey,
		RootCommitmentTxid: row.VtxoVw.CommitmentTxid,
		CommitmentTxids:    commitmentTxids,
		SettledBy:          row.VtxoVw.SettledBy.String,
		ArkTxid:            row.VtxoVw.ArkTxid.String,
		SpentBy:            row.VtxoVw.SpentBy.String,
		Spent:              row.VtxoVw.Spent,
		Unrolled:           row.VtxoVw.Unrolled,
		Swept:              toBool(row.VtxoVw.Swept),
		Preconfirmed:       row.VtxoVw.Preconfirmed,
		ExpiresAt:          row.VtxoVw.ExpiresAt,
		CreatedAt:          row.VtxoVw.CreatedAt,
		Depth:              uint32(row.VtxoVw.Depth),
		MarkerIDs:          parseMarkersJSON(row.VtxoVw.Markers),
	}
}

// parseMarkersJSON parses a JSON array string into a slice of strings.
// Logs and returns nil if the JSON is malformed so that corrupt markers are
// surfaced instead of silently treated as empty.
func parseMarkersJSON(markersJSON string) []string {
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
