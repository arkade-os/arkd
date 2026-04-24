package sqlitedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
	log "github.com/sirupsen/logrus"
)

type markerRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewMarkerRepository(config ...interface{}) (domain.MarkerRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open marker repository: invalid config")
	}

	return &markerRepository{
		db:      db,
		querier: queries.New(db),
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

	return m.querier.UpsertMarker(ctx, queries.UpsertMarkerParams{
		ID:            marker.ID,
		Depth:         int64(marker.Depth),
		ParentMarkers: sql.NullString{String: string(parentMarkersJSON), Valid: true},
	})
}

func (m *markerRepository) GetMarker(ctx context.Context, id string) (*domain.Marker, error) {
	row, err := m.querier.SelectMarker(ctx, id)
	if err != nil {
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

func (m *markerRepository) GetMarkersByDepth(
	ctx context.Context,
	depth uint32,
) ([]domain.Marker, error) {
	rows, err := m.querier.SelectMarkersByDepth(ctx, int64(depth))
	if err != nil {
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

func (m *markerRepository) GetMarkersByDepthRange(
	ctx context.Context,
	minDepth, maxDepth uint32,
) ([]domain.Marker, error) {
	rows, err := m.querier.SelectMarkersByDepthRange(ctx, queries.SelectMarkersByDepthRangeParams{
		MinDepth: int64(minDepth),
		MaxDepth: int64(maxDepth),
	})
	if err != nil {
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

	rows, err := m.querier.SelectMarkersByIds(ctx, ids)
	if err != nil {
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

func (m *markerRepository) SweepMarker(ctx context.Context, markerID string, sweptAt int64) error {
	return m.querier.InsertSweptMarker(ctx, queries.InsertSweptMarkerParams{
		MarkerID: markerID,
		SweptAt:  sweptAt,
	})
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
	return execTx(ctx, m.db, txBody)
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
	return execTx(ctx, m.db, txBody)
}

func (m *markerRepository) SweepMarkerWithDescendants(
	ctx context.Context,
	markerID string,
	sweptAt int64,
) (int64, error) {
	var count int64
	txBody := func(qtx *queries.Queries) error {
		// Get all descendant marker IDs (including the root marker) that are not already swept
		descendantIDs, err := qtx.GetDescendantMarkerIds(ctx, markerID)
		if err != nil {
			return fmt.Errorf("failed to get descendant markers: %w", err)
		}

		// Insert each descendant into swept_marker
		for _, id := range descendantIDs {
			if err := qtx.InsertSweptMarker(ctx, queries.InsertSweptMarkerParams{
				MarkerID: id,
				SweptAt:  sweptAt,
			}); err != nil {
				return fmt.Errorf("failed to sweep marker %s: %w", id, err)
			}
			count++
		}
		return nil
	}
	if err := execTx(ctx, m.db, txBody); err != nil {
		return 0, err
	}
	return count, nil
}

func (m *markerRepository) IsMarkerSwept(ctx context.Context, markerID string) (bool, error) {
	result, err := m.querier.IsMarkerSwept(ctx, markerID)
	if err != nil {
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

	rows, err := m.querier.SelectSweptMarkersByIds(ctx, markerIDs)
	if err != nil {
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
	return m.querier.UpdateVtxoMarkers(ctx, queries.UpdateVtxoMarkersParams{
		Markers: string(markersJSON),
		Txid:    outpoint.Txid,
		Vout:    int64(outpoint.VOut),
	})
}

func (m *markerRepository) GetVtxosByMarker(
	ctx context.Context,
	markerID string,
) ([]domain.Vtxo, error) {
	rows, err := m.querier.SelectVtxosByMarkerId(
		ctx,
		sql.NullString{String: markerID, Valid: len(markerID) > 0},
	)
	if err != nil {
		return nil, err
	}

	vtxos := make([]domain.Vtxo, 0, len(rows))
	for _, row := range rows {
		vtxos = append(vtxos, rowToVtxoFromMarkerQuery(row))
	}
	return vtxos, nil
}

func (m *markerRepository) SweepVtxosByMarker(ctx context.Context, markerID string) (int64, error) {
	var count int64
	txBody := func(qtx *queries.Queries) error {
		// First check if the marker exists (foreign key constraint on swept_marker)
		if _, err := qtx.SelectMarker(ctx, markerID); err != nil {
			if err == sql.ErrNoRows {
				return nil // Marker doesn't exist, nothing to sweep
			}
			return fmt.Errorf("failed to check marker existence: %w", err)
		}

		// Count unswept VTXOs with this marker before inserting to swept_marker
		c, err := qtx.CountUnsweptVtxosByMarkerId(
			ctx,
			sql.NullString{String: markerID, Valid: len(markerID) > 0},
		)
		if err != nil {
			return fmt.Errorf("failed to count unswept vtxos: %w", err)
		}

		// Insert the marker into swept_marker (sweep state is computed via view)
		if err := qtx.InsertSweptMarker(ctx, queries.InsertSweptMarkerParams{
			MarkerID: markerID,
			SweptAt:  time.Now().UnixMilli(),
		}); err != nil {
			return fmt.Errorf("failed to insert swept marker: %w", err)
		}
		count = c
		return nil
	}
	if err := execTx(ctx, m.db, txBody); err != nil {
		return 0, err
	}
	return count, nil
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

	return execTx(ctx, m.db, txBody)
}

func (m *markerRepository) GetVtxosByDepthRange(
	ctx context.Context,
	minDepth, maxDepth uint32,
) ([]domain.Vtxo, error) {
	rows, err := m.querier.SelectVtxosByDepthRange(ctx, queries.SelectVtxosByDepthRangeParams{
		MinDepth: int64(minDepth),
		MaxDepth: int64(maxDepth),
	})
	if err != nil {
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
	rows, err := m.querier.SelectVtxosByArkTxid(
		ctx,
		sql.NullString{String: arkTxid, Valid: arkTxid != ""},
	)
	if err != nil {
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
		rows, err := m.querier.SelectVtxoChainByMarker(
			ctx,
			sql.NullString{String: markerID, Valid: len(markerID) > 0},
		)
		if err != nil {
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
