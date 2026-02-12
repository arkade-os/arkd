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

func (m *markerRepository) SweepMarkerWithDescendants(
	ctx context.Context,
	markerID string,
	sweptAt int64,
) (int64, error) {
	// Get all descendant marker IDs (including the root marker) that are not already swept
	descendantIDs, err := m.querier.GetDescendantMarkerIds(ctx, markerID)
	if err != nil {
		return 0, fmt.Errorf("failed to get descendant markers: %w", err)
	}

	// Insert each descendant into swept_marker
	var count int64
	for _, id := range descendantIDs {
		err := m.querier.InsertSweptMarker(ctx, queries.InsertSweptMarkerParams{
			MarkerID: id,
			SweptAt:  sweptAt,
		})
		if err != nil {
			return count, fmt.Errorf("failed to sweep marker %s: %w", id, err)
		}
		count++
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
		Markers: sql.NullString{String: string(markersJSON), Valid: len(markerIDs) > 0},
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
	// First check if the marker exists (foreign key constraint on swept_marker)
	marker, err := m.GetMarker(ctx, markerID)
	if err != nil {
		return 0, fmt.Errorf("failed to check marker existence: %w", err)
	}
	if marker == nil {
		return 0, nil // Marker doesn't exist, nothing to sweep
	}

	// Count unswept VTXOs with this marker before inserting to swept_marker
	count, err := m.querier.CountUnsweptVtxosByMarkerId(
		ctx,
		sql.NullString{String: markerID, Valid: len(markerID) > 0},
	)
	if err != nil {
		return 0, fmt.Errorf("failed to count unswept vtxos: %w", err)
	}

	// Insert the marker into swept_marker (sweep state is computed via view)
	if err := m.querier.InsertSweptMarker(ctx, queries.InsertSweptMarkerParams{
		MarkerID: markerID,
		SweptAt:  time.Now().Unix(),
	}); err != nil {
		return 0, fmt.Errorf("failed to insert swept marker: %w", err)
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
			if err := querierWithTx.UpsertMarker(ctx, queries.UpsertMarkerParams{
				ID:            markerID,
				Depth:         0,
				ParentMarkers: sql.NullString{String: "[]", Valid: true},
			}); err != nil {
				return fmt.Errorf("failed to create marker for vtxo %s: %w", markerID, err)
			}

			// Update the vtxo's markers
			markersJSON, err := json.Marshal([]string{markerID})
			if err != nil {
				return fmt.Errorf("failed to marshal markers: %w", err)
			}
			if err := querierWithTx.UpdateVtxoMarkers(ctx, queries.UpdateVtxoMarkersParams{
				Markers: sql.NullString{String: string(markersJSON), Valid: true},
				Txid:    vtxo.Txid,
				Vout:    int64(vtxo.VOut),
			}); err != nil {
				return fmt.Errorf("failed to update markers for vtxo %s: %w", markerID, err)
			}
		}
		return nil
	}

	return execTx(ctx, m.db, txBody)
}

func (m *markerRepository) MarkDustVtxoSwept(
	ctx context.Context,
	outpoint domain.Outpoint,
	sweptAt int64,
) error {
	// Create a unique dust marker for this vtxo
	dustMarkerID := outpoint.String() + ":dust"

	// First, get the vtxo to find its depth and current markers
	vtxoRow, err := m.querier.SelectVtxo(ctx, queries.SelectVtxoParams{
		Txid: outpoint.Txid,
		Vout: int64(outpoint.VOut),
	})
	if err != nil {
		return fmt.Errorf("failed to get vtxo: %w", err)
	}

	// Get current markers from the vtxo
	var parentMarkers []string
	if vtxoRow.VtxoVw.Markers.Valid && vtxoRow.VtxoVw.Markers.String != "" {
		if err := json.Unmarshal([]byte(vtxoRow.VtxoVw.Markers.String), &parentMarkers); err != nil {
			parentMarkers = nil
		}
	}

	parentMarkersJSON, err := json.Marshal(parentMarkers)
	if err != nil {
		return fmt.Errorf("failed to marshal parent markers: %w", err)
	}

	// Create the dust marker
	if err := m.querier.UpsertMarker(ctx, queries.UpsertMarkerParams{
		ID:            dustMarkerID,
		Depth:         vtxoRow.VtxoVw.Depth,
		ParentMarkers: sql.NullString{String: string(parentMarkersJSON), Valid: true},
	}); err != nil {
		return fmt.Errorf("failed to create dust marker: %w", err)
	}

	// Insert into swept_marker
	if err := m.querier.InsertSweptMarker(ctx, queries.InsertSweptMarkerParams{
		MarkerID: dustMarkerID,
		SweptAt:  sweptAt,
	}); err != nil {
		return fmt.Errorf("failed to insert swept marker: %w", err)
	}

	// Update the vtxo's markers to include the dust marker
	newMarkers := append(parentMarkers, dustMarkerID)
	newMarkersJSON, err := json.Marshal(newMarkers)
	if err != nil {
		return fmt.Errorf("failed to marshal new markers: %w", err)
	}

	if err := m.querier.UpdateVtxoMarkers(ctx, queries.UpdateVtxoMarkersParams{
		Markers: sql.NullString{String: string(newMarkersJSON), Valid: true},
		Txid:    outpoint.Txid,
		Vout:    int64(outpoint.VOut),
	}); err != nil {
		return fmt.Errorf("failed to update vtxo markers: %w", err)
	}

	return nil
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
	rows, err := m.querier.SelectVtxosByArkTxid(ctx, arkTxid)
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
			sql.NullString{String: markerID, Valid: true},
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
		Swept:              row.VtxoVw.Swept != 0,
		Preconfirmed:       row.VtxoVw.Preconfirmed,
		ExpiresAt:          row.VtxoVw.ExpiresAt,
		CreatedAt:          row.VtxoVw.CreatedAt,
		Depth:              uint32(row.VtxoVw.Depth),
		MarkerIDs:          parseMarkersJSON(row.VtxoVw.Markers.String),
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
		Swept:              row.VtxoVw.Swept != 0,
		Preconfirmed:       row.VtxoVw.Preconfirmed,
		ExpiresAt:          row.VtxoVw.ExpiresAt,
		CreatedAt:          row.VtxoVw.CreatedAt,
		Depth:              uint32(row.VtxoVw.Depth),
		MarkerIDs:          parseMarkersJSON(row.VtxoVw.Markers.String),
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
		Swept:              row.VtxoVw.Swept != 0,
		Preconfirmed:       row.VtxoVw.Preconfirmed,
		ExpiresAt:          row.VtxoVw.ExpiresAt,
		CreatedAt:          row.VtxoVw.CreatedAt,
		Depth:              uint32(row.VtxoVw.Depth),
		MarkerIDs:          parseMarkersJSON(row.VtxoVw.Markers.String),
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
		Swept:              row.VtxoVw.Swept != 0,
		Preconfirmed:       row.VtxoVw.Preconfirmed,
		ExpiresAt:          row.VtxoVw.ExpiresAt,
		CreatedAt:          row.VtxoVw.CreatedAt,
		Depth:              uint32(row.VtxoVw.Depth),
		MarkerIDs:          parseMarkersJSON(row.VtxoVw.Markers.String),
	}
}

// parseMarkersJSON parses a JSON array string into a slice of strings
func parseMarkersJSON(markersJSON string) []string {
	if markersJSON == "" {
		return nil
	}
	var markerIDs []string
	if err := json.Unmarshal([]byte(markersJSON), &markerIDs); err != nil {
		return nil
	}
	return markerIDs
}
