package sqlitedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

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

func (m *markerRepository) GetMarkersByDepth(ctx context.Context, depth uint32) ([]domain.Marker, error) {
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

func (m *markerRepository) GetMarkersByDepthRange(ctx context.Context, minDepth, maxDepth uint32) ([]domain.Marker, error) {
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

func (m *markerRepository) GetMarkersByIds(ctx context.Context, ids []string) ([]domain.Marker, error) {
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

func (m *markerRepository) IsMarkerSwept(ctx context.Context, markerID string) (bool, error) {
	result, err := m.querier.IsMarkerSwept(ctx, markerID)
	if err != nil {
		return false, err
	}
	return result == 1, nil
}

func (m *markerRepository) GetSweptMarkers(ctx context.Context, markerIDs []string) ([]domain.SweptMarker, error) {
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

func (m *markerRepository) UpdateVtxoMarker(ctx context.Context, outpoint domain.Outpoint, markerID string) error {
	return m.querier.UpdateVtxoMarkerId(ctx, queries.UpdateVtxoMarkerIdParams{
		MarkerID: sql.NullString{String: markerID, Valid: len(markerID) > 0},
		Txid:     outpoint.Txid,
		Vout:     int64(outpoint.VOut),
	})
}

func (m *markerRepository) GetVtxosByMarker(ctx context.Context, markerID string) ([]domain.Vtxo, error) {
	rows, err := m.querier.SelectVtxosByMarkerId(ctx, sql.NullString{String: markerID, Valid: len(markerID) > 0})
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
	return m.querier.SweepVtxosByMarkerId(ctx, sql.NullString{String: markerID, Valid: len(markerID) > 0})
}

func (m *markerRepository) GetVtxosByDepthRange(ctx context.Context, minDepth, maxDepth uint32) ([]domain.Vtxo, error) {
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

func (m *markerRepository) GetVtxosByArkTxid(ctx context.Context, arkTxid string) ([]domain.Vtxo, error) {
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

func (m *markerRepository) GetVtxoChainByMarkers(ctx context.Context, markerIDs []string) ([]domain.Vtxo, error) {
	if len(markerIDs) == 0 {
		return nil, nil
	}

	// Convert string slice to sql.NullString slice
	nullStringIDs := make([]sql.NullString, len(markerIDs))
	for i, id := range markerIDs {
		nullStringIDs[i] = sql.NullString{String: id, Valid: true}
	}

	rows, err := m.querier.SelectVtxoChainByMarker(ctx, nullStringIDs)
	if err != nil {
		return nil, err
	}

	vtxos := make([]domain.Vtxo, 0, len(rows))
	for _, row := range rows {
		vtxos = append(vtxos, rowToVtxoFromChainQuery(row))
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
		Swept:              row.VtxoVw.Swept,
		Preconfirmed:       row.VtxoVw.Preconfirmed,
		ExpiresAt:          row.VtxoVw.ExpiresAt,
		CreatedAt:          row.VtxoVw.CreatedAt,
		Depth:              uint32(row.VtxoVw.Depth),
		MarkerID:           row.VtxoVw.MarkerID.String,
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
		Swept:              row.VtxoVw.Swept,
		Preconfirmed:       row.VtxoVw.Preconfirmed,
		ExpiresAt:          row.VtxoVw.ExpiresAt,
		CreatedAt:          row.VtxoVw.CreatedAt,
		Depth:              uint32(row.VtxoVw.Depth),
		MarkerID:           row.VtxoVw.MarkerID.String,
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
		Swept:              row.VtxoVw.Swept,
		Preconfirmed:       row.VtxoVw.Preconfirmed,
		ExpiresAt:          row.VtxoVw.ExpiresAt,
		CreatedAt:          row.VtxoVw.CreatedAt,
		Depth:              uint32(row.VtxoVw.Depth),
		MarkerID:           row.VtxoVw.MarkerID.String,
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
		Swept:              row.VtxoVw.Swept,
		Preconfirmed:       row.VtxoVw.Preconfirmed,
		ExpiresAt:          row.VtxoVw.ExpiresAt,
		CreatedAt:          row.VtxoVw.CreatedAt,
		Depth:              uint32(row.VtxoVw.Depth),
		MarkerID:           row.VtxoVw.MarkerID.String,
	}
}
