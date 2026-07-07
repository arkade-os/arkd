package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const (
	markerStoreDir      = "markers"
	sweptMarkerStoreDir = "swept_markers"
)

type markerRepository struct {
	markerStore      *badgerhold.Store
	sweptMarkerStore *badgerhold.Store
	vtxoStore        *badgerhold.Store
	ownsVtxoStore    bool // whether this repo owns the vtxo store (for Close())
}

// MarkerStoreAccessor exposes the underlying markers badgerhold store to the
// startup marker backfill (badger has no SQL migration path). The marker repo
// is returned as domain.MarkerRepository, so the call site asserts to this.
type MarkerStoreAccessor interface {
	GetMarkerStore() *badgerhold.Store
}

// GetMarkerStore returns the underlying markers badgerhold store.
func (r *markerRepository) GetMarkerStore() *badgerhold.Store {
	return r.markerStore
}

type markerDTO struct {
	ID              string
	Depth           uint32
	ParentMarkerIDs []string
}

type sweptMarkerDTO struct {
	MarkerID string
	SweptAt  int64
}

// NewMarkerRepository creates a new marker repository.
// Config can be:
// - [baseDir string, logger badger.Logger] - creates its own vtxo store
// - [baseDir string, logger badger.Logger, vtxoStore *badgerhold.Store] - uses shared vtxo store
func NewMarkerRepository(config ...interface{}) (domain.MarkerRepository, error) {
	if len(config) < 2 {
		return nil, fmt.Errorf("invalid config: need at least baseDir and logger")
	}
	baseDir, ok := config[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid base directory")
	}
	var logger badger.Logger
	if config[1] != nil {
		logger, ok = config[1].(badger.Logger)
		if !ok {
			return nil, fmt.Errorf("invalid logger")
		}
	}

	var markerDir, sweptMarkerDir string
	if len(baseDir) > 0 {
		markerDir = filepath.Join(baseDir, markerStoreDir)
		sweptMarkerDir = filepath.Join(baseDir, sweptMarkerStoreDir)
	}

	markerStore, err := createDB(markerDir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open marker store: %s", err)
	}

	sweptMarkerStore, err := createDB(sweptMarkerDir, logger)
	if err != nil {
		_ = markerStore.Close()
		return nil, fmt.Errorf("failed to open swept marker store: %s", err)
	}

	// Check if a shared vtxo store was provided
	var vtxoStore *badgerhold.Store
	ownsVtxoStore := false
	if len(config) >= 3 && config[2] != nil {
		vtxoStore, ok = config[2].(*badgerhold.Store)
		if !ok {
			_ = markerStore.Close()
			_ = sweptMarkerStore.Close()
			return nil, fmt.Errorf("invalid vtxo store")
		}
	} else {
		// Create our own vtxo store
		var vtxoDir string
		if len(baseDir) > 0 {
			vtxoDir = filepath.Join(baseDir, vtxoStoreDir)
		}
		vtxoStore, err = createDB(vtxoDir, logger)
		if err != nil {
			_ = markerStore.Close()
			_ = sweptMarkerStore.Close()
			return nil, fmt.Errorf("failed to open vtxo store for marker repo: %s", err)
		}
		ownsVtxoStore = true
	}

	return &markerRepository{
		markerStore:      markerStore,
		sweptMarkerStore: sweptMarkerStore,
		vtxoStore:        vtxoStore,
		ownsVtxoStore:    ownsVtxoStore,
	}, nil
}

func (r *markerRepository) Close() {
	_ = r.markerStore.Close()
	_ = r.sweptMarkerStore.Close()
	if r.ownsVtxoStore {
		_ = r.vtxoStore.Close()
	}
}

func (r *markerRepository) AddMarker(ctx context.Context, marker domain.Marker) error {
	dto := markerDTO{
		ID:              marker.ID,
		Depth:           marker.Depth,
		ParentMarkerIDs: marker.ParentMarkerIDs,
	}

	err := r.markerStore.Upsert(marker.ID, dto)
	if err != nil {
		if errors.Is(err, badger.ErrConflict) {
			for attempts := 1; attempts <= maxRetries; attempts++ {
				time.Sleep(100 * time.Millisecond)
				err = r.markerStore.Upsert(marker.ID, dto)
				if err == nil {
					break
				}
			}
		}
	}
	return err
}

func (r *markerRepository) GetMarker(ctx context.Context, id string) (*domain.Marker, error) {
	var dto markerDTO
	err := r.markerStore.Get(id, &dto)
	if err != nil {
		if err == badgerhold.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	return &domain.Marker{
		ID:              dto.ID,
		Depth:           dto.Depth,
		ParentMarkerIDs: dto.ParentMarkerIDs,
	}, nil
}

func (r *markerRepository) GetMarkersByDepthRange(
	ctx context.Context,
	minDepth, maxDepth uint32,
) ([]domain.Marker, error) {
	var dtos []markerDTO
	err := r.markerStore.Find(&dtos,
		badgerhold.Where("Depth").Ge(minDepth).And("Depth").Le(maxDepth))
	if err != nil {
		return nil, err
	}

	markers := make([]domain.Marker, 0, len(dtos))
	for _, dto := range dtos {
		markers = append(markers, domain.Marker{
			ID:              dto.ID,
			Depth:           dto.Depth,
			ParentMarkerIDs: dto.ParentMarkerIDs,
		})
	}
	return markers, nil
}

func (r *markerRepository) GetMarkersByIds(
	ctx context.Context,
	ids []string,
) ([]domain.Marker, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	markers := make([]domain.Marker, 0, len(ids))
	for _, id := range ids {
		marker, err := r.GetMarker(ctx, id)
		if err != nil {
			return nil, err
		}
		if marker != nil {
			markers = append(markers, *marker)
		}
	}
	return markers, nil
}

// sweepMarker marks a single marker as swept and syncs the Swept field on
// affected VTXOs. Used by BulkSweepMarkers.
func (r *markerRepository) sweepMarker(ctx context.Context, markerID string, sweptAt int64) error {
	// Check if already swept - if so, preserve original swept_at (ON CONFLICT DO NOTHING behavior)
	var existing sweptMarkerDTO
	err := r.sweptMarkerStore.Get(markerID, &existing)
	if err == nil {
		// Already swept, don't update
		return nil
	}
	if err != badgerhold.ErrNotFound {
		return err
	}

	dto := sweptMarkerDTO{
		MarkerID: markerID,
		SweptAt:  sweptAt,
	}

	err = r.sweptMarkerStore.Insert(markerID, dto)
	if err != nil {
		if errors.Is(err, badgerhold.ErrKeyExists) {
			// Already exists (race condition), that's fine
			return nil
		}
		if errors.Is(err, badger.ErrConflict) {
			for attempts := 1; attempts <= maxRetries; attempts++ {
				time.Sleep(100 * time.Millisecond)
				err = r.sweptMarkerStore.Insert(markerID, dto)
				if err == nil || errors.Is(err, badgerhold.ErrKeyExists) {
					break
				}
			}
			if err != nil && !errors.Is(err, badgerhold.ErrKeyExists) {
				return err
			}
		} else {
			return err
		}
	}

	// Update Swept field on VTXOs that contain this marker.
	// This keeps the stored Swept field in sync for query compatibility.
	// Errors here are non-fatal since swept_marker is already recorded.
	var filteredDtos []vtxoDTO
	if err := r.vtxoStore.Find(
		&filteredDtos,
		badgerhold.Where("MarkerIDs").Contains(markerID),
	); err != nil {
		return nil
	}

	for _, dto := range filteredDtos {
		if !dto.Swept {
			dto.Swept = true
			dto.UpdatedAt = time.Now().UnixMilli()
			if err := r.vtxoStore.Update(dto.Outpoint.String(), dto); err != nil {
				if errors.Is(err, badger.ErrConflict) {
					for attempts := 1; attempts <= maxRetries; attempts++ {
						time.Sleep(100 * time.Millisecond)
						if err = r.vtxoStore.Update(dto.Outpoint.String(), dto); err == nil {
							break
						}
					}
				}
			}
		}
	}

	return nil
}

func (r *markerRepository) BulkSweepMarkers(
	ctx context.Context,
	markerIDs []string,
	sweptAt int64,
) error {
	for _, markerID := range markerIDs {
		if err := r.sweepMarker(ctx, markerID, sweptAt); err != nil {
			return err
		}
	}
	return nil
}

func (r *markerRepository) SweepVtxoOutpoints(
	ctx context.Context,
	outpoints []domain.Outpoint,
	sweptAt int64,
) error {
	for _, op := range outpoints {
		var dto vtxoDTO
		if err := r.vtxoStore.Get(op.String(), &dto); err != nil {
			if err == badgerhold.ErrNotFound {
				continue
			}
			return err
		}
		dto.Swept = true
		if err := r.vtxoStore.Update(op.String(), dto); err != nil {
			return err
		}
	}
	return nil
}

func (r *markerRepository) IsMarkerSwept(ctx context.Context, markerID string) (bool, error) {
	var dto sweptMarkerDTO
	err := r.sweptMarkerStore.Get(markerID, &dto)
	if err != nil {
		if err == badgerhold.ErrNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (r *markerRepository) GetSweptMarkers(
	ctx context.Context,
	markerIDs []string,
) ([]domain.SweptMarker, error) {
	if len(markerIDs) == 0 {
		return nil, nil
	}

	sweptMarkers := make([]domain.SweptMarker, 0, len(markerIDs))
	for _, id := range markerIDs {
		var dto sweptMarkerDTO
		err := r.sweptMarkerStore.Get(id, &dto)
		if err != nil {
			if err == badgerhold.ErrNotFound {
				continue
			}
			return nil, err
		}
		sweptMarkers = append(sweptMarkers, domain.SweptMarker{
			MarkerID: dto.MarkerID,
			SweptAt:  dto.SweptAt,
		})
	}
	return sweptMarkers, nil
}

func (r *markerRepository) UpdateVtxoMarkers(
	ctx context.Context,
	outpoint domain.Outpoint,
	markerIDs []string,
) error {
	var dto vtxoDTO
	err := r.vtxoStore.Get(outpoint.String(), &dto)
	if err != nil {
		if err == badgerhold.ErrNotFound {
			return nil // VTXO not found, nothing to update
		}
		return err
	}

	dto.MarkerIDs = markerIDs
	dto.UpdatedAt = time.Now().UnixMilli()

	err = r.vtxoStore.Update(outpoint.String(), dto)
	if err != nil {
		if errors.Is(err, badger.ErrConflict) {
			for attempts := 1; attempts <= maxRetries; attempts++ {
				time.Sleep(100 * time.Millisecond)
				err = r.vtxoStore.Update(outpoint.String(), dto)
				if err == nil {
					break
				}
			}
		}
	}
	return err
}

func (r *markerRepository) GetVtxosByMarker(
	ctx context.Context,
	markerID string,
) ([]domain.Vtxo, error) {
	var dtos []vtxoDTO
	err := r.vtxoStore.Find(&dtos, badgerhold.Where("MarkerIDs").Contains(markerID))
	if err != nil {
		return nil, err
	}

	vtxos := make([]domain.Vtxo, 0, len(dtos))
	for _, dto := range dtos {
		vtxos = append(vtxos, dto.Vtxo)
	}
	return vtxos, nil
}

func (r *markerRepository) CreateRootMarkersForVtxos(
	ctx context.Context,
	vtxos []domain.Vtxo,
) error {
	if len(vtxos) == 0 {
		return nil
	}

	for _, vtxo := range vtxos {
		markerID := vtxo.Outpoint.String()

		// Create the root marker (depth 0, no parents)
		// Note: vtxo.MarkerIDs should already be set before AddVtxos is called
		if err := r.AddMarker(ctx, domain.Marker{
			ID:              markerID,
			Depth:           0,
			ParentMarkerIDs: nil,
		}); err != nil {
			return fmt.Errorf("failed to create marker for vtxo %s: %w", markerID, err)
		}
	}

	return nil
}

func (r *markerRepository) GetVtxosByDepthRange(
	ctx context.Context,
	minDepth, maxDepth uint32,
) ([]domain.Vtxo, error) {
	var dtos []vtxoDTO
	err := r.vtxoStore.Find(&dtos,
		badgerhold.Where("Depth").Ge(minDepth).And("Depth").Le(maxDepth))
	if err != nil {
		return nil, err
	}

	vtxos := make([]domain.Vtxo, 0, len(dtos))
	for _, dto := range dtos {
		vtxos = append(vtxos, dto.Vtxo)
	}
	return vtxos, nil
}

func (r *markerRepository) GetVtxosByArkTxid(
	ctx context.Context,
	arkTxid string,
) ([]domain.Vtxo, error) {
	var dtos []vtxoDTO
	err := r.vtxoStore.Find(&dtos, badgerhold.Where("ArkTxid").Eq(arkTxid))
	if err != nil {
		return nil, err
	}

	vtxos := make([]domain.Vtxo, 0, len(dtos))
	for _, dto := range dtos {
		vtxos = append(vtxos, dto.Vtxo)
	}
	return vtxos, nil
}

func (r *markerRepository) GetVtxoChainByMarkers(
	ctx context.Context,
	markerIDs []string,
) ([]domain.Vtxo, error) {
	if len(markerIDs) == 0 {
		return nil, nil
	}

	seen := make(map[string]bool)
	vtxos := make([]domain.Vtxo, 0)

	for _, markerID := range markerIDs {
		var dtos []vtxoDTO
		err := r.vtxoStore.Find(&dtos,
			badgerhold.Where("MarkerIDs").Contains(markerID))
		if err != nil {
			return nil, err
		}
		for _, dto := range dtos {
			key := dto.Outpoint.String()
			if !seen[key] {
				seen[key] = true
				vtxos = append(vtxos, dto.Vtxo)
			}
		}
	}
	return vtxos, nil
}
