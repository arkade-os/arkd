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

func (r *markerRepository) GetMarkersByDepth(
	ctx context.Context,
	depth uint32,
) ([]domain.Marker, error) {
	var dtos []markerDTO
	err := r.markerStore.Find(&dtos, badgerhold.Where("Depth").Eq(depth))
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

func (r *markerRepository) SweepMarker(ctx context.Context, markerID string, sweptAt int64) error {
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
					return nil
				}
			}
		}
		return err
	}
	return nil
}

func (r *markerRepository) SweepMarkerWithDescendants(
	ctx context.Context,
	markerID string,
	sweptAt int64,
) (int64, error) {
	// Find all descendant markers using BFS
	descendantIDs, err := r.getDescendantMarkerIds(ctx, markerID)
	if err != nil {
		return 0, fmt.Errorf("failed to get descendant markers: %w", err)
	}

	var count int64
	for _, id := range descendantIDs {
		// Check if already swept
		isSwept, err := r.IsMarkerSwept(ctx, id)
		if err != nil {
			return count, err
		}
		if isSwept {
			continue
		}

		if err := r.SweepMarker(ctx, id, sweptAt); err != nil {
			return count, fmt.Errorf("failed to sweep marker %s: %w", id, err)
		}
		count++
	}

	return count, nil
}

// getDescendantMarkerIds finds all markers that descend from the given marker ID
// using BFS traversal of the parent_marker_ids relationship.
// Returns empty slice if the root marker doesn't exist.
func (r *markerRepository) getDescendantMarkerIds(
	ctx context.Context,
	rootMarkerID string,
) ([]string, error) {
	// First check if the root marker exists
	var rootDTO markerDTO
	err := r.markerStore.Get(rootMarkerID, &rootDTO)
	if err != nil {
		if err == badgerhold.ErrNotFound {
			return []string{}, nil // Root doesn't exist, return empty
		}
		return nil, err
	}

	descendantIDs := []string{rootMarkerID}
	visited := map[string]bool{rootMarkerID: true}
	queue := []string{rootMarkerID}

	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]

		// Find all markers that have currentID in their ParentMarkerIDs
		var dtos []markerDTO
		err := r.markerStore.Find(&dtos,
			badgerhold.Where("ParentMarkerIDs").Contains(currentID))
		if err != nil {
			return nil, err
		}

		for _, dto := range dtos {
			if !visited[dto.ID] {
				visited[dto.ID] = true
				descendantIDs = append(descendantIDs, dto.ID)
				queue = append(queue, dto.ID)
			}
		}
	}

	return descendantIDs, nil
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
	// For badger, we need to scan all VTXOs and filter by MarkerIDs slice membership
	var dtos []vtxoDTO
	err := r.vtxoStore.Find(&dtos, &badgerhold.Query{})
	if err != nil {
		return nil, err
	}

	vtxos := make([]domain.Vtxo, 0)
	for _, dto := range dtos {
		for _, id := range dto.MarkerIDs {
			if id == markerID {
				vtxos = append(vtxos, dto.Vtxo)
				break
			}
		}
	}
	return vtxos, nil
}

func (r *markerRepository) SweepVtxosByMarker(ctx context.Context, markerID string) (int64, error) {
	// For badger, we need to:
	// 1. Mark the marker as swept
	// 2. Update vtxo.Swept field for all VTXOs with this marker (for query compatibility)

	// Find all VTXOs whose MarkerIDs contains markerID and are not swept
	var allDtos []vtxoDTO
	err := r.vtxoStore.Find(&allDtos, badgerhold.Where("Swept").Eq(false))
	if err != nil {
		return 0, err
	}

	var count int64
	for _, dto := range allDtos {
		// Check if this VTXO has the markerID
		hasMarker := false
		for _, id := range dto.MarkerIDs {
			if id == markerID {
				hasMarker = true
				break
			}
		}
		if !hasMarker {
			continue
		}

		// Update the vtxo's Swept field
		dto.Swept = true
		dto.UpdatedAt = time.Now().UnixMilli()

		err := r.vtxoStore.Update(dto.Outpoint.String(), dto)
		if err != nil {
			if errors.Is(err, badger.ErrConflict) {
				for attempts := 1; attempts <= maxRetries; attempts++ {
					time.Sleep(100 * time.Millisecond)
					err = r.vtxoStore.Update(dto.Outpoint.String(), dto)
					if err == nil {
						break
					}
				}
			}
			if err != nil {
				return count, err
			}
		}
		count++
	}

	// Also insert the marker into swept_marker for consistency
	if err := r.SweepMarker(ctx, markerID, time.Now().Unix()); err != nil {
		// Non-fatal - the vtxos are already marked as swept
		_ = err
	}

	return count, nil
}

func (r *markerRepository) MarkDustVtxoSwept(
	ctx context.Context,
	outpoint domain.Outpoint,
	sweptAt int64,
) error {
	// Create a unique dust marker for this vtxo
	dustMarkerID := outpoint.String() + ":dust"

	// Get the vtxo to find its depth and current markers
	var dto vtxoDTO
	err := r.vtxoStore.Get(outpoint.String(), &dto)
	if err != nil {
		if err == badgerhold.ErrNotFound {
			return fmt.Errorf("vtxo not found: %s", outpoint.String())
		}
		return fmt.Errorf("failed to get vtxo: %w", err)
	}

	// Create the dust marker
	if err := r.AddMarker(ctx, domain.Marker{
		ID:              dustMarkerID,
		Depth:           dto.Depth,
		ParentMarkerIDs: dto.MarkerIDs,
	}); err != nil {
		return fmt.Errorf("failed to create dust marker: %w", err)
	}

	// Insert into swept_marker
	if err := r.SweepMarker(ctx, dustMarkerID, sweptAt); err != nil {
		return fmt.Errorf("failed to insert swept marker: %w", err)
	}

	// Update the vtxo's markers to include the dust marker and mark as swept
	dto.MarkerIDs = append(dto.MarkerIDs, dustMarkerID)
	dto.Swept = true
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
		if err != nil {
			return fmt.Errorf("failed to update vtxo: %w", err)
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
	err := r.vtxoStore.Find(&dtos, badgerhold.Where("Txid").Eq(arkTxid))
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

	// Build a set of marker IDs for efficient lookup
	markerIDSet := make(map[string]bool)
	for _, id := range markerIDs {
		markerIDSet[id] = true
	}

	// Find all VTXOs that have any marker_id in our set
	var dtos []vtxoDTO
	err := r.vtxoStore.Find(&dtos, &badgerhold.Query{})
	if err != nil {
		return nil, err
	}

	vtxos := make([]domain.Vtxo, 0)
	for _, dto := range dtos {
		// Check if any of the VTXO's markers are in our set
		for _, markerID := range dto.MarkerIDs {
			if markerIDSet[markerID] {
				vtxos = append(vtxos, dto.Vtxo)
				break
			}
		}
	}
	return vtxos, nil
}
