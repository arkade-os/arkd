package domain

import "context"

type MarkerRepository interface {
	// AddMarker creates or updates a marker
	AddMarker(ctx context.Context, marker Marker) error
	// GetMarker retrieves a marker by ID
	GetMarker(ctx context.Context, id string) (*Marker, error)
	// GetMarkersByDepthRange retrieves all markers within a depth range
	GetMarkersByDepthRange(ctx context.Context, minDepth, maxDepth uint32) ([]Marker, error)
	// GetMarkersByIds retrieves markers by their IDs
	GetMarkersByIds(ctx context.Context, ids []string) ([]Marker, error)

	// BulkSweepMarkers marks multiple markers as swept in a single operation
	BulkSweepMarkers(ctx context.Context, markerIDs []string, sweptAt int64) error
	// IsMarkerSwept checks if a marker has been swept
	IsMarkerSwept(ctx context.Context, markerID string) (bool, error)
	// GetSweptMarkers retrieves swept marker records for the given marker IDs
	GetSweptMarkers(ctx context.Context, markerIDs []string) ([]SweptMarker, error)

	// UpdateVtxoMarkers updates the markers array for a VTXO
	UpdateVtxoMarkers(ctx context.Context, outpoint Outpoint, markerIDs []string) error
	// GetVtxosByMarker retrieves all VTXOs associated with a marker
	GetVtxosByMarker(ctx context.Context, markerID string) ([]Vtxo, error)

	// CreateRootMarkersForVtxos creates root markers for batch VTXOs and updates their marker references
	// in a single transaction. Each VTXO gets a marker with ID equal to its outpoint string.
	CreateRootMarkersForVtxos(ctx context.Context, vtxos []Vtxo) error

	// SweepVtxoOutpoints marks specific VTXO outpoints as swept in the swept_vtxo
	// table. Used by checkpoint sweeps where marker-based sweeping would over-reach
	// across independent subtrees that share inherited markers.
	SweepVtxoOutpoints(ctx context.Context, outpoints []Outpoint, sweptAt int64) error

	// Chain traversal methods for GetVtxoChain optimization
	// GetVtxosByDepthRange retrieves VTXOs within a depth range
	GetVtxosByDepthRange(ctx context.Context, minDepth, maxDepth uint32) ([]Vtxo, error)
	// GetVtxosByArkTxid retrieves VTXOs created by a specific ark tx
	GetVtxosByArkTxid(ctx context.Context, arkTxid string) ([]Vtxo, error)
	// GetVtxoChainByMarkers retrieves VTXOs that have markers in the given list
	GetVtxoChainByMarkers(ctx context.Context, markerIDs []string) ([]Vtxo, error)

	Close()
}
