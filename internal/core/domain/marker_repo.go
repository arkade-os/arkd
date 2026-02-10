package domain

import "context"

type MarkerRepository interface {
	// AddMarker creates or updates a marker
	AddMarker(ctx context.Context, marker Marker) error
	// GetMarker retrieves a marker by ID
	GetMarker(ctx context.Context, id string) (*Marker, error)
	// GetMarkersByDepth retrieves all markers at a specific depth
	GetMarkersByDepth(ctx context.Context, depth uint32) ([]Marker, error)
	// GetMarkersByDepthRange retrieves all markers within a depth range
	GetMarkersByDepthRange(ctx context.Context, minDepth, maxDepth uint32) ([]Marker, error)
	// GetMarkersByIds retrieves markers by their IDs
	GetMarkersByIds(ctx context.Context, ids []string) ([]Marker, error)

	// SweepMarker marks a marker as swept at the given timestamp
	SweepMarker(ctx context.Context, markerID string, sweptAt int64) error
	// IsMarkerSwept checks if a marker has been swept
	IsMarkerSwept(ctx context.Context, markerID string) (bool, error)
	// GetSweptMarkers retrieves swept marker records for the given marker IDs
	GetSweptMarkers(ctx context.Context, markerIDs []string) ([]SweptMarker, error)

	// UpdateVtxoMarker updates the marker_id for a VTXO
	UpdateVtxoMarker(ctx context.Context, outpoint Outpoint, markerID string) error
	// GetVtxosByMarker retrieves all VTXOs associated with a marker
	GetVtxosByMarker(ctx context.Context, markerID string) ([]Vtxo, error)
	// SweepVtxosByMarker marks all VTXOs with the given marker_id as swept
	// Returns the number of VTXOs that were swept (not already swept)
	SweepVtxosByMarker(ctx context.Context, markerID string) (int64, error)

	// Chain traversal methods for GetVtxoChain optimization
	// GetVtxosByDepthRange retrieves VTXOs within a depth range
	GetVtxosByDepthRange(ctx context.Context, minDepth, maxDepth uint32) ([]Vtxo, error)
	// GetVtxosByArkTxid retrieves VTXOs created by a specific ark tx
	GetVtxosByArkTxid(ctx context.Context, arkTxid string) ([]Vtxo, error)
	// GetVtxoChainByMarkers retrieves VTXOs that have markers in the given list
	GetVtxoChainByMarkers(ctx context.Context, markerIDs []string) ([]Vtxo, error)

	Close()
}
