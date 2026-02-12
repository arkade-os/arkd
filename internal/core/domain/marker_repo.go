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
	// SweepMarkerWithDescendants marks a marker and all its descendants as swept
	// Returns the number of markers swept (including descendants)
	SweepMarkerWithDescendants(ctx context.Context, markerID string, sweptAt int64) (int64, error)
	// IsMarkerSwept checks if a marker has been swept
	IsMarkerSwept(ctx context.Context, markerID string) (bool, error)
	// GetSweptMarkers retrieves swept marker records for the given marker IDs
	GetSweptMarkers(ctx context.Context, markerIDs []string) ([]SweptMarker, error)

	// UpdateVtxoMarkers updates the markers array for a VTXO
	UpdateVtxoMarkers(ctx context.Context, outpoint Outpoint, markerIDs []string) error
	// GetVtxosByMarker retrieves all VTXOs associated with a marker
	GetVtxosByMarker(ctx context.Context, markerID string) ([]Vtxo, error)
	// SweepVtxosByMarker inserts the marker into swept_marker table
	// Returns the number of VTXOs that will now be considered swept
	SweepVtxosByMarker(ctx context.Context, markerID string) (int64, error)

	// MarkDustVtxoSwept creates a unique dust marker for a vtxo and marks it as swept
	// Used for dust vtxos that need to be marked swept immediately on creation
	MarkDustVtxoSwept(ctx context.Context, outpoint Outpoint, sweptAt int64) error

	// Chain traversal methods for GetVtxoChain optimization
	// GetVtxosByDepthRange retrieves VTXOs within a depth range
	GetVtxosByDepthRange(ctx context.Context, minDepth, maxDepth uint32) ([]Vtxo, error)
	// GetVtxosByArkTxid retrieves VTXOs created by a specific ark tx
	GetVtxosByArkTxid(ctx context.Context, arkTxid string) ([]Vtxo, error)
	// GetVtxoChainByMarkers retrieves VTXOs that have markers in the given list
	GetVtxoChainByMarkers(ctx context.Context, markerIDs []string) ([]Vtxo, error)

	Close()
}
