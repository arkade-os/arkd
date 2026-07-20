package domain

import "fmt"

// MarkerInterval is the depth interval at which markers are created.
// VTXOs at depth 0, 100, 200, etc. create new markers.
const MarkerInterval = 100

// SweptMarker records when a marker (and all VTXOs it covers) was swept.
// This is an append-only table that enables efficient bulk sweep operations.
type SweptMarker struct {
	// MarkerID is the ID of the marker that was swept
	MarkerID string
	// SweptAt is the Unix timestamp (seconds) when the marker was swept
	SweptAt int64
}

// Marker represents a DAG traversal checkpoint created at regular depth intervals.
// Markers enable compressed traversal of the VTXO chain by allowing jumps of
// MarkerInterval depths instead of traversing each VTXO individually.
type Marker struct {
	// ID is the unique identifier for this marker (typically the VTXO outpoint)
	ID string
	// Depth is the chain depth at which this marker exists (0, 100, 200, ...)
	Depth uint32
	// ParentMarkerIDs is a list of marker IDs that this marker descends from
	ParentMarkerIDs []string
	// CreatedAt is the Unix timestamp (seconds) when this marker was created.
	// Used by the velocity rate limiter to measure how fast a chain is growing.
	CreatedAt int64
}

// NewMarker computes marker information for a new offchain transaction.
// If the depth is at a marker boundary, it returns a new Marker and the marker IDs
// to assign to the child VTXOs (just the new marker ID).
// Otherwise, it returns nil and the inherited parent marker IDs.
func NewMarker(txid string, depth uint32, parentMarkerIDs []string) (*Marker, []string) {
	if isAtMarkerBoundary(depth) {
		id := fmt.Sprintf("%s:marker:%d", txid, depth)
		marker := &Marker{
			ID:              id,
			Depth:           depth,
			ParentMarkerIDs: parentMarkerIDs,
		}
		return marker, []string{id}
	}
	if len(parentMarkerIDs) > 0 {
		return nil, parentMarkerIDs
	}
	return nil, nil
}

// MarkerIDsOf collects the marker IDs referenced by the given VTXOs, preserving
// first-seen order and dropping duplicates and empty IDs. Sibling VTXOs routinely
// inherit the same markers, so callers bulk-fetching by these IDs would otherwise
// ask the store for the same marker several times.
func MarkerIDsOf(vtxos []Vtxo) []string {
	ids := make([]string, 0)
	seen := make(map[string]struct{})
	for _, vtxo := range vtxos {
		for _, id := range vtxo.MarkerIDs {
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids
}

// isAtMarkerBoundary returns true if the given depth is at a marker boundary.
func isAtMarkerBoundary(depth uint32) bool {
	return depth%MarkerInterval == 0
}
