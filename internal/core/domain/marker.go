package domain

import (
	"fmt"
	"sort"
)

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
}

// ChainDepthAndParentMarkers computes the chain depth and inherited parent
// marker IDs for a new tx from the vtxos it spends. Depth is
// max(parent depths) + 1, or 0 when nothing is spent. ParentMarkerIDs is the
// deduplicated union of the spent vtxos' non-empty marker IDs, sorted so the
// result is deterministic regardless of input order.
//
// This is the single source of truth for the computation recorded on the
// OffchainTxAccepted event, so the call sites that need it cannot drift.
func ChainDepthAndParentMarkers(spent []Vtxo) (uint32, []string) {
	var maxDepth uint32
	parentSet := make(map[string]struct{})
	for _, v := range spent {
		if v.Depth > maxDepth {
			maxDepth = v.Depth
		}
		for _, id := range v.MarkerIDs {
			if id != "" {
				parentSet[id] = struct{}{}
			}
		}
	}
	var depth uint32
	if len(spent) > 0 {
		depth = maxDepth + 1
	}
	parents := make([]string, 0, len(parentSet))
	for id := range parentSet {
		parents = append(parents, id)
	}
	sort.Strings(parents)
	return depth, parents
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

// isAtMarkerBoundary returns true if the given depth is at a marker boundary.
func isAtMarkerBoundary(depth uint32) bool {
	return depth%MarkerInterval == 0
}
