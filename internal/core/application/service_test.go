package application

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

func TestNextScheduledSession(t *testing.T) {
	scheduledSessionStartTime := parseTime(t, "2023-10-10 13:00:00")
	scheduledSessionEndTime := parseTime(t, "2023-10-10 14:00:00")
	period := 1 * time.Hour

	testCases := []struct {
		now           time.Time
		expectedStart time.Time
		expectedEnd   time.Time
		description   string
	}{
		{
			now:           parseTime(t, "2023-10-10 13:00:00"),
			expectedStart: parseTime(t, "2023-10-10 13:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 14:00:00"),
			description:   "now is exactly scheduled session start time",
		},
		{
			now:           parseTime(t, "2023-10-10 13:55:00"),
			expectedStart: parseTime(t, "2023-10-10 13:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 14:00:00"),
			description:   "now is in the first scheduled session",
		},
		{
			now:           parseTime(t, "2023-10-10 14:00:00"),
			expectedStart: parseTime(t, "2023-10-10 14:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 15:00:00"),
			description:   "now is exactly scheduled session end time",
		},
		{
			now:           parseTime(t, "2023-10-10 14:06:00"),
			expectedStart: parseTime(t, "2023-10-10 14:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 15:00:00"),
			description:   "now is after first scheduled session",
		},
		{
			now:           parseTime(t, "2023-10-10 15:30:00"),
			expectedStart: parseTime(t, "2023-10-10 15:00:00"),
			expectedEnd:   parseTime(t, "2023-10-10 16:00:00"),
			description:   "now is after second scheduled session",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			startTime, endTime := calcNextScheduledSession(
				tc.now, scheduledSessionStartTime, scheduledSessionEndTime, period,
			)
			require.True(t, startTime.Equal(tc.expectedStart))
			require.True(t, endTime.Equal(tc.expectedEnd))
		})
	}
}

func parseTime(t *testing.T, value string) time.Time {
	tm, err := time.ParseInLocation(time.DateTime, value, time.UTC)
	require.NoError(t, err)
	return tm
}

// calculateMaxDepth mimics the depth calculation logic in the service event handler.
// This function exists to make the depth calculation testable independently.
func calculateMaxDepth(spentVtxos []domain.Vtxo) uint32 {
	var maxDepth uint32
	for _, v := range spentVtxos {
		if v.Depth > maxDepth {
			maxDepth = v.Depth
		}
	}
	return maxDepth
}

func TestDepthCalculation(t *testing.T) {
	testCases := []struct {
		name          string
		spentVtxos    []domain.Vtxo
		expectedDepth uint32
		description   string
	}{
		{
			name:          "single batch vtxo at depth 0",
			spentVtxos:    []domain.Vtxo{{Depth: 0}},
			expectedDepth: 1,
			description:   "spending a batch vtxo creates vtxo at depth 1",
		},
		{
			name:          "single vtxo at depth 50",
			spentVtxos:    []domain.Vtxo{{Depth: 50}},
			expectedDepth: 51,
			description:   "spending a chained vtxo increments depth",
		},
		{
			name: "multiple vtxos with same depth",
			spentVtxos: []domain.Vtxo{
				{Depth: 10},
				{Depth: 10},
				{Depth: 10},
			},
			expectedDepth: 11,
			description:   "combining vtxos at same depth increments once",
		},
		{
			name: "multiple vtxos with different depths",
			spentVtxos: []domain.Vtxo{
				{Depth: 5},
				{Depth: 25},
				{Depth: 15},
			},
			expectedDepth: 26,
			description:   "uses max depth from inputs",
		},
		{
			name: "vtxos spanning marker boundary",
			spentVtxos: []domain.Vtxo{
				{Depth: 95},
				{Depth: 105},
			},
			expectedDepth: 106,
			description:   "handles depths across marker boundaries",
		},
		{
			name: "deep chain near marker boundary",
			spentVtxos: []domain.Vtxo{
				{Depth: 99},
			},
			expectedDepth: 100,
			description:   "result at marker boundary (100)",
		},
		{
			name: "very deep chain",
			spentVtxos: []domain.Vtxo{
				{Depth: 500},
			},
			expectedDepth: 501,
			description:   "handles deep chains beyond multiple marker intervals",
		},
		{
			name:          "no spent vtxos (empty)",
			spentVtxos:    []domain.Vtxo{},
			expectedDepth: 1,
			description:   "empty input results in depth 1 (edge case)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			maxDepth := calculateMaxDepth(tc.spentVtxos)
			newDepth := maxDepth + 1
			require.Equal(t, tc.expectedDepth, newDepth, tc.description)
		})
	}
}

func TestDepthAtMarkerBoundary(t *testing.T) {
	// Test integration of depth and marker boundary detection
	testCases := []struct {
		depth        uint32
		isAtBoundary bool
		description  string
	}{
		{0, true, "depth 0 is at marker boundary"},
		{1, false, "depth 1 is not at boundary"},
		{50, false, "depth 50 is not at boundary"},
		{99, false, "depth 99 is not at boundary"},
		{100, true, "depth 100 is at marker boundary"},
		{101, false, "depth 101 is not at boundary"},
		{200, true, "depth 200 is at marker boundary"},
		{500, true, "depth 500 is at marker boundary"},
		{1000, true, "depth 1000 is at marker boundary"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			isAtBoundary := domain.IsAtMarkerBoundary(tc.depth)
			require.Equal(t, tc.isAtBoundary, isAtBoundary)
		})
	}
}

func TestDepthIncrementCreatesMarkerAtBoundary(t *testing.T) {
	// Test scenario: when depth increments to a marker boundary,
	// a marker should be created for that VTXO
	testCases := []struct {
		parentDepth        uint32
		newDepth           uint32
		shouldCreateMarker bool
	}{
		{99, 100, true},   // crossing into boundary
		{100, 101, false}, // leaving boundary
		{199, 200, true},  // crossing into next boundary
		{0, 1, false},     // moving away from initial boundary
		{98, 99, false},   // approaching but not at boundary
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			// Simulate the depth increment
			spentVtxos := []domain.Vtxo{{Depth: tc.parentDepth}}
			maxDepth := calculateMaxDepth(spentVtxos)
			newDepth := maxDepth + 1

			require.Equal(t, tc.newDepth, newDepth)
			isAtBoundary := domain.IsAtMarkerBoundary(newDepth)
			require.Equal(t, tc.shouldCreateMarker, isAtBoundary)
		})
	}
}

// collectParentMarkers mimics the parent marker collection logic in the
// service's updateProjectionsAfterOffchainTxEvents handler.
// It collects ALL unique, non-empty marker IDs from the spent VTXOs.
func collectParentMarkers(spentVtxos []domain.Vtxo) []string {
	parentMarkerSet := make(map[string]struct{})
	for _, v := range spentVtxos {
		for _, markerID := range v.MarkerIDs {
			if markerID != "" {
				parentMarkerSet[markerID] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(parentMarkerSet))
	for id := range parentMarkerSet {
		result = append(result, id)
	}
	return result
}

// deriveMarkerIDs mimics the marker creation/inheritance decision in the
// service's updateProjectionsAfterOffchainTxEvents handler.
// At boundary depths a new marker is created; otherwise parent markers are inherited.
func deriveMarkerIDs(
	newDepth uint32,
	parentMarkerIDs []string,
	txid string,
) (markerIDs []string, createdMarker *domain.Marker) {
	if domain.IsAtMarkerBoundary(newDepth) {
		newMarkerID := txid + ":marker:" + fmt.Sprintf("%d", newDepth)
		marker := domain.Marker{
			ID:              newMarkerID,
			Depth:           newDepth,
			ParentMarkerIDs: parentMarkerIDs,
		}
		return []string{newMarkerID}, &marker
	}
	if len(parentMarkerIDs) > 0 {
		return parentMarkerIDs, nil
	}
	return nil, nil
}

func TestParentMarkerCollectionFromMultipleParents(t *testing.T) {
	// When spending multiple VTXOs with different marker sets,
	// the parent marker set should be the deduplicated union of all inputs' markers.
	testCases := []struct {
		name            string
		spentVtxos      []domain.Vtxo
		expectedMarkers []string
	}{
		{
			name: "single parent with one marker",
			spentVtxos: []domain.Vtxo{
				{MarkerIDs: []string{"marker-A"}},
			},
			expectedMarkers: []string{"marker-A"},
		},
		{
			name: "two parents with distinct markers",
			spentVtxos: []domain.Vtxo{
				{MarkerIDs: []string{"marker-A"}},
				{MarkerIDs: []string{"marker-B"}},
			},
			expectedMarkers: []string{"marker-A", "marker-B"},
		},
		{
			name: "three parents with overlapping markers",
			spentVtxos: []domain.Vtxo{
				{MarkerIDs: []string{"marker-A", "marker-B"}},
				{MarkerIDs: []string{"marker-B", "marker-C"}},
				{MarkerIDs: []string{"marker-A", "marker-C"}},
			},
			expectedMarkers: []string{"marker-A", "marker-B", "marker-C"},
		},
		{
			name: "all parents share the same marker",
			spentVtxos: []domain.Vtxo{
				{MarkerIDs: []string{"root-marker"}},
				{MarkerIDs: []string{"root-marker"}},
				{MarkerIDs: []string{"root-marker"}},
			},
			expectedMarkers: []string{"root-marker"},
		},
		{
			name:            "no parents",
			spentVtxos:      []domain.Vtxo{},
			expectedMarkers: []string{},
		},
		{
			name: "parent with no markers",
			spentVtxos: []domain.Vtxo{
				{MarkerIDs: []string{}},
			},
			expectedMarkers: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := collectParentMarkers(tc.spentVtxos)
			sort.Strings(result)
			sort.Strings(tc.expectedMarkers)
			require.Equal(t, tc.expectedMarkers, result)
		})
	}
}

func TestParentMarkerCollectionSkipsEmptyMarkerIDs(t *testing.T) {
	// Empty string marker IDs should be filtered out.
	spentVtxos := []domain.Vtxo{
		{MarkerIDs: []string{"marker-A", "", "marker-B"}},
		{MarkerIDs: []string{"", ""}},
		{MarkerIDs: []string{"marker-C", ""}},
	}

	result := collectParentMarkers(spentVtxos)
	sort.Strings(result)
	require.Equal(t, []string{"marker-A", "marker-B", "marker-C"}, result)
}

func TestMarkerInheritanceAtNonBoundary(t *testing.T) {
	// When the new depth is NOT at a marker boundary, the child VTXO
	// should inherit ALL parent marker IDs (no new marker created).
	testCases := []struct {
		name             string
		parentDepths     []uint32
		parentMarkerSets [][]string
		expectedDepth    uint32
		expectedMarkers  []string
		description      string
	}{
		{
			name:             "single parent at depth 0, child at depth 1",
			parentDepths:     []uint32{0},
			parentMarkerSets: [][]string{{"root-marker-1"}},
			expectedDepth:    1,
			expectedMarkers:  []string{"root-marker-1"},
			description:      "child inherits single parent marker",
		},
		{
			name:             "single parent at depth 50, child at depth 51",
			parentDepths:     []uint32{50},
			parentMarkerSets: [][]string{{"marker-A", "marker-B"}},
			expectedDepth:    51,
			expectedMarkers:  []string{"marker-A", "marker-B"},
			description:      "child inherits multiple parent markers",
		},
		{
			name:             "two parents at different depths, child not at boundary",
			parentDepths:     []uint32{30, 40},
			parentMarkerSets: [][]string{{"marker-X"}, {"marker-Y"}},
			expectedDepth:    41,
			expectedMarkers:  []string{"marker-X", "marker-Y"},
			description:      "child inherits union of all parent markers",
		},
		{
			name:             "three parents with overlapping markers",
			parentDepths:     []uint32{10, 20, 15},
			parentMarkerSets: [][]string{{"m1", "m2"}, {"m2", "m3"}, {"m1"}},
			expectedDepth:    21,
			expectedMarkers:  []string{"m1", "m2", "m3"},
			description:      "child inherits deduplicated union",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spentVtxos := make([]domain.Vtxo, len(tc.parentDepths))
			for i, depth := range tc.parentDepths {
				spentVtxos[i] = domain.Vtxo{
					Depth:     depth,
					MarkerIDs: tc.parentMarkerSets[i],
				}
			}

			maxDepth := calculateMaxDepth(spentVtxos)
			newDepth := maxDepth + 1
			require.Equal(t, tc.expectedDepth, newDepth)

			// Should NOT be at a marker boundary
			require.False(t, domain.IsAtMarkerBoundary(newDepth),
				"depth %d should not be at marker boundary for this test", newDepth)

			parentMarkers := collectParentMarkers(spentVtxos)
			markerIDs, createdMarker := deriveMarkerIDs(newDepth, parentMarkers, "some-txid")

			// No new marker should be created
			require.Nil(t, createdMarker, tc.description)
			// Should inherit all parent markers
			sort.Strings(markerIDs)
			sort.Strings(tc.expectedMarkers)
			require.Equal(t, tc.expectedMarkers, markerIDs, tc.description)
		})
	}
}

func TestMarkerCreationAtBoundary(t *testing.T) {
	// When the new depth IS at a marker boundary, a new marker should be
	// created with the collected parent markers as its ParentMarkerIDs.
	testCases := []struct {
		name             string
		parentDepths     []uint32
		parentMarkerSets [][]string
		expectedDepth    uint32
		description      string
	}{
		{
			name:             "parent at depth 99, child at depth 100",
			parentDepths:     []uint32{99},
			parentMarkerSets: [][]string{{"root-marker"}},
			expectedDepth:    100,
			description:      "first non-root boundary",
		},
		{
			name:             "parent at depth 199, child at depth 200",
			parentDepths:     []uint32{199},
			parentMarkerSets: [][]string{{"marker-100", "root-marker"}},
			expectedDepth:    200,
			description:      "second boundary with two parent markers",
		},
		{
			name:             "multiple parents converging at boundary",
			parentDepths:     []uint32{95, 99},
			parentMarkerSets: [][]string{{"marker-A"}, {"marker-B"}},
			expectedDepth:    100,
			description:      "boundary with multiple parent VTXOs",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spentVtxos := make([]domain.Vtxo, len(tc.parentDepths))
			for i, depth := range tc.parentDepths {
				spentVtxos[i] = domain.Vtxo{
					Depth:     depth,
					MarkerIDs: tc.parentMarkerSets[i],
				}
			}

			maxDepth := calculateMaxDepth(spentVtxos)
			newDepth := maxDepth + 1
			require.Equal(t, tc.expectedDepth, newDepth)

			// Should be at a marker boundary
			require.True(t, domain.IsAtMarkerBoundary(newDepth),
				"depth %d should be at marker boundary for this test", newDepth)

			parentMarkers := collectParentMarkers(spentVtxos)
			markerIDs, createdMarker := deriveMarkerIDs(newDepth, parentMarkers, "test-txid")

			// A new marker should be created
			require.NotNil(t, createdMarker, tc.description)
			require.Equal(t, newDepth, createdMarker.Depth)
			// The new marker's ParentMarkerIDs should match collected parent markers
			sort.Strings(createdMarker.ParentMarkerIDs)
			sort.Strings(parentMarkers)
			require.Equal(t, parentMarkers, createdMarker.ParentMarkerIDs)
			// The child VTXO should get ONLY the new marker ID, not parent markers
			require.Len(t, markerIDs, 1)
			require.Equal(t, createdMarker.ID, markerIDs[0])
		})
	}
}
