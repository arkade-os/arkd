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
			expectedDepth: 0,
			description:   "empty input results in depth 0 (no spent vtxos means maxDepth stays 0, newDepth = 0)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			maxDepth := calculateMaxDepth(tc.spentVtxos)
			var newDepth uint32
			if len(tc.spentVtxos) > 0 {
				newDepth = maxDepth + 1
			}
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

// TestAllNewVtxosGetSameDepth verifies that when a single offchain tx produces
// multiple output VTXOs, all of them receive the same depth (max parent depth + 1)
// and the same marker IDs. This mirrors the logic in updateProjectionsAfterOffchainTxEvents
// where newDepth is computed once and applied to all new VTXOs from the same tx.
func TestAllNewVtxosGetSameDepth(t *testing.T) {
	testCases := []struct {
		name              string
		parentDepths      []uint32
		parentMarkerSets  [][]string
		numOutputVtxos    int
		expectedDepth     uint32
		expectedMarkerLen int
		description       string
	}{
		{
			name:              "3 outputs from single parent at depth 0",
			parentDepths:      []uint32{0},
			parentMarkerSets:  [][]string{{"root-marker-1"}},
			numOutputVtxos:    3,
			expectedDepth:     1,
			expectedMarkerLen: 1,
			description:       "all 3 outputs get depth 1 and inherit root marker",
		},
		{
			name:              "5 outputs from two parents at different depths",
			parentDepths:      []uint32{30, 50},
			parentMarkerSets:  [][]string{{"marker-A"}, {"marker-B", "marker-C"}},
			numOutputVtxos:    5,
			expectedDepth:     51,
			expectedMarkerLen: 3,
			description:       "all 5 outputs get depth 51 (max+1) and inherit union of markers",
		},
		{
			name:              "2 outputs at marker boundary",
			parentDepths:      []uint32{99},
			parentMarkerSets:  [][]string{{"root-marker"}},
			numOutputVtxos:    2,
			expectedDepth:     100,
			expectedMarkerLen: 1,
			description:       "both outputs get depth 100 and the same new marker",
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

			parentMarkers := collectParentMarkers(spentVtxos)
			markerIDs, _ := deriveMarkerIDs(newDepth, parentMarkers, "tx-with-multiple-outputs")

			// Simulate creating multiple output VTXOs — each gets the same depth and markers
			outputs := make([]domain.Vtxo, tc.numOutputVtxos)
			for i := 0; i < tc.numOutputVtxos; i++ {
				outputs[i] = domain.Vtxo{
					Outpoint:  domain.Outpoint{Txid: "tx-with-multiple-outputs", VOut: uint32(i)},
					Depth:     newDepth,
					MarkerIDs: markerIDs,
				}
			}

			// All outputs must have the same depth
			for i, v := range outputs {
				require.Equal(t, tc.expectedDepth, v.Depth,
					"output %d has wrong depth", i)
			}

			// All outputs must have the same marker IDs
			for i := 1; i < len(outputs); i++ {
				sort.Strings(outputs[0].MarkerIDs)
				sort.Strings(outputs[i].MarkerIDs)
				require.Equal(t, outputs[0].MarkerIDs, outputs[i].MarkerIDs,
					"output %d has different markers than output 0", i)
			}

			require.Len(t, outputs[0].MarkerIDs, tc.expectedMarkerLen, tc.description)
		})
	}
}

// TestDepth20k_MarkerBoundaryAndInheritance verifies marker behavior at the
// target maximum depth of 20000. Tests boundary transitions, inheritance with
// large marker sets, and depth calculation with deeply chained VTXOs.
func TestDepth20k_MarkerBoundaryAndInheritance(t *testing.T) {
	t.Run("depth 19999 inherits markers, depth 20000 creates new marker", func(t *testing.T) {
		// Parent at depth 19999 => child at 20000 (boundary)
		parent := domain.Vtxo{Depth: 19999, MarkerIDs: []string{"marker-19900"}}
		parentMarkers := collectParentMarkers([]domain.Vtxo{parent})

		newDepth := calculateMaxDepth([]domain.Vtxo{parent}) + 1
		require.Equal(t, uint32(20000), newDepth)
		require.True(t, domain.IsAtMarkerBoundary(newDepth))

		markerIDs, createdMarker := deriveMarkerIDs(newDepth, parentMarkers, "tx-at-20k")
		require.NotNil(t, createdMarker, "marker should be created at depth 20000")
		require.Equal(t, uint32(20000), createdMarker.Depth)
		require.Equal(t, []string{"marker-19900"}, createdMarker.ParentMarkerIDs)
		require.Len(t, markerIDs, 1)
		require.Equal(t, createdMarker.ID, markerIDs[0])
	})

	t.Run("depth 20001 inherits markers from boundary parent", func(t *testing.T) {
		parent := domain.Vtxo{Depth: 20000, MarkerIDs: []string{"marker-20000"}}
		parentMarkers := collectParentMarkers([]domain.Vtxo{parent})

		newDepth := calculateMaxDepth([]domain.Vtxo{parent}) + 1
		require.Equal(t, uint32(20001), newDepth)
		require.False(t, domain.IsAtMarkerBoundary(newDepth))

		markerIDs, createdMarker := deriveMarkerIDs(newDepth, parentMarkers, "tx-at-20001")
		require.Nil(t, createdMarker, "no marker at non-boundary depth")
		require.Equal(t, []string{"marker-20000"}, markerIDs)
	})

	t.Run("VTXO with 200 inherited markers from deep chain", func(t *testing.T) {
		// Simulate a VTXO at depth 19950 that has accumulated 200 marker IDs
		// from a chain where markers were created at every boundary
		markers := make([]string, 200)
		for i := range markers {
			markers[i] = fmt.Sprintf("marker-%d", i*100)
		}

		parent := domain.Vtxo{Depth: 19950, MarkerIDs: markers}
		collected := collectParentMarkers([]domain.Vtxo{parent})
		sort.Strings(collected)
		sort.Strings(markers)
		require.Equal(t, markers, collected, "all 200 markers should be collected")
	})

	t.Run("multiple deep parents merge 200+ markers correctly", func(t *testing.T) {
		// Two parents deep in the chain with overlapping markers
		markersA := make([]string, 100)
		markersB := make([]string, 150)
		for i := range markersA {
			markersA[i] = fmt.Sprintf("marker-%d", i*100) // 0, 100, ..., 9900
		}
		for i := range markersB {
			markersB[i] = fmt.Sprintf("marker-%d", i*100) // 0, 100, ..., 14900
		}

		parents := []domain.Vtxo{
			{Depth: 10000, MarkerIDs: markersA},
			{Depth: 15000, MarkerIDs: markersB},
		}
		collected := collectParentMarkers(parents)

		// Union should be 150 unique markers (0..14900)
		require.Len(t, collected, 150)

		newDepth := calculateMaxDepth(parents) + 1
		require.Equal(t, uint32(15001), newDepth)
		require.False(t, domain.IsAtMarkerBoundary(newDepth))

		markerIDs, createdMarker := deriveMarkerIDs(newDepth, collected, "merge-tx")
		require.Nil(t, createdMarker)
		require.Len(t, markerIDs, 150, "child inherits all 150 unique markers")
	})

	t.Run("depth beyond 20k target remains valid", func(t *testing.T) {
		// Verify depth arithmetic works correctly beyond the 20k boundary
		parent := domain.Vtxo{Depth: 20000, MarkerIDs: []string{"marker-20000"}}
		newDepth := calculateMaxDepth([]domain.Vtxo{parent}) + 1
		require.Equal(t, uint32(20001), newDepth)

		// Depth 20100 should also be a boundary
		require.True(t, domain.IsAtMarkerBoundary(20100))
		require.True(t, domain.IsAtMarkerBoundary(20200))
		require.False(t, domain.IsAtMarkerBoundary(20001))
		require.False(t, domain.IsAtMarkerBoundary(20099))
	})
}
