package domain

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsAtMarkerBoundary(t *testing.T) {
	tests := []struct {
		depth    uint32
		expected bool
	}{
		{0, true}, // First marker boundary
		{1, false},
		{50, false},
		{99, false},
		{100, true}, // Second marker boundary
		{101, false},
		{150, false},
		{199, false},
		{200, true}, // Third marker boundary
		{201, false},
		{300, true},
		{1000, true},
		{1001, false},
		{10000, true},
	}

	for _, tt := range tests {
		result := isAtMarkerBoundary(tt.depth)
		require.Equal(t, tt.expected, result,
			"isAtMarkerBoundary(%d) should be %v", tt.depth, tt.expected)
	}
}

func TestMarkerInterval(t *testing.T) {
	require.Equal(t, uint32(100), uint32(MarkerInterval))
}

func TestMarkerStruct(t *testing.T) {
	marker := Marker{
		ID:              "test-marker-id",
		Depth:           100,
		ParentMarkerIDs: []string{"parent-marker-1", "parent-marker-2"},
	}

	require.Equal(t, "test-marker-id", marker.ID)
	require.Equal(t, uint32(100), marker.Depth)
	require.Len(t, marker.ParentMarkerIDs, 2)
	require.Contains(t, marker.ParentMarkerIDs, "parent-marker-1")
	require.Contains(t, marker.ParentMarkerIDs, "parent-marker-2")
}

func TestSweptMarkerStruct(t *testing.T) {
	sweptMarker := SweptMarker{
		MarkerID: "swept-marker-id",
		SweptAt:  1234567890,
	}

	require.Equal(t, "swept-marker-id", sweptMarker.MarkerID)
	require.Equal(t, int64(1234567890), sweptMarker.SweptAt)
}

func TestRootMarkerHasNoParents(t *testing.T) {
	rootMarker := Marker{
		ID:              "root-marker",
		Depth:           0,
		ParentMarkerIDs: nil,
	}

	require.True(t, isAtMarkerBoundary(rootMarker.Depth))
	require.Nil(t, rootMarker.ParentMarkerIDs)
}

func TestNewMarker(t *testing.T) {
	t.Run("at boundary creates marker", func(t *testing.T) {
		parentIDs := []string{"parent-A", "parent-B"}
		marker, markerIDs := NewMarker("txid123", 100, parentIDs)

		require.NotNil(t, marker)
		require.Equal(t, "txid123:marker:100", marker.ID)
		require.Equal(t, uint32(100), marker.Depth)
		require.Equal(t, parentIDs, marker.ParentMarkerIDs)
		require.Equal(t, []string{"txid123:marker:100"}, markerIDs)
	})

	t.Run("at depth 0 creates root marker", func(t *testing.T) {
		marker, markerIDs := NewMarker("txid-root", 0, nil)

		require.NotNil(t, marker)
		require.Equal(t, "txid-root:marker:0", marker.ID)
		require.Equal(t, uint32(0), marker.Depth)
		require.Nil(t, marker.ParentMarkerIDs)
		require.Equal(t, []string{"txid-root:marker:0"}, markerIDs)
	})

	t.Run("non-boundary inherits parent markers", func(t *testing.T) {
		parentIDs := []string{"marker-A", "marker-B"}
		marker, markerIDs := NewMarker("txid456", 51, parentIDs)

		require.Nil(t, marker)
		require.Equal(t, parentIDs, markerIDs)
	})

	t.Run("non-boundary no parents returns nil", func(t *testing.T) {
		marker, markerIDs := NewMarker("txid789", 5, nil)

		require.Nil(t, marker)
		require.Nil(t, markerIDs)
	})

	t.Run("at depth 200 with parents", func(t *testing.T) {
		parentIDs := []string{"marker-100"}
		marker, markerIDs := NewMarker("deep-tx", 200, parentIDs)

		require.NotNil(t, marker)
		require.Equal(t, "deep-tx:marker:200", marker.ID)
		require.Equal(t, uint32(200), marker.Depth)
		require.Equal(t, parentIDs, marker.ParentMarkerIDs)
		require.Len(t, markerIDs, 1)
		require.Equal(t, marker.ID, markerIDs[0])
	})
}

// calculateMaxDepth returns the maximum depth from a set of spent VTXOs.
func calculateMaxDepth(spentVtxos []Vtxo) uint32 {
	var maxDepth uint32
	for _, v := range spentVtxos {
		if v.Depth > maxDepth {
			maxDepth = v.Depth
		}
	}
	return maxDepth
}

// collectParentMarkers collects all unique, non-empty marker IDs from spent VTXOs.
func collectParentMarkers(spentVtxos []Vtxo) []string {
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

func TestDepthCalculation(t *testing.T) {
	testCases := []struct {
		name          string
		spentVtxos    []Vtxo
		expectedDepth uint32
		description   string
	}{
		{
			name:          "single batch vtxo at depth 0",
			spentVtxos:    []Vtxo{{Depth: 0}},
			expectedDepth: 1,
			description:   "spending a batch vtxo creates vtxo at depth 1",
		},
		{
			name:          "single vtxo at depth 50",
			spentVtxos:    []Vtxo{{Depth: 50}},
			expectedDepth: 51,
			description:   "spending a chained vtxo increments depth",
		},
		{
			name: "multiple vtxos with same depth",
			spentVtxos: []Vtxo{
				{Depth: 10},
				{Depth: 10},
				{Depth: 10},
			},
			expectedDepth: 11,
			description:   "combining vtxos at same depth increments once",
		},
		{
			name: "multiple vtxos with different depths",
			spentVtxos: []Vtxo{
				{Depth: 5},
				{Depth: 25},
				{Depth: 15},
			},
			expectedDepth: 26,
			description:   "uses max depth from inputs",
		},
		{
			name: "vtxos spanning marker boundary",
			spentVtxos: []Vtxo{
				{Depth: 95},
				{Depth: 105},
			},
			expectedDepth: 106,
			description:   "handles depths across marker boundaries",
		},
		{
			name: "deep chain near marker boundary",
			spentVtxos: []Vtxo{
				{Depth: 99},
			},
			expectedDepth: 100,
			description:   "result at marker boundary (100)",
		},
		{
			name: "very deep chain",
			spentVtxos: []Vtxo{
				{Depth: 500},
			},
			expectedDepth: 501,
			description:   "handles deep chains beyond multiple marker intervals",
		},
		{
			name:          "no spent vtxos (empty)",
			spentVtxos:    []Vtxo{},
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
			require.Equal(t, tc.isAtBoundary, isAtMarkerBoundary(tc.depth))
		})
	}
}

func TestDepthIncrementCreatesMarkerAtBoundary(t *testing.T) {
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
			spentVtxos := []Vtxo{{Depth: tc.parentDepth}}
			maxDepth := calculateMaxDepth(spentVtxos)
			newDepth := maxDepth + 1

			require.Equal(t, tc.newDepth, newDepth)
			marker, _ := NewMarker("test-txid", newDepth, nil)
			require.Equal(t, tc.shouldCreateMarker, marker != nil)
		})
	}
}

func TestParentMarkerCollectionFromMultipleParents(t *testing.T) {
	testCases := []struct {
		name            string
		spentVtxos      []Vtxo
		expectedMarkers []string
	}{
		{
			name: "single parent with one marker",
			spentVtxos: []Vtxo{
				{MarkerIDs: []string{"marker-A"}},
			},
			expectedMarkers: []string{"marker-A"},
		},
		{
			name: "two parents with distinct markers",
			spentVtxos: []Vtxo{
				{MarkerIDs: []string{"marker-A"}},
				{MarkerIDs: []string{"marker-B"}},
			},
			expectedMarkers: []string{"marker-A", "marker-B"},
		},
		{
			name: "three parents with overlapping markers",
			spentVtxos: []Vtxo{
				{MarkerIDs: []string{"marker-A", "marker-B"}},
				{MarkerIDs: []string{"marker-B", "marker-C"}},
				{MarkerIDs: []string{"marker-A", "marker-C"}},
			},
			expectedMarkers: []string{"marker-A", "marker-B", "marker-C"},
		},
		{
			name: "all parents share the same marker",
			spentVtxos: []Vtxo{
				{MarkerIDs: []string{"root-marker"}},
				{MarkerIDs: []string{"root-marker"}},
				{MarkerIDs: []string{"root-marker"}},
			},
			expectedMarkers: []string{"root-marker"},
		},
		{
			name:            "no parents",
			spentVtxos:      []Vtxo{},
			expectedMarkers: []string{},
		},
		{
			name: "parent with no markers",
			spentVtxos: []Vtxo{
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
	spentVtxos := []Vtxo{
		{MarkerIDs: []string{"marker-A", "", "marker-B"}},
		{MarkerIDs: []string{"", ""}},
		{MarkerIDs: []string{"marker-C", ""}},
	}

	result := collectParentMarkers(spentVtxos)
	sort.Strings(result)
	require.Equal(t, []string{"marker-A", "marker-B", "marker-C"}, result)
}

func TestMarkerInheritanceAtNonBoundary(t *testing.T) {
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
			spentVtxos := make([]Vtxo, len(tc.parentDepths))
			for i, depth := range tc.parentDepths {
				spentVtxos[i] = Vtxo{
					Depth:     depth,
					MarkerIDs: tc.parentMarkerSets[i],
				}
			}

			maxDepth := calculateMaxDepth(spentVtxos)
			newDepth := maxDepth + 1
			require.Equal(t, tc.expectedDepth, newDepth)

			require.False(t, isAtMarkerBoundary(newDepth),
				"depth %d should not be at marker boundary for this test", newDepth)

			parentMarkers := collectParentMarkers(spentVtxos)
			marker, markerIDs := NewMarker("some-txid", newDepth, parentMarkers)

			require.Nil(t, marker, tc.description)
			sort.Strings(markerIDs)
			sort.Strings(tc.expectedMarkers)
			require.Equal(t, tc.expectedMarkers, markerIDs, tc.description)
		})
	}
}

func TestMarkerCreationAtBoundary(t *testing.T) {
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
			spentVtxos := make([]Vtxo, len(tc.parentDepths))
			for i, depth := range tc.parentDepths {
				spentVtxos[i] = Vtxo{
					Depth:     depth,
					MarkerIDs: tc.parentMarkerSets[i],
				}
			}

			maxDepth := calculateMaxDepth(spentVtxos)
			newDepth := maxDepth + 1
			require.Equal(t, tc.expectedDepth, newDepth)

			require.True(t, isAtMarkerBoundary(newDepth),
				"depth %d should be at marker boundary for this test", newDepth)

			parentMarkers := collectParentMarkers(spentVtxos)
			createdMarker, markerIDs := NewMarker("test-txid", newDepth, parentMarkers)

			require.NotNil(t, createdMarker, tc.description)
			require.Equal(t, newDepth, createdMarker.Depth)
			sort.Strings(createdMarker.ParentMarkerIDs)
			sort.Strings(parentMarkers)
			require.Equal(t, parentMarkers, createdMarker.ParentMarkerIDs)
			require.Len(t, markerIDs, 1)
			require.Equal(t, createdMarker.ID, markerIDs[0])
		})
	}
}

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
			spentVtxos := make([]Vtxo, len(tc.parentDepths))
			for i, depth := range tc.parentDepths {
				spentVtxos[i] = Vtxo{
					Depth:     depth,
					MarkerIDs: tc.parentMarkerSets[i],
				}
			}

			maxDepth := calculateMaxDepth(spentVtxos)
			newDepth := maxDepth + 1
			require.Equal(t, tc.expectedDepth, newDepth)

			parentMarkers := collectParentMarkers(spentVtxos)
			_, markerIDs := NewMarker("tx-with-multiple-outputs", newDepth, parentMarkers)

			// Simulate creating multiple output VTXOs — each gets the same depth and markers
			outputs := make([]Vtxo, tc.numOutputVtxos)
			for i := 0; i < tc.numOutputVtxos; i++ {
				outputs[i] = Vtxo{
					Outpoint:  Outpoint{Txid: "tx-with-multiple-outputs", VOut: uint32(i)},
					Depth:     newDepth,
					MarkerIDs: markerIDs,
				}
			}

			for i, v := range outputs {
				require.Equal(t, tc.expectedDepth, v.Depth,
					"output %d has wrong depth", i)
			}

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

func TestDepth20k_MarkerBoundaryAndInheritance(t *testing.T) {
	t.Run("depth 19999 inherits markers, depth 20000 creates new marker", func(t *testing.T) {
		parent := Vtxo{Depth: 19999, MarkerIDs: []string{"marker-19900"}}
		parentMarkers := collectParentMarkers([]Vtxo{parent})

		newDepth := calculateMaxDepth([]Vtxo{parent}) + 1
		require.Equal(t, uint32(20000), newDepth)
		require.True(t, isAtMarkerBoundary(newDepth))

		createdMarker, markerIDs := NewMarker("tx-at-20k", newDepth, parentMarkers)
		require.NotNil(t, createdMarker, "marker should be created at depth 20000")
		require.Equal(t, uint32(20000), createdMarker.Depth)
		require.Equal(t, []string{"marker-19900"}, createdMarker.ParentMarkerIDs)
		require.Len(t, markerIDs, 1)
		require.Equal(t, createdMarker.ID, markerIDs[0])
	})

	t.Run("depth 20001 inherits markers from boundary parent", func(t *testing.T) {
		parent := Vtxo{Depth: 20000, MarkerIDs: []string{"marker-20000"}}
		parentMarkers := collectParentMarkers([]Vtxo{parent})

		newDepth := calculateMaxDepth([]Vtxo{parent}) + 1
		require.Equal(t, uint32(20001), newDepth)
		require.False(t, isAtMarkerBoundary(newDepth))

		createdMarker, markerIDs := NewMarker("tx-at-20001", newDepth, parentMarkers)
		require.Nil(t, createdMarker, "no marker at non-boundary depth")
		require.Equal(t, []string{"marker-20000"}, markerIDs)
	})

	t.Run("VTXO with 200 inherited markers from deep chain", func(t *testing.T) {
		markers := make([]string, 200)
		for i := range markers {
			markers[i] = fmt.Sprintf("marker-%d", i*100)
		}

		parent := Vtxo{Depth: 19950, MarkerIDs: markers}
		collected := collectParentMarkers([]Vtxo{parent})
		sort.Strings(collected)
		sort.Strings(markers)
		require.Equal(t, markers, collected, "all 200 markers should be collected")
	})

	t.Run("multiple deep parents merge 200+ markers correctly", func(t *testing.T) {
		markersA := make([]string, 100)
		markersB := make([]string, 150)
		for i := range markersA {
			markersA[i] = fmt.Sprintf("marker-%d", i*100)
		}
		for i := range markersB {
			markersB[i] = fmt.Sprintf("marker-%d", i*100)
		}

		parents := []Vtxo{
			{Depth: 10000, MarkerIDs: markersA},
			{Depth: 15000, MarkerIDs: markersB},
		}
		collected := collectParentMarkers(parents)

		require.Len(t, collected, 150)

		newDepth := calculateMaxDepth(parents) + 1
		require.Equal(t, uint32(15001), newDepth)
		require.False(t, isAtMarkerBoundary(newDepth))

		createdMarker, markerIDs := NewMarker("merge-tx", newDepth, collected)
		require.Nil(t, createdMarker)
		require.Len(t, markerIDs, 150, "child inherits all 150 unique markers")
	})

	t.Run("depth beyond 20k target remains valid", func(t *testing.T) {
		parent := Vtxo{Depth: 20000, MarkerIDs: []string{"marker-20000"}}
		newDepth := calculateMaxDepth([]Vtxo{parent}) + 1
		require.Equal(t, uint32(20001), newDepth)

		require.True(t, isAtMarkerBoundary(20100))
		require.True(t, isAtMarkerBoundary(20200))
		require.False(t, isAtMarkerBoundary(20001))
		require.False(t, isAtMarkerBoundary(20099))
	})
}
