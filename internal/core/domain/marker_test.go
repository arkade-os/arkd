package domain

import (
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
		result := IsAtMarkerBoundary(tt.depth)
		require.Equal(t, tt.expected, result,
			"IsAtMarkerBoundary(%d) should be %v", tt.depth, tt.expected)
	}
}

func TestMarkerInterval(t *testing.T) {
	// Verify the constant is set correctly
	require.Equal(t, uint32(100), uint32(MarkerInterval))
}

func TestMarkerStruct(t *testing.T) {
	// Test Marker struct creation
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
	// Test SweptMarker struct creation
	sweptMarker := SweptMarker{
		MarkerID: "swept-marker-id",
		SweptAt:  1234567890,
	}

	require.Equal(t, "swept-marker-id", sweptMarker.MarkerID)
	require.Equal(t, int64(1234567890), sweptMarker.SweptAt)
}

func TestRootMarkerHasNoParents(t *testing.T) {
	// Root markers (depth 0) should have no parent markers
	rootMarker := Marker{
		ID:              "root-marker",
		Depth:           0,
		ParentMarkerIDs: nil,
	}

	require.True(t, IsAtMarkerBoundary(rootMarker.Depth))
	require.Nil(t, rootMarker.ParentMarkerIDs)
}
