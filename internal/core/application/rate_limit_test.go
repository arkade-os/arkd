package application

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/stretchr/testify/require"
)

type mockMarkerRepoForRateLimit struct {
	domain.MarkerRepository
	markers map[string]domain.Marker
}

func (m *mockMarkerRepoForRateLimit) GetMarkersByIds(
	_ context.Context, ids []string,
) ([]domain.Marker, error) {
	result := make([]domain.Marker, 0, len(ids))
	for _, id := range ids {
		if marker, ok := m.markers[id]; ok {
			result = append(result, marker)
		}
	}
	return result, nil
}

type mockRepoManagerForRateLimit struct {
	markerRepo *mockMarkerRepoForRateLimit
}

func (m *mockRepoManagerForRateLimit) Markers() domain.MarkerRepository {
	return m.markerRepo
}

// Stub all other RepoManager methods to satisfy the interface
func (m *mockRepoManagerForRateLimit) Events() domain.EventRepository            { return nil }
func (m *mockRepoManagerForRateLimit) Rounds() domain.RoundRepository            { return nil }
func (m *mockRepoManagerForRateLimit) Vtxos() domain.VtxoRepository              { return nil }
func (m *mockRepoManagerForRateLimit) ScheduledSession() domain.ScheduledSessionRepo { return nil }
func (m *mockRepoManagerForRateLimit) OffchainTxs() domain.OffchainTxRepository  { return nil }
func (m *mockRepoManagerForRateLimit) Convictions() domain.ConvictionRepository  { return nil }
func (m *mockRepoManagerForRateLimit) Assets() domain.AssetRepository            { return nil }
func (m *mockRepoManagerForRateLimit) Fees() domain.FeeRepository                { return nil }
func (m *mockRepoManagerForRateLimit) Close()                                    {}

func TestCheckRateLimit(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		name                 string
		rateLimitEnabled     bool
		rateLimitMaxVelocity float64
		rateLimitMaxCooldown int64
		vtxos                []domain.Vtxo
		markers              map[string]domain.Marker
		expectError          bool
		expectCode           uint16
		expectInputCount     int
	}{
		{
			name:                 "disabled rate limiting skips check",
			rateLimitEnabled:     false,
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxos: []domain.Vtxo{
				{
					Outpoint:  domain.Outpoint{Txid: "tx1", VOut: 0},
					Depth:     200,
					MarkerIDs: []string{"m1"},
				},
			},
			markers: map[string]domain.Marker{
				"m1": {ID: "m1", Depth: 100, CreatedAt: now - 100},
			},
			expectError: false,
		},
		{
			name:                 "vtxo with no markers is skipped",
			rateLimitEnabled:     true,
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxos: []domain.Vtxo{
				{
					Outpoint:  domain.Outpoint{Txid: "tx1", VOut: 0},
					Depth:     50,
					MarkerIDs: nil,
				},
			},
			markers:     map[string]domain.Marker{},
			expectError: false,
		},
		{
			name:                 "high velocity rejected (depth 200, marker at 100, 100s ago = velocity 1.0)",
			rateLimitEnabled:     true,
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxos: []domain.Vtxo{
				{
					Outpoint:  domain.Outpoint{Txid: "tx1", VOut: 0},
					Depth:     200,
					MarkerIDs: []string{"m1"},
				},
			},
			markers: map[string]domain.Marker{
				"m1": {ID: "m1", Depth: 100, CreatedAt: now - 100},
			},
			expectError:      true,
			expectCode:       48,
			expectInputCount: 1,
		},
		{
			name:                 "low velocity allowed (depth 200, marker at 100, 1000s ago = velocity 0.1)",
			rateLimitEnabled:     true,
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxos: []domain.Vtxo{
				{
					Outpoint:  domain.Outpoint{Txid: "tx1", VOut: 0},
					Depth:     200,
					MarkerIDs: []string{"m1"},
				},
			},
			markers: map[string]domain.Marker{
				"m1": {ID: "m1", Depth: 100, CreatedAt: now - 1000},
			},
			expectError: false,
		},
		{
			name:                 "vtxo depth <= marker depth is skipped",
			rateLimitEnabled:     true,
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxos: []domain.Vtxo{
				{
					Outpoint:  domain.Outpoint{Txid: "tx1", VOut: 0},
					Depth:     50,
					MarkerIDs: []string{"m1"},
				},
			},
			markers: map[string]domain.Marker{
				"m1": {ID: "m1", Depth: 100, CreatedAt: now - 10},
			},
			expectError: false,
		},
		{
			name:                 "multiple inputs, one rate-limited, all rejected",
			rateLimitEnabled:     true,
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxos: []domain.Vtxo{
				{
					Outpoint:  domain.Outpoint{Txid: "tx1", VOut: 0},
					Depth:     200,
					MarkerIDs: []string{"m1"},
				},
				{
					Outpoint:  domain.Outpoint{Txid: "tx2", VOut: 0},
					Depth:     110,
					MarkerIDs: []string{"m2"},
				},
			},
			markers: map[string]domain.Marker{
				"m1": {ID: "m1", Depth: 100, CreatedAt: now - 100},
				"m2": {ID: "m2", Depth: 100, CreatedAt: now - 1000},
			},
			expectError:      true,
			expectCode:       48,
			expectInputCount: 1, // only tx1 is rate limited
		},
		{
			name:                 "cooldown capped at max_cooldown_secs",
			rateLimitEnabled:     true,
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 100,
			vtxos: []domain.Vtxo{
				{
					Outpoint:  domain.Outpoint{Txid: "tx1", VOut: 0},
					Depth:     200,
					MarkerIDs: []string{"m1"},
				},
			},
			markers: map[string]domain.Marker{
				// velocity = 100/1 = 100.0, cooldown = 100/0.28 - 1 ≈ 356 > 100
				"m1": {ID: "m1", Depth: 100, CreatedAt: now - 1},
			},
			expectError:      true,
			expectCode:       48,
			expectInputCount: 1,
		},
		{
			name:                 "youngest marker used when multiple markers",
			rateLimitEnabled:     true,
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxos: []domain.Vtxo{
				{
					Outpoint:  domain.Outpoint{Txid: "tx1", VOut: 0},
					Depth:     300,
					MarkerIDs: []string{"m1", "m2"},
				},
			},
			markers: map[string]domain.Marker{
				"m1": {ID: "m1", Depth: 100, CreatedAt: now - 1000},
				"m2": {ID: "m2", Depth: 200, CreatedAt: now - 500},
			},
			// youngest marker is m2 at depth 200
			// depthDelta = 300 - 200 = 100, timeDelta = 500
			// velocity = 100/500 = 0.2 < 0.28 -> allowed
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &service{
				rateLimitEnabled:         tt.rateLimitEnabled,
				rateLimitMaxVelocity:     tt.rateLimitMaxVelocity,
				rateLimitMaxCooldownSecs: tt.rateLimitMaxCooldown,
				repoManager: &mockRepoManagerForRateLimit{
					markerRepo: &mockMarkerRepoForRateLimit{
						markers: tt.markers,
					},
				},
			}

			err := svc.checkRateLimit(context.Background(), tt.vtxos)

			if !tt.expectError {
				require.Nil(t, err)
				return
			}

			require.NotNil(t, err)
			require.Equal(t, tt.expectCode, err.Code())

			metadata := err.Metadata()
			if tt.expectInputCount > 0 {
				require.Contains(t, metadata, "inputs")
			}
		})
	}
}

// TestCheckRateLimitDeepChains tests rate limiting across realistic deep chain
// topologies with markers placed at every MarkerInterval (100) boundary, matching
// the real marker creation logic in updateProjectionsAfterOffchainTxEvents.
func TestCheckRateLimitDeepChains(t *testing.T) {
	now := time.Now().Unix()

	// Helper: build a linear marker chain from depth 0 to maxDepth at MarkerInterval
	// boundaries. Each marker's CreatedAt is baseTime + (depth * secsPerDepth),
	// simulating a chain that grows at a steady rate.
	buildMarkerChain := func(maxDepth uint32, baseTime int64, secsPerDepth float64) map[string]domain.Marker {
		markers := make(map[string]domain.Marker)
		for d := uint32(0); d <= maxDepth; d += domain.MarkerInterval {
			id := fmt.Sprintf("m-%d", d)
			var parents []string
			if d > 0 {
				parents = []string{fmt.Sprintf("m-%d", d-domain.MarkerInterval)}
			}
			markers[id] = domain.Marker{
				ID:              id,
				Depth:           d,
				ParentMarkerIDs: parents,
				CreatedAt:       baseTime + int64(float64(d)*secsPerDepth),
			}
		}
		return markers
	}

	// Helper: for a VTXO at a given depth, return the marker IDs it would have.
	// At a boundary: the marker at that depth. Otherwise: the marker at the
	// nearest boundary below.
	markerIDsForDepth := func(depth uint32) []string {
		if domain.IsAtMarkerBoundary(depth) {
			return []string{fmt.Sprintf("m-%d", depth)}
		}
		nearestBoundary := (depth / domain.MarkerInterval) * domain.MarkerInterval
		return []string{fmt.Sprintf("m-%d", nearestBoundary)}
	}

	tests := []struct {
		name                 string
		rateLimitMaxVelocity float64
		rateLimitMaxCooldown int64
		vtxoDepth            uint32
		markers              map[string]domain.Marker
		expectError          bool
		description          string
	}{
		{
			name:                 "deep chain at depth 500, fast growth rejected",
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxoDepth:            550,
			// Chain grew from 0 to 500 markers over 500s (1 depth/sec).
			// Youngest marker at 500, created at now-50.
			// depthDelta = 550-500 = 50, timeDelta = 50, velocity = 1.0 > 0.28.
			markers:     buildMarkerChain(500, now-500, 1.0),
			expectError: true,
			description: "50 depths in 50s = velocity 1.0",
		},
		{
			name:                 "deep chain at depth 500, slow growth allowed",
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxoDepth:            550,
			// Chain grew slowly: 1 depth every 5 seconds.
			// Youngest marker at 500, created at now-250 (50 depths ago * 5 sec).
			// depthDelta = 50, timeDelta = 250, velocity = 0.2 < 0.28.
			markers:     buildMarkerChain(500, now-2750, 5.0),
			expectError: false,
			description: "50 depths in 250s = velocity 0.2",
		},
		{
			name:                 "very deep chain at depth 5000, burst rejected",
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxoDepth:            5050,
			// Markers up to 5000. Last marker created 30s ago.
			// depthDelta = 50, timeDelta = 30, velocity = 1.67 > 0.28.
			markers: buildMarkerChain(5000, now-50000, 10.0),
			// Override the last marker to make it recent (simulating burst)
			expectError: true,
			description: "burst after slow growth: 50 depths in 30s = velocity 1.67",
		},
		{
			name:                 "very deep chain at depth 5000, steady allowed",
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxoDepth:            5050,
			// Markers up to 5000 growing at 4 sec/depth.
			// Youngest marker at 5000, created at now-200 (50 depths ago * 4).
			// depthDelta = 50, timeDelta = 200, velocity = 0.25 < 0.28.
			markers:     buildMarkerChain(5000, now-20200, 4.0),
			expectError: false,
			description: "50 depths in 200s = velocity 0.25",
		},
		{
			name:                 "max depth 20000, boundary VTXO uses own marker",
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxoDepth:            20000,
			// At boundary: VTXO references marker at depth 20000.
			// Youngest marker IS the VTXO's own marker.
			// depthDelta = 20000 - 20000 = 0 → skipped (depth <= marker depth).
			markers:     buildMarkerChain(20000, now-100000, 5.0),
			expectError: false,
			description: "VTXO at boundary references its own marker, delta=0",
		},
		{
			name:                 "max depth 20000, one past boundary rejected on burst",
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxoDepth:            20001,
			// VTXO at 20001 references marker at 20000 (nearest boundary below).
			// If marker was created 1s ago: depthDelta=1, timeDelta=1, velocity=1.0.
			markers: func() map[string]domain.Marker {
				m := buildMarkerChain(20000, now-200000, 10.0)
				// Override the last marker to be very recent
				m["m-20000"] = domain.Marker{
					ID: "m-20000", Depth: 20000,
					ParentMarkerIDs: []string{"m-19900"},
					CreatedAt:       now - 1,
				}
				return m
			}(),
			expectError: true,
			description: "1 depth in 1s = velocity 1.0 at max depth",
		},
		{
			name:                 "chain across multiple boundaries, uses youngest marker",
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxoDepth:            1050,
			// VTXO at depth 1050 inherits marker from boundary 1000.
			// Youngest marker at 1000, created 360s ago.
			// depthDelta = 50, timeDelta = 360, velocity = 0.139 < 0.28.
			markers:     buildMarkerChain(1000, now-10360, 10.0),
			expectError: false,
			description: "50 depths in 360s = velocity 0.139",
		},
		{
			name:                 "just at velocity threshold allowed",
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxoDepth:            550,
			// depthDelta = 50, need timeDelta >= 50/0.28 = 178.57s.
			// Set marker at 500 created 179s ago → velocity = 50/179 = 0.2793 < 0.28.
			markers: func() map[string]domain.Marker {
				m := buildMarkerChain(500, now-5179, 10.0)
				m["m-500"] = domain.Marker{
					ID: "m-500", Depth: 500,
					ParentMarkerIDs: []string{"m-400"},
					CreatedAt:       now - 179,
				}
				return m
			}(),
			expectError: false,
			description: "velocity 0.2793 just under 0.28 threshold",
		},
		{
			name:                 "just over velocity threshold rejected",
			rateLimitMaxVelocity: 0.28,
			rateLimitMaxCooldown: 3600,
			vtxoDepth:            550,
			// depthDelta = 50, timeDelta = 177 → velocity = 50/177 = 0.2825 > 0.28.
			markers: func() map[string]domain.Marker {
				m := buildMarkerChain(500, now-5177, 10.0)
				m["m-500"] = domain.Marker{
					ID: "m-500", Depth: 500,
					ParentMarkerIDs: []string{"m-400"},
					CreatedAt:       now - 177,
				}
				return m
			}(),
			expectError: true,
			description: "velocity 0.2825 just over 0.28 threshold",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &service{
				rateLimitEnabled:         true,
				rateLimitMaxVelocity:     tt.rateLimitMaxVelocity,
				rateLimitMaxCooldownSecs: tt.rateLimitMaxCooldown,
				repoManager: &mockRepoManagerForRateLimit{
					markerRepo: &mockMarkerRepoForRateLimit{
						markers: tt.markers,
					},
				},
			}

			vtxos := []domain.Vtxo{
				{
					Outpoint:  domain.Outpoint{Txid: "deep-tx", VOut: 0},
					Depth:     tt.vtxoDepth,
					MarkerIDs: markerIDsForDepth(tt.vtxoDepth),
				},
			}

			err := svc.checkRateLimit(context.Background(), vtxos)

			if !tt.expectError {
				require.Nil(t, err, "expected no rate limit for: %s", tt.description)
				return
			}

			require.NotNil(t, err, "expected rate limit for: %s", tt.description)
			require.Equal(t, uint16(48), err.Code())
		})
	}
}

// TestCheckRateLimitMergedMarkerChains tests rate limiting when VTXOs inherit
// markers from multiple parent chains (DAG merge scenario). When two chains
// merge, the child VTXO's MarkerIDs is the union of all parent markers. The
// rate limiter should pick the youngest (highest depth) marker from the set.
func TestCheckRateLimitMergedMarkerChains(t *testing.T) {
	now := time.Now().Unix()

	t.Run("youngest marker at higher depth used for velocity calc", func(t *testing.T) {
		// Chain A reached depth 100, chain B reached depth 200.
		// They merge: child at depth 301 has MarkerIDs = [mA-100, mB-200].
		// Rate limiter picks mB-200 (highest depth).
		// depthDelta = 301-200 = 101, timeDelta = 500, velocity = 0.202 < 0.28 → allowed.
		markers := map[string]domain.Marker{
			"mA-100": {ID: "mA-100", Depth: 100, CreatedAt: now - 2000},
			"mB-200": {ID: "mB-200", Depth: 200, CreatedAt: now - 500},
		}

		svc := &service{
			rateLimitEnabled:         true,
			rateLimitMaxVelocity:     0.28,
			rateLimitMaxCooldownSecs: 3600,
			repoManager: &mockRepoManagerForRateLimit{
				markerRepo: &mockMarkerRepoForRateLimit{markers: markers},
			},
		}

		vtxo := domain.Vtxo{
			Outpoint:  domain.Outpoint{Txid: "merge-tx", VOut: 0},
			Depth:     301,
			MarkerIDs: []string{"mA-100", "mB-200"},
		}

		err := svc.checkRateLimit(context.Background(), []domain.Vtxo{vtxo})
		require.Nil(t, err, "velocity 0.202 < 0.28, should be allowed")
	})

	t.Run("older marker ignored even if it would trigger limit", func(t *testing.T) {
		// Chain A has marker at depth 100 (very old, low velocity against it).
		// Chain B has marker at depth 300 (recent, high velocity from it).
		// Child at depth 350 with markers [mA-100, mB-300].
		// Rate limiter picks mB-300 (highest depth).
		// depthDelta = 350-300 = 50, timeDelta = 10, velocity = 5.0 > 0.28 → rejected.
		// If it had used mA-100: depthDelta = 250, timeDelta = 5000, velocity = 0.05 → allowed.
		markers := map[string]domain.Marker{
			"mA-100": {ID: "mA-100", Depth: 100, CreatedAt: now - 5000},
			"mB-300": {ID: "mB-300", Depth: 300, CreatedAt: now - 10},
		}

		svc := &service{
			rateLimitEnabled:         true,
			rateLimitMaxVelocity:     0.28,
			rateLimitMaxCooldownSecs: 3600,
			repoManager: &mockRepoManagerForRateLimit{
				markerRepo: &mockMarkerRepoForRateLimit{markers: markers},
			},
		}

		vtxo := domain.Vtxo{
			Outpoint:  domain.Outpoint{Txid: "merge-tx2", VOut: 0},
			Depth:     350,
			MarkerIDs: []string{"mA-100", "mB-300"},
		}

		err := svc.checkRateLimit(context.Background(), []domain.Vtxo{vtxo})
		require.NotNil(t, err, "youngest marker (depth 300) gives velocity 5.0, should be rejected")
		require.Equal(t, uint16(48), err.Code())
	})

	t.Run("three chains merge, deepest marker determines velocity", func(t *testing.T) {
		// Three chains with markers at depths 100, 200, 500.
		// Child at depth 510 inherits all three.
		// Youngest = depth 500, created 1000s ago.
		// depthDelta = 10, timeDelta = 1000, velocity = 0.01 < 0.28 → allowed.
		markers := map[string]domain.Marker{
			"m-100": {ID: "m-100", Depth: 100, CreatedAt: now - 5000},
			"m-200": {ID: "m-200", Depth: 200, CreatedAt: now - 3000},
			"m-500": {ID: "m-500", Depth: 500, CreatedAt: now - 1000},
		}

		svc := &service{
			rateLimitEnabled:         true,
			rateLimitMaxVelocity:     0.28,
			rateLimitMaxCooldownSecs: 3600,
			repoManager: &mockRepoManagerForRateLimit{
				markerRepo: &mockMarkerRepoForRateLimit{markers: markers},
			},
		}

		vtxo := domain.Vtxo{
			Outpoint:  domain.Outpoint{Txid: "merge-tx3", VOut: 0},
			Depth:     510,
			MarkerIDs: []string{"m-100", "m-200", "m-500"},
		}

		err := svc.checkRateLimit(context.Background(), []domain.Vtxo{vtxo})
		require.Nil(t, err, "velocity 0.01 < 0.28, should be allowed")
	})
}

// TestCheckRateLimitCooldownComputation verifies that rate limiting triggers
// correctly at various depths and that the cooldown cap is applied at extreme depths.
func TestCheckRateLimitCooldownComputation(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		name             string
		vtxoDepth        uint32
		markerDepth      uint32
		markerCreatedAgo int64 // seconds ago
		maxVelocity      float64
		maxCooldown      int64
		expectRejected   bool
	}{
		{
			name:             "depth 550, marker at 500, 10s ago: velocity 5.0 rejected",
			vtxoDepth:        550,
			markerDepth:      500,
			markerCreatedAgo: 10,
			maxVelocity:      0.28,
			maxCooldown:      3600,
			// depthDelta=50, timeDelta=10, velocity=5.0 > 0.28
			expectRejected: true,
		},
		{
			name:             "depth 10050, marker at 10000, 500s ago: velocity 0.1 allowed",
			vtxoDepth:        10050,
			markerDepth:      10000,
			markerCreatedAgo: 500,
			maxVelocity:      0.28,
			maxCooldown:      3600,
			// depthDelta=50, timeDelta=500, velocity=0.1 < 0.28
			expectRejected: false,
		},
		{
			name:             "depth 20099, marker at 20000, 1s ago: extreme burst rejected",
			vtxoDepth:        20099,
			markerDepth:      20000,
			markerCreatedAgo: 1,
			maxVelocity:      0.28,
			maxCooldown:      3600,
			// depthDelta=99, timeDelta=1, velocity=99.0 >> 0.28
			expectRejected: true,
		},
		{
			name:             "depth 5099, marker at 0, 10s ago: huge delta rejected",
			vtxoDepth:        5099,
			markerDepth:      0,
			markerCreatedAgo: 10,
			maxVelocity:      0.28,
			maxCooldown:      3600,
			// depthDelta=5099, timeDelta=10, velocity=509.9 >> 0.28
			expectRejected: true,
		},
		{
			name:             "depth 5099, marker at 0, old enough: allowed",
			vtxoDepth:        5099,
			markerDepth:      0,
			markerCreatedAgo: 20000,
			maxVelocity:      0.28,
			maxCooldown:      3600,
			// depthDelta=5099, timeDelta=20000, velocity=0.255 < 0.28
			expectRejected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			markerID := fmt.Sprintf("m-%d", tt.markerDepth)
			svc := &service{
				rateLimitEnabled:         true,
				rateLimitMaxVelocity:     tt.maxVelocity,
				rateLimitMaxCooldownSecs: tt.maxCooldown,
				repoManager: &mockRepoManagerForRateLimit{
					markerRepo: &mockMarkerRepoForRateLimit{
						markers: map[string]domain.Marker{
							markerID: {
								ID:        markerID,
								Depth:     tt.markerDepth,
								CreatedAt: now - tt.markerCreatedAgo,
							},
						},
					},
				},
			}

			vtxos := []domain.Vtxo{
				{
					Outpoint:  domain.Outpoint{Txid: "cooldown-tx", VOut: 0},
					Depth:     tt.vtxoDepth,
					MarkerIDs: []string{markerID},
				},
			}

			err := svc.checkRateLimit(context.Background(), vtxos)

			if !tt.expectRejected {
				require.Nil(t, err)
				return
			}

			require.NotNil(t, err)
			require.Equal(t, uint16(48), err.Code())

			var rateLimitErr errors.TypedError[errors.RateLimitMetadata]
			require.ErrorAs(t, err, &rateLimitErr)

			metadata := err.Metadata()
			require.Contains(t, metadata, "inputs")
		})
	}
}

func TestCheckRateLimitCooldownCap(t *testing.T) {
	now := time.Now().Unix()

	svc := &service{
		rateLimitEnabled:         true,
		rateLimitMaxVelocity:     0.28,
		rateLimitMaxCooldownSecs: 100,
		repoManager: &mockRepoManagerForRateLimit{
			markerRepo: &mockMarkerRepoForRateLimit{
				markers: map[string]domain.Marker{
					"m1": {ID: "m1", Depth: 100, CreatedAt: now - 1},
				},
			},
		},
	}

	vtxos := []domain.Vtxo{
		{
			Outpoint:  domain.Outpoint{Txid: "tx1", VOut: 0},
			Depth:     200,
			MarkerIDs: []string{"m1"},
		},
	}

	err := svc.checkRateLimit(context.Background(), vtxos)
	require.NotNil(t, err)

	// Verify the error is RATE_LIMITED
	var rateLimitErr errors.TypedError[errors.RateLimitMetadata]
	require.ErrorAs(t, err, &rateLimitErr)
}
