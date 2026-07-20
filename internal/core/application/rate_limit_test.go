package application

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestCheckRateLimit(t *testing.T) {
	now := time.Now().Unix()

	t.Run("scenarios", func(t *testing.T) {
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
				expectCode:       errors.RATE_LIMITED.Code,
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
				expectCode:       errors.RATE_LIMITED.Code,
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
				expectCode:       errors.RATE_LIMITED.Code,
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
			{
				// Markers backfilled by the migration default to created_at 0
				// (the unix epoch), which the limiter reads as ~decades old, so
				// timeDelta is huge and velocity ~0: existing chains are never
				// limited right after migrating. See the add_marker_created_at
				// migration.
				name:                 "legacy marker with created_at 0 is not limited",
				rateLimitEnabled:     true,
				rateLimitMaxVelocity: 0.28,
				rateLimitMaxCooldown: 3600,
				vtxos: []domain.Vtxo{
					{
						Outpoint:  domain.Outpoint{Txid: "tx1", VOut: 0},
						Depth:     5000,
						MarkerIDs: []string{"m1"},
					},
				},
				markers: map[string]domain.Marker{
					// depthDelta = 5000, timeDelta = now (~epoch), velocity ~= 0.
					"m1": {ID: "m1", Depth: 0, CreatedAt: 0},
				},
				expectError: false,
			},
			{
				// timeDelta == 0 must not divide by zero: the guard clamps it to 1s,
				// so a marker stamped this same second reads as maximal velocity.
				name:                 "marker created_at equal to now triggers the timeDelta guard",
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
					// timeDelta = 0 -> clamped to 1, velocity = 100/1 = 100 > 0.28.
					"m1": {ID: "m1", Depth: 100, CreatedAt: now},
				},
				expectError:      true,
				expectCode:       errors.RATE_LIMITED.Code,
				expectInputCount: 1,
			},
			{
				// A future marker timestamp (clock skew between nodes) makes
				// timeDelta negative; the guard clamps it to 1s rather than
				// producing a negative/garbage velocity.
				name:                 "marker created_at in the future (clock skew) triggers the timeDelta guard",
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
					// timeDelta = now-(now+100) = -100 -> clamped to 1, velocity = 100 > 0.28.
					"m1": {ID: "m1", Depth: 100, CreatedAt: now + 100},
				},
				expectError:      true,
				expectCode:       errors.RATE_LIMITED.Code,
				expectInputCount: 1,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				svc := newRateLimitTestService(
					tt.rateLimitEnabled, tt.rateLimitMaxVelocity, tt.rateLimitMaxCooldown, tt.markers,
				)

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
	})

	// deep chains exercises realistic deep chain topologies with markers placed at
	// every MarkerInterval (100) boundary, matching the real marker creation logic.
	t.Run("deep chains", func(t *testing.T) {
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
				markers:     buildMarkerChain(5000, now-50000, 10.0),
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
				svc := newRateLimitTestService(true, tt.rateLimitMaxVelocity, tt.rateLimitMaxCooldown, tt.markers)

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
				require.Equal(t, errors.RATE_LIMITED.Code, err.Code())
			})
		}
	})

	// merged marker chains covers VTXOs that inherit markers from multiple parent
	// chains (DAG merge). The child's MarkerIDs is the union of all parent markers;
	// the rate limiter should pick the youngest (highest depth) marker from the set.
	t.Run("merged marker chains", func(t *testing.T) {
		t.Run("youngest marker at higher depth used for velocity calc", func(t *testing.T) {
			// Chain A reached depth 100, chain B reached depth 200.
			// They merge: child at depth 301 has MarkerIDs = [mA-100, mB-200].
			// Rate limiter picks mB-200 (highest depth).
			// depthDelta = 301-200 = 101, timeDelta = 500, velocity = 0.202 < 0.28 → allowed.
			markers := map[string]domain.Marker{
				"mA-100": {ID: "mA-100", Depth: 100, CreatedAt: now - 2000},
				"mB-200": {ID: "mB-200", Depth: 200, CreatedAt: now - 500},
			}

			svc := newRateLimitTestService(true, 0.28, 3600, markers)

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

			svc := newRateLimitTestService(true, 0.28, 3600, markers)

			vtxo := domain.Vtxo{
				Outpoint:  domain.Outpoint{Txid: "merge-tx2", VOut: 0},
				Depth:     350,
				MarkerIDs: []string{"mA-100", "mB-300"},
			}

			err := svc.checkRateLimit(context.Background(), []domain.Vtxo{vtxo})
			require.NotNil(t, err, "youngest marker (depth 300) gives velocity 5.0, should be rejected")
			require.Equal(t, errors.RATE_LIMITED.Code, err.Code())
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

			svc := newRateLimitTestService(true, 0.28, 3600, markers)

			vtxo := domain.Vtxo{
				Outpoint:  domain.Outpoint{Txid: "merge-tx3", VOut: 0},
				Depth:     510,
				MarkerIDs: []string{"m-100", "m-200", "m-500"},
			}

			err := svc.checkRateLimit(context.Background(), []domain.Vtxo{vtxo})
			require.Nil(t, err, "velocity 0.01 < 0.28, should be allowed")
		})
	})

	// cooldown computation verifies rate limiting triggers correctly at various
	// depths and that the cooldown cap is applied at extreme depths.
	t.Run("cooldown computation", func(t *testing.T) {
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
				svc := newRateLimitTestService(true, tt.maxVelocity, tt.maxCooldown, map[string]domain.Marker{
					markerID: {
						ID:        markerID,
						Depth:     tt.markerDepth,
						CreatedAt: now - tt.markerCreatedAgo,
					},
				})

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
				require.Equal(t, errors.RATE_LIMITED.Code, err.Code())

				var rateLimitErr errors.TypedError[errors.RateLimitMetadata]
				require.ErrorAs(t, err, &rateLimitErr)

				metadata := err.Metadata()
				require.Contains(t, metadata, "inputs")
			})
		}
	})

	t.Run("cooldown cap", func(t *testing.T) {
		svc := newRateLimitTestService(true, 0.28, 100, map[string]domain.Marker{
			"m1": {ID: "m1", Depth: 100, CreatedAt: now - 1},
		})

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
	})

	// rejection metadata asserts the client-visible error metadata (the flattened
	// form clients actually receive from Error.Metadata()) decodes back into the
	// per-input detail a client needs to back off.
	t.Run("rejection metadata", func(t *testing.T) {
		t.Run("reports the computed cooldown for the rejected input", func(t *testing.T) {
			// depth 200, marker depth 100 created 100s ago:
			// depthDelta=100, timeDelta=100, velocity=1.0 > 0.28.
			// cooldown = ceil(100/0.28 - 100) = ceil(257.14) = 258 (below the 3600 cap).
			svc := newRateLimitTestService(true, 0.28, 3600, map[string]domain.Marker{
				"m1": {ID: "m1", Depth: 100, CreatedAt: now - 100},
			})

			err := svc.checkRateLimit(context.Background(), []domain.Vtxo{
				{Outpoint: domain.Outpoint{Txid: "tx1", VOut: 0}, Depth: 200, MarkerIDs: []string{"m1"}},
			})
			require.NotNil(t, err)

			require.Equal(t, "258", err.Metadata()["cooldown_secs"])

			inputs := decodeRateLimitInputs(t, err)
			require.Len(t, inputs, 1)
			require.Equal(t, 200, inputs["tx1:0"].Depth)
			require.Equal(t, 100, inputs["tx1:0"].MarkerDepth)
			require.Equal(t, int64(258), inputs["tx1:0"].CooldownSecs)
		})

		t.Run("cooldown is capped in the reported metadata", func(t *testing.T) {
			// velocity is enormous (marker 1s ago), so the raw cooldown far exceeds
			// the 100s cap and must be reported as exactly 100.
			svc := newRateLimitTestService(true, 0.28, 100, map[string]domain.Marker{
				"m1": {ID: "m1", Depth: 100, CreatedAt: now - 1},
			})

			err := svc.checkRateLimit(context.Background(), []domain.Vtxo{
				{Outpoint: domain.Outpoint{Txid: "tx1", VOut: 0}, Depth: 200, MarkerIDs: []string{"m1"}},
			})
			require.NotNil(t, err)

			require.Equal(t, "100", err.Metadata()["cooldown_secs"])
			require.Equal(t, int64(100), decodeRateLimitInputs(t, err)["tx1:0"].CooldownSecs)
		})

		t.Run("only the rate-limited input of a batch is reported", func(t *testing.T) {
			// tx1 grows fast (velocity 1.0, rejected); tx2 grows slowly
			// (velocity 0.01, allowed), so only tx1 appears in the metadata.
			svc := newRateLimitTestService(true, 0.28, 3600, map[string]domain.Marker{
				"m1": {ID: "m1", Depth: 100, CreatedAt: now - 100},
				"m2": {ID: "m2", Depth: 100, CreatedAt: now - 1000},
			})

			err := svc.checkRateLimit(context.Background(), []domain.Vtxo{
				{Outpoint: domain.Outpoint{Txid: "tx1", VOut: 0}, Depth: 200, MarkerIDs: []string{"m1"}},
				{Outpoint: domain.Outpoint{Txid: "tx2", VOut: 0}, Depth: 110, MarkerIDs: []string{"m2"}},
			})
			require.NotNil(t, err)

			inputs := decodeRateLimitInputs(t, err)
			require.Contains(t, inputs, "tx1:0")
			require.NotContains(t, inputs, "tx2:0")
		})

		t.Run("reported cooldown is the longest across rejected inputs", func(t *testing.T) {
			// tx1: depthDelta=100, timeDelta=100 -> cooldown 258.
			// tx2: depthDelta=200, timeDelta=100 -> cooldown ceil(714.28-100) = 615.
			// The top level cooldown_secs must be the larger of the two.
			svc := newRateLimitTestService(true, 0.28, 3600, map[string]domain.Marker{
				"m1": {ID: "m1", Depth: 100, CreatedAt: now - 100},
				"m2": {ID: "m2", Depth: 100, CreatedAt: now - 100},
			})

			err := svc.checkRateLimit(context.Background(), []domain.Vtxo{
				{Outpoint: domain.Outpoint{Txid: "tx1", VOut: 0}, Depth: 200, MarkerIDs: []string{"m1"}},
				{Outpoint: domain.Outpoint{Txid: "tx2", VOut: 0}, Depth: 300, MarkerIDs: []string{"m2"}},
			})
			require.NotNil(t, err)

			inputs := decodeRateLimitInputs(t, err)
			require.Equal(t, int64(258), inputs["tx1:0"].CooldownSecs)
			require.Equal(t, int64(615), inputs["tx2:0"].CooldownSecs)
			require.Equal(t, "615", err.Metadata()["cooldown_secs"])
		})
	})

	// marker lookup failures must not block offchain txs. The limiter fails open.
	t.Run("marker lookup failure fails to open", func(t *testing.T) {
		svc := newRateLimitTestService(true, 0.28, 3600, map[string]domain.Marker{
			"m1": {ID: "m1", Depth: 100, CreatedAt: now - 1},
		})
		svc.repoManager.(*mockRepoManagerForRateLimit).markerRepo.err = fmt.Errorf("marker store down")

		err := svc.checkRateLimit(context.Background(), []domain.Vtxo{
			{Outpoint: domain.Outpoint{Txid: "tx1", VOut: 0}, Depth: 200, MarkerIDs: []string{"m1"}},
		})
		require.Nil(t, err, "a marker store error must not reject the tx")
	})

	// the limiter reads every referenced marker in one query, not one per input.
	t.Run("markers are fetched in a single batched query", func(t *testing.T) {
		svc := newRateLimitTestService(true, 0.28, 3600, map[string]domain.Marker{
			"m1": {ID: "m1", Depth: 100, CreatedAt: now - 5000},
			"m2": {ID: "m2", Depth: 200, CreatedAt: now - 5000},
		})

		err := svc.checkRateLimit(context.Background(), []domain.Vtxo{
			{Outpoint: domain.Outpoint{Txid: "tx1", VOut: 0}, Depth: 150, MarkerIDs: []string{"m1"}},
			{Outpoint: domain.Outpoint{Txid: "tx2", VOut: 0}, Depth: 250, MarkerIDs: []string{"m1", "m2"}},
		})
		require.Nil(t, err)

		// One query for two inputs sharing a marker. ID deduping itself is covered
		// by domain.TestMarkerIDCollection.
		require.Equal(t, 1, svc.repoManager.(*mockRepoManagerForRateLimit).markerRepo.calls)
	})
}

// newRateLimitTestService builds a service whose cached settings carry the given
// rate-limit config and whose marker repo serves the given markers.
func newRateLimitTestService(
	enabled bool, maxVelocity float64, maxCooldown int64, markers map[string]domain.Marker,
) *service {
	settings := &ports.Settings{
		Settings: domain.Settings{
			RateLimitEnabled:         enabled,
			RateLimitMaxVelocity:     maxVelocity,
			RateLimitMaxCooldownSecs: maxCooldown,
		},
	}
	return &service{
		cache: rateLimitTestLiveStore{settings: settings},
		repoManager: &mockRepoManagerForRateLimit{
			markerRepo: &mockMarkerRepoForRateLimit{markers: markers},
		},
	}
}

// buildMarkerChain builds a linear marker chain from depth 0 to maxDepth at
// MarkerInterval boundaries. Each marker's CreatedAt is baseTime + (depth *
// secsPerDepth), simulating a chain that grows at a steady rate.
func buildMarkerChain(maxDepth uint32, baseTime int64, secsPerDepth float64) map[string]domain.Marker {
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

// markerIDsForDepth returns the marker IDs a VTXO at the given depth would have:
// the marker at that depth if on a boundary, otherwise the nearest boundary below.
func markerIDsForDepth(depth uint32) []string {
	if depth%domain.MarkerInterval == 0 {
		return []string{fmt.Sprintf("m-%d", depth)}
	}
	nearestBoundary := (depth / domain.MarkerInterval) * domain.MarkerInterval
	return []string{fmt.Sprintf("m-%d", nearestBoundary)}
}

type rateLimitTestLiveStore struct {
	ports.LiveStore
	settings *ports.Settings
}

func (s rateLimitTestLiveStore) Settings() ports.SettingsStore {
	return rateLimitTestSettingsStore{settings: s.settings}
}

type rateLimitTestSettingsStore struct {
	ports.SettingsStore
	settings *ports.Settings
}

func (s rateLimitTestSettingsStore) Get(context.Context) (*ports.Settings, error) {
	return s.settings, nil
}

// decodeRateLimitInputs decodes the JSON per-input detail out of the flattened
// metadata, which is exactly what a client has to do with the error.
func decodeRateLimitInputs(
	t *testing.T, err errors.Error,
) map[string]errors.InputRateLimitInfoMeta {
	t.Helper()
	raw, ok := err.Metadata()["inputs"]
	require.True(t, ok, "metadata must carry an inputs key")

	var inputs map[string]errors.InputRateLimitInfoMeta
	require.NoError(t, json.Unmarshal([]byte(raw), &inputs))
	return inputs
}

type mockMarkerRepoForRateLimit struct {
	domain.MarkerRepository
	markers map[string]domain.Marker
	err     error
	calls   int
}

func (m *mockMarkerRepoForRateLimit) GetMarkersByIds(
	_ context.Context, ids []string,
) ([]domain.Marker, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}

	result := make([]domain.Marker, 0, len(ids))
	for _, id := range ids {
		if marker, ok := m.markers[id]; ok {
			result = append(result, marker)
		}
	}
	return result, nil
}

type mockRepoManagerForRateLimit struct {
	ports.RepoManager
	markerRepo *mockMarkerRepoForRateLimit
}

func (m *mockRepoManagerForRateLimit) Markers() domain.MarkerRepository {
	return m.markerRepo
}
