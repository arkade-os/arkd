package application

import (
	"context"
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
