package application_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminService_Settings(t *testing.T) {
	repo := &mockRepoManager{
		settingsRepo: &mockSettingsRepository{},
	}
	defaults := domain.Settings{
		BanThreshold:              3,
		BanDuration:               300,
		VtxoTreeExpiry:            604672,
		UnilateralExitDelay:       86400,
		PublicUnilateralExitDelay: 86400,
		CheckpointExitDelay:       86400,
		BoardingExitDelay:         7776000,
		RoundMinParticipantsCount: 1,
		RoundMaxParticipantsCount: 128,
		UtxoMaxAmount:             -1,
		UtxoMinAmount:             -1,
		VtxoMaxAmount:             -1,
		VtxoMinAmount:             -1,
		MaxTxWeight:               40000,
	}
	svc := application.NewAdminService(
		nil, repo, nil, nil, ports.UnixTime, nil, 1, 128,
		defaults, nil, func() {},
	)

	ctx := context.Background()

	t.Run("get returns nil when no settings exist", func(t *testing.T) {
		settings, err := svc.GetSettings(ctx)
		require.NoError(t, err)
		require.Nil(t, settings)
	})

	t.Run("update persists settings and sets UpdatedAt", func(t *testing.T) {
		before := time.Now().Add(-time.Second)
		input := domain.Settings{
			BanThreshold:              3,
			BanDuration:               300,
			VtxoTreeExpiry:            604672,
			UnilateralExitDelay:       86400,
			PublicUnilateralExitDelay: 86400,
			CheckpointExitDelay:       86400,
			BoardingExitDelay:         7776000,
			RoundMinParticipantsCount: 1,
			RoundMaxParticipantsCount: 128,
			UtxoMaxAmount:             -1,
			UtxoMinAmount:             -1,
			VtxoMaxAmount:             -1,
			VtxoMinAmount:             -1,
			MaxTxWeight:               40000,
		}
		err := svc.UpdateSettings(ctx, input, nil)
		require.NoError(t, err)

		got, err := svc.GetSettings(ctx)
		require.NoError(t, err)
		require.NotNil(t, got)

		assert.Equal(t, input.BanThreshold, got.BanThreshold)
		assert.Equal(t, input.BanDuration, got.BanDuration)
		assert.Equal(t, input.VtxoTreeExpiry, got.VtxoTreeExpiry)
		assert.Equal(t, input.UnilateralExitDelay, got.UnilateralExitDelay)
		assert.Equal(t, input.PublicUnilateralExitDelay, got.PublicUnilateralExitDelay)
		assert.Equal(t, input.CheckpointExitDelay, got.CheckpointExitDelay)
		assert.Equal(t, input.BoardingExitDelay, got.BoardingExitDelay)
		assert.Equal(t, input.RoundMinParticipantsCount, got.RoundMinParticipantsCount)
		assert.Equal(t, input.RoundMaxParticipantsCount, got.RoundMaxParticipantsCount)
		assert.Equal(t, input.UtxoMaxAmount, got.UtxoMaxAmount)
		assert.Equal(t, input.UtxoMinAmount, got.UtxoMinAmount)
		assert.Equal(t, input.VtxoMaxAmount, got.VtxoMaxAmount)
		assert.Equal(t, input.VtxoMinAmount, got.VtxoMinAmount)
		assert.Equal(t, input.MaxTxWeight, got.MaxTxWeight)
		assert.Equal(t, input.SettlementMinExpiryGap, got.SettlementMinExpiryGap)
		assert.Equal(t, input.VtxoNoCsvValidationCutoffDate, got.VtxoNoCsvValidationCutoffDate)

		// UpdatedAt must have been set automatically
		assert.True(t, got.UpdatedAt.After(before), "UpdatedAt should be set by UpdateSettings")
	})

	t.Run("get returns previously stored settings", func(t *testing.T) {
		got, err := svc.GetSettings(ctx)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, int64(3), got.BanThreshold)
		assert.Equal(t, int64(128), got.RoundMaxParticipantsCount)
	})

	t.Run("update overwrites existing settings", func(t *testing.T) {
		updated := domain.Settings{
			BanThreshold:              5,
			BanDuration:               600,
			VtxoTreeExpiry:            604672,
			UnilateralExitDelay:       86400,
			PublicUnilateralExitDelay: 86400,
			CheckpointExitDelay:       86400,
			BoardingExitDelay:         7776000,
			RoundMinParticipantsCount: 2,
			RoundMaxParticipantsCount: 256,
			UtxoMaxAmount:             1000000,
			UtxoMinAmount:             1000,
			VtxoMaxAmount:             500000,
			VtxoMinAmount:             500,
			MaxTxWeight:               80000,
			SettlementMinExpiryGap:    7200,
		}
		err := svc.UpdateSettings(ctx, updated, nil)
		require.NoError(t, err)

		got, err := svc.GetSettings(ctx)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, int64(5), got.BanThreshold)
		assert.Equal(t, int64(600), got.BanDuration)
		assert.Equal(t, int64(256), got.RoundMaxParticipantsCount)
		assert.Equal(t, int64(1000000), got.UtxoMaxAmount)
		assert.Equal(t, int64(80000), got.MaxTxWeight)
		assert.Equal(t, int64(7200), got.SettlementMinExpiryGap)
	})

	t.Run("partial update only changes provided fields", func(t *testing.T) {
		// Get current state after the full update above.
		before, err := svc.GetSettings(ctx)
		require.NoError(t, err)

		// Send only BanThreshold via update mask.
		partial := domain.Settings{BanThreshold: 99}
		err = svc.UpdateSettings(ctx, partial, []string{"ban_threshold"})
		require.NoError(t, err)

		got, err := svc.GetSettings(ctx)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, int64(99), got.BanThreshold)
		// Other fields unchanged.
		assert.Equal(t, before.BanDuration, got.BanDuration)
		assert.Equal(t, before.UnilateralExitDelay, got.UnilateralExitDelay)
		assert.Equal(t, before.BoardingExitDelay, got.BoardingExitDelay)
		assert.Equal(t, before.VtxoTreeExpiry, got.VtxoTreeExpiry)
		assert.Equal(t, before.MaxTxWeight, got.MaxTxWeight)
	})

	t.Run("clear resets settings to defaults", func(t *testing.T) {
		err := svc.ClearSettings(ctx)
		require.NoError(t, err)

		got, err := svc.GetSettings(ctx)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, defaults.BanThreshold, got.BanThreshold)
		assert.Equal(t, defaults.BanDuration, got.BanDuration)
		assert.Equal(t, defaults.RoundMaxParticipantsCount, got.RoundMaxParticipantsCount)
	})

	t.Run("clear on defaults is idempotent", func(t *testing.T) {
		err := svc.ClearSettings(ctx)
		require.NoError(t, err)

		got, err := svc.GetSettings(ctx)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, defaults.BanThreshold, got.BanThreshold)
	})
}

// Minimal mock implementations for testing settings methods only.

type mockRepoManager struct {
	ports.RepoManager
	settingsRepo domain.SettingsRepository
}

func (m *mockRepoManager) Settings() domain.SettingsRepository {
	return m.settingsRepo
}

type mockSettingsRepository struct {
	mu       sync.Mutex
	settings *domain.Settings
}

func (m *mockSettingsRepository) Get(_ context.Context) (*domain.Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.settings == nil {
		return nil, nil
	}
	cp := *m.settings
	return &cp, nil
}

func (m *mockSettingsRepository) Upsert(_ context.Context, settings domain.Settings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings = &settings
	return nil
}

func (m *mockSettingsRepository) Clear(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings = nil
	return nil
}

func (m *mockSettingsRepository) Close() {}
