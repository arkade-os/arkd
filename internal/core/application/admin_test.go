package application_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/stretchr/testify/require"
)

// validSettings returns a fully-valid settings value to seed the mock repo with.
// The admin update/clear methods all require existing settings, so every flow
// below starts from this seed.
func validSettings() domain.Settings {
	delay := func(v uint32) arklib.RelativeLocktime {
		lt, _ := arklib.ParseRelativeLocktime(v)
		return lt
	}
	return domain.Settings{
		SessionDuration:             30 * time.Second,
		UnrolledVtxoMinExpiryMargin: 30 * time.Second,
		BanThreshold:                3,
		BanDuration:                 time.Hour,
		UnilateralExitDelay:         delay(512),
		PublicUnilateralExitDelay:   delay(512),
		CheckpointExitDelay:         delay(1024),
		BoardingExitDelay:           delay(1536),
		VtxoTreeExpiry:              delay(1024),
		RoundMinParticipantsCount:   1,
		RoundMaxParticipantsCount:   128,
		VtxoMinAmount:               1000,
		VtxoMaxAmount:               -1,
		UtxoMinAmount:               1000,
		UtxoMaxAmount:               -1,
		MaxTxWeight:                 400000,
		AssetTxMaxWeightRatio:       0.5,
		UpdatedAt:                   time.Now(),
	}
}

func TestAdminService_Settings(t *testing.T) {
	ctx := context.Background()

	// newSvc builds an admin service over a mock repo, optionally pre-seeded with
	// settings (the update/clear methods require existing settings).
	newSvc := func(t *testing.T, seed *domain.Settings) application.AdminService {
		t.Helper()
		repo := &mockRepoManager{settingsRepo: &mockSettingsRepository{}}
		if seed != nil {
			require.NoError(t, repo.settingsRepo.Upsert(ctx, *seed, nil))
		}
		return application.NewAdminService(nil, repo, nil, nil, ports.UnixTime, nil)
	}

	t.Run("settings", func(t *testing.T) {
		t.Run("get returns nil when unset", func(t *testing.T) {
			svc := newSvc(t, nil)
			got, err := svc.GetSettings(ctx)
			require.NoError(t, err)
			require.Nil(t, got)
		})

		t.Run("update on empty settings fails", func(t *testing.T) {
			svc := newSvc(t, nil)
			banThreshold := uint64(5)
			_, err := svc.UpdateSettings(ctx, domain.SettingsUpdate{BanThreshold: &banThreshold})
			require.Error(t, err)
		})

		t.Run("update changes only provided fields and returns changelog", func(t *testing.T) {
			seed := validSettings()
			svc := newSvc(t, &seed)

			banThreshold := uint64(99)
			vtxoMin := int64(2000)
			changelog, err := svc.UpdateSettings(ctx, domain.SettingsUpdate{
				BanThreshold:  &banThreshold,
				VtxoMinAmount: &vtxoMin,
			})
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"ban_threshold", "vtxo_min_amount"}, changelog)

			got, err := svc.GetSettings(ctx)
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, uint64(99), got.BanThreshold)
			require.Equal(t, int64(2000), got.VtxoMinAmount)
			// Fields not in the update keep their seeded values.
			require.Equal(t, seed.RoundMaxParticipantsCount, got.RoundMaxParticipantsCount)
			require.Equal(t, seed.VtxoTreeExpiry, got.VtxoTreeExpiry)
		})

		t.Run("invalid update is rejected and leaves state untouched", func(t *testing.T) {
			seed := validSettings()
			svc := newSvc(t, &seed)

			zero := int64(0) // vtxo min amount must be > 0
			_, err := svc.UpdateSettings(ctx, domain.SettingsUpdate{VtxoMinAmount: &zero})
			require.Error(t, err)

			got, err := svc.GetSettings(ctx)
			require.NoError(t, err)
			require.Equal(t, seed.VtxoMinAmount, got.VtxoMinAmount)
		})
	})

	t.Run("scheduled session", func(t *testing.T) {
		seed := validSettings()
		svc := newSvc(t, &seed)

		// Unset on a fresh seed.
		ss, err := svc.GetScheduledSession(ctx)
		require.NoError(t, err)
		require.Nil(t, ss)

		// Update sets it.
		start := time.Now().Add(time.Hour)
		end := start.Add(time.Hour)
		period := 2 * time.Hour
		duration := 30 * time.Minute
		minP := int64(1)
		maxP := int64(10)
		require.NoError(t, svc.UpdateScheduledSession(ctx, domain.ScheduledSessionUpdate{
			StartTime:                 &start,
			EndTime:                   &end,
			Period:                    &period,
			Duration:                  &duration,
			RoundMinParticipantsCount: &minP,
			RoundMaxParticipantsCount: &maxP,
		}))

		ss, err = svc.GetScheduledSession(ctx)
		require.NoError(t, err)
		require.NotNil(t, ss)
		require.Equal(t, period, ss.Period)
		require.Equal(t, duration, ss.Duration)
		require.Equal(t, maxP, ss.RoundMaxParticipantsCount)

		// Clear removes it.
		require.NoError(t, svc.ClearScheduledSession(ctx))
		ss, err = svc.GetScheduledSession(ctx)
		require.NoError(t, err)
		require.Nil(t, ss)
	})

	t.Run("batch fees", func(t *testing.T) {
		seed := validSettings()
		svc := newSvc(t, &seed)

		// Empty on a fresh seed.
		fees, err := svc.GetBatchFees(ctx)
		require.NoError(t, err)
		require.NotNil(t, fees)
		require.Equal(t, domain.BatchFees{}, *fees)

		// Update sets the provided programs, leaving the others empty.
		inFee := "0.0"
		outFee := "0.0"
		require.NoError(t, svc.UpdateBatchFees(ctx, domain.BatchFeesUpdate{
			OffchainInputFee:  &inFee,
			OffchainOutputFee: &outFee,
		}))

		fees, err = svc.GetBatchFees(ctx)
		require.NoError(t, err)
		require.Equal(t, "0.0", fees.OffchainInputFee)
		require.Equal(t, "0.0", fees.OffchainOutputFee)
		require.Empty(t, fees.OnchainInputFee)

		// Clear zeroes them out.
		require.NoError(t, svc.ClearBatchFees(ctx))
		fees, err = svc.GetBatchFees(ctx)
		require.NoError(t, err)
		require.Equal(t, domain.BatchFees{}, *fees)
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

func (m *mockSettingsRepository) Upsert(
	_ context.Context, settings domain.Settings, _ []string,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings = &settings
	return nil
}

func (m *mockSettingsRepository) RegisterUpdatesHandler(_ func(domain.Settings, []string)) {}

func (m *mockSettingsRepository) Clear(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings = nil
	return nil
}

func (m *mockSettingsRepository) Close() {}
