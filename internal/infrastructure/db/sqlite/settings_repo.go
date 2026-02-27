package sqlitedb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
)

type settingsRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewSettingsRepository(config ...interface{}) (domain.SettingsRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config: expected 1 argument, got %d", len(config))
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf(
			"cannot open settings repository: expected *sql.DB but got %T", config[0],
		)
	}

	return &settingsRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (r *settingsRepository) Get(ctx context.Context) (*domain.Settings, error) {
	settings, err := r.querier.SelectLatestSettings(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}

	return &domain.Settings{
		BanThreshold:                  settings.BanThreshold,
		BanDuration:                   settings.BanDuration,
		UnilateralExitDelay:           settings.UnilateralExitDelay,
		PublicUnilateralExitDelay:     settings.PublicUnilateralExitDelay,
		CheckpointExitDelay:           settings.CheckpointExitDelay,
		BoardingExitDelay:             settings.BoardingExitDelay,
		VtxoTreeExpiry:                settings.VtxoTreeExpiry,
		RoundMinParticipantsCount:     settings.RoundMinParticipantsCount,
		RoundMaxParticipantsCount:     settings.RoundMaxParticipantsCount,
		VtxoMinAmount:                 settings.VtxoMinAmount,
		VtxoMaxAmount:                 settings.VtxoMaxAmount,
		UtxoMinAmount:                 settings.UtxoMinAmount,
		UtxoMaxAmount:                 settings.UtxoMaxAmount,
		SettlementMinExpiryGap:        settings.SettlementMinExpiryGap,
		VtxoNoCsvValidationCutoffDate: settings.VtxoNoCsvValidationCutoffDate,
		MaxTxWeight:                   settings.MaxTxWeight,
		UpdatedAt:                     time.Unix(settings.UpdatedAt, 0),
	}, nil
}

func (r *settingsRepository) Upsert(
	ctx context.Context, settings domain.Settings,
) error {
	return r.querier.UpsertSettings(ctx, queries.UpsertSettingsParams{
		BanThreshold:                  settings.BanThreshold,
		BanDuration:                   settings.BanDuration,
		UnilateralExitDelay:           settings.UnilateralExitDelay,
		PublicUnilateralExitDelay:     settings.PublicUnilateralExitDelay,
		CheckpointExitDelay:           settings.CheckpointExitDelay,
		BoardingExitDelay:             settings.BoardingExitDelay,
		VtxoTreeExpiry:                settings.VtxoTreeExpiry,
		RoundMinParticipantsCount:     settings.RoundMinParticipantsCount,
		RoundMaxParticipantsCount:     settings.RoundMaxParticipantsCount,
		VtxoMinAmount:                 settings.VtxoMinAmount,
		VtxoMaxAmount:                 settings.VtxoMaxAmount,
		UtxoMinAmount:                 settings.UtxoMinAmount,
		UtxoMaxAmount:                 settings.UtxoMaxAmount,
		SettlementMinExpiryGap:        settings.SettlementMinExpiryGap,
		VtxoNoCsvValidationCutoffDate: settings.VtxoNoCsvValidationCutoffDate,
		MaxTxWeight:                   settings.MaxTxWeight,
		UpdatedAt:                     settings.UpdatedAt.Unix(),
	})
}

func (r *settingsRepository) Clear(ctx context.Context) error {
	return r.querier.ClearSettings(ctx)
}

func (r *settingsRepository) Close() {
	_ = r.db.Close()
}
