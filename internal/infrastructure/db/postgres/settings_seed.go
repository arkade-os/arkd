package pgdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/postgres/sqlc/queries"
)

// SeedSettings seeds the singleton settings row from the config-built defaults on
// first boot, carrying over any legacy intent_fees / scheduled_session rows, then
// deletes those legacy rows. It runs at most once: after the settings row exists it
// returns immediately without touching anything (so it never clobbers admin changes).
//
// Everything runs in one raw transaction so a crash rolls back cleanly, leaving the
// legacy data intact for the next boot. The write goes through the generated
// UpsertSettings (not the repo's public Upsert) to deliberately bypass the repo's
// update dispatch and settings_history audit — this is init, not a user change.
func SeedSettings(ctx context.Context, db *sql.DB, defaults domain.Settings) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Gate: seed only when the settings table is empty.
	var hasSettings bool
	if err = tx.QueryRowContext(
		ctx, `SELECT EXISTS(SELECT 1 FROM settings)`,
	).Scan(&hasSettings); err != nil {
		return fmt.Errorf("check settings existence: %w", err)
	}
	if hasSettings {
		return tx.Commit()
	}

	merged := defaults

	// Read latest legacy intent_fees, if any.
	var fees domain.BatchFees
	feeErr := tx.QueryRowContext(ctx, `
		SELECT offchain_input_fee_program, onchain_input_fee_program,
		       offchain_output_fee_program, onchain_output_fee_program
		FROM intent_fees ORDER BY created_at DESC LIMIT 1`).Scan(
		&fees.OffchainInputFee, &fees.OnchainInputFee,
		&fees.OffchainOutputFee, &fees.OnchainOutputFee,
	)
	switch {
	case feeErr == nil:
		merged.BatchFees = fees
	case errors.Is(feeErr, sql.ErrNoRows):
		// no legacy fees; keep defaults
	default:
		return fmt.Errorf("read legacy intent_fees: %w", feeErr)
	}

	// Read latest legacy scheduled_session, if any.
	var (
		startUnix, endUnix     int64
		periodSec, durationSec int64
		roundMin, roundMax     int64
	)
	ssErr := tx.QueryRowContext(ctx, `
		SELECT start_time, end_time, period, duration,
		       round_min_participants, round_max_participants
		FROM scheduled_session ORDER BY id DESC LIMIT 1`).Scan(
		&startUnix, &endUnix, &periodSec, &durationSec, &roundMin, &roundMax,
	)
	switch {
	case ssErr == nil:
		ss := &domain.ScheduledSession{
			StartTime:                 timeFromUnix(startUnix),
			EndTime:                   timeFromUnix(endUnix),
			Period:                    time.Duration(periodSec) * time.Second,
			Duration:                  time.Duration(durationSec) * time.Second,
			RoundMinParticipantsCount: roundMin,
			RoundMaxParticipantsCount: roundMax,
		}
		if !ss.IsEmpty() {
			merged.ScheduledSession = ss
		}
	case errors.Is(ssErr, sql.ErrNoRows):
		// no legacy session; keep defaults
	default:
		return fmt.Errorf("read legacy scheduled_session: %w", ssErr)
	}

	if err = merged.Validate(); err != nil {
		return fmt.Errorf("invalid seeded settings: %w", err)
	}

	if err = queries.New(tx).UpsertSettings(ctx, seedParams(merged)); err != nil {
		return fmt.Errorf("upsert seeded settings: %w", err)
	}

	// Consume the legacy rows now that they've been carried over.
	if _, err = tx.ExecContext(ctx, `DELETE FROM intent_fees`); err != nil {
		return fmt.Errorf("delete legacy intent_fees: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM scheduled_session`); err != nil {
		return fmt.Errorf("delete legacy scheduled_session: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit settings seed: %w", err)
	}
	return nil
}

// seedParams maps a domain.Settings to UpsertSettingsParams. It mirrors the
// settings repository's Upsert mapping; kept here so the seed does not depend on
// the repo's internals. AssetTxMaxWeightRatio is float32 in the postgres codegen.
func seedParams(settings domain.Settings) queries.UpsertSettingsParams {
	params := queries.UpsertSettingsParams{
		SessionDuration:               int64(settings.SessionDuration.Seconds()),
		UnrolledVtxoMinExpiryMargin:   int64(settings.UnrolledVtxoMinExpiryMargin.Seconds()),
		BanThreshold:                  int64(settings.BanThreshold),
		BanDuration:                   int64(settings.BanDuration.Seconds()),
		UnilateralExitDelay:           int64(settings.UnilateralExitDelay.Value),
		PublicUnilateralExitDelay:     int64(settings.PublicUnilateralExitDelay.Value),
		CheckpointExitDelay:           int64(settings.CheckpointExitDelay.Value),
		BoardingExitDelay:             int64(settings.BoardingExitDelay.Value),
		VtxoTreeExpiry:                int64(settings.VtxoTreeExpiry.Value),
		RoundMinParticipantsCount:     int64(settings.RoundMinParticipantsCount),
		RoundMaxParticipantsCount:     int64(settings.RoundMaxParticipantsCount),
		VtxoMinAmount:                 settings.VtxoMinAmount,
		VtxoMaxAmount:                 settings.VtxoMaxAmount,
		UtxoMinAmount:                 settings.UtxoMinAmount,
		UtxoMaxAmount:                 settings.UtxoMaxAmount,
		SettlementMinExpiryGap:        int64(settings.SettlementMinExpiryGap.Seconds()),
		VtxoNoCsvValidationCutoffDate: timeToUnix(settings.VtxoNoCsvValidationCutoffDate),
		MaxTxWeight:                   int64(settings.MaxTxWeight),
		MaxOpReturnOutputs:            int64(settings.MaxOpReturnOutputs),
		AssetTxMaxWeightRatio:         settings.AssetTxMaxWeightRatio,
		NoteUriPrefix:                 settings.NoteUriPrefix,
		BuildVersionHeader:            settings.BuildVersionHeader,
		BuildVersionHeaderRequired:    settings.BuildVersionHeaderRequired,
		DigestHeaderRequired:          settings.DigestHeaderRequired,
		BatchOnchainInputFee:          settings.BatchFees.OnchainInputFee,
		BatchOffchainInputFee:         settings.BatchFees.OffchainInputFee,
		BatchOnchainOutputFee:         settings.BatchFees.OnchainOutputFee,
		BatchOffchainOutputFee:        settings.BatchFees.OffchainOutputFee,
		UpdatedAt:                     timeToUnix(settings.UpdatedAt),
	}
	if ss := settings.ScheduledSession; ss != nil && !ss.IsEmpty() {
		params.ScheduledSessionStartTime = timeToUnix(ss.StartTime)
		params.ScheduledSessionEndTime = timeToUnix(ss.EndTime)
		params.ScheduledSessionPeriod = int64(ss.Period.Seconds())
		params.ScheduledSessionDuration = int64(ss.Duration.Seconds())
		params.ScheduledSessionRoundMinParticipantsCount = ss.RoundMinParticipantsCount
		params.ScheduledSessionRoundMaxParticipantsCount = ss.RoundMaxParticipantsCount
	}
	return params
}
