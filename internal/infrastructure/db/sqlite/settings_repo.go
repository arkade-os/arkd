package sqlitedb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
)

type settingsRepository struct {
	db SQLiteDB

	updateHandlerMu *sync.Mutex
	updateHandler   func(domain.Settings, []string)
}

func NewSettingsRepository(config ...interface{}) (domain.SettingsRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config: expected 1 argument, got %d", len(config))
	}
	db, ok := config[0].(SQLiteDB)
	if !ok {
		return nil, fmt.Errorf(
			"cannot open settings repository: expected SQLiteDB but got %T", config[0],
		)
	}

	return &settingsRepository{
		db:              db,
		updateHandlerMu: &sync.Mutex{},
	}, nil
}

func (r *settingsRepository) RegisterUpdatesHandler(handler func(domain.Settings, []string)) {
	r.updateHandlerMu.Lock()
	defer r.updateHandlerMu.Unlock()
	r.updateHandler = handler
}

func (r *settingsRepository) Get(ctx context.Context) (*domain.Settings, error) {
	var row queries.Setting
	if err := withReadQuerier(ctx, r.db, func(q *queries.Queries) error {
		var err error
		row, err = q.SelectSettings(ctx)
		return err
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}

	scheduledSession := &domain.ScheduledSession{
		StartTime:                 timeFromUnix(row.ScheduledSessionStartTime),
		EndTime:                   timeFromUnix(row.ScheduledSessionEndTime),
		Period:                    time.Duration(row.ScheduledSessionPeriod) * time.Second,
		Duration:                  time.Duration(row.ScheduledSessionDuration) * time.Second,
		RoundMinParticipantsCount: row.ScheduledSessionRoundMinParticipantsCount,
		RoundMaxParticipantsCount: row.ScheduledSessionRoundMaxParticipantsCount,
	}
	// No scheduled session is represented as nil in the domain.
	if scheduledSession.IsEmpty() {
		scheduledSession = nil
	}

	unilateral, _ := arklib.ParseRelativeLocktime(uint32(row.UnilateralExitDelay))
	publicUnilateral, _ := arklib.ParseRelativeLocktime(uint32(row.PublicUnilateralExitDelay))
	checkpoint, _ := arklib.ParseRelativeLocktime(uint32(row.CheckpointExitDelay))
	boarding, _ := arklib.ParseRelativeLocktime(uint32(row.BoardingExitDelay))
	vtxoTreeExpiry, _ := arklib.ParseRelativeLocktime(uint32(row.VtxoTreeExpiry))

	return &domain.Settings{
		SessionDuration:               time.Duration(row.SessionDuration) * time.Second,
		UnrolledVtxoMinExpiryMargin:   time.Duration(row.UnrolledVtxoMinExpiryMargin) * time.Second,
		BanThreshold:                  uint64(row.BanThreshold),
		BanDuration:                   time.Duration(row.BanDuration) * time.Second,
		UnilateralExitDelay:           unilateral,
		PublicUnilateralExitDelay:     publicUnilateral,
		CheckpointExitDelay:           checkpoint,
		BoardingExitDelay:             boarding,
		VtxoTreeExpiry:                vtxoTreeExpiry,
		RoundMinParticipantsCount:     row.RoundMinParticipantsCount,
		RoundMaxParticipantsCount:     row.RoundMaxParticipantsCount,
		VtxoMinAmount:                 row.VtxoMinAmount,
		VtxoMaxAmount:                 row.VtxoMaxAmount,
		UtxoMinAmount:                 row.UtxoMinAmount,
		UtxoMaxAmount:                 row.UtxoMaxAmount,
		SettlementMinExpiryGap:        time.Duration(row.SettlementMinExpiryGap) * time.Second,
		VtxoNoCsvValidationCutoffDate: timeFromUnix(row.VtxoNoCsvValidationCutoffDate),
		MaxTxWeight:                   uint64(row.MaxTxWeight),
		MaxOpReturnOutputs:            uint64(row.MaxOpReturnOutputs),
		AssetTxMaxWeightRatio:         float32(row.AssetTxMaxWeightRatio),
		NoteUriPrefix:                 row.NoteUriPrefix,
		BuildVersionHeader:            row.BuildVersionHeader,
		BuildVersionHeaderRequired:    row.BuildVersionHeaderRequired,
		DigestHeaderRequired:          row.DigestHeaderRequired,
		ScheduledSession:              scheduledSession,
		BatchFees: domain.BatchFees{
			OnchainInputFee:   row.BatchOnchainInputFee,
			OffchainInputFee:  row.BatchOffchainInputFee,
			OnchainOutputFee:  row.BatchOnchainOutputFee,
			OffchainOutputFee: row.BatchOffchainOutputFee,
		},
		UpdatedAt: timeFromUnix(row.UpdatedAt),
	}, nil
}

// Upsert writes the singleton settings row (id defaults to 0). Unlike postgres
// this backend doesn't keep a change history; it's only used for testing.
func (r *settingsRepository) Upsert(
	ctx context.Context, settings domain.Settings, changelog []string,
) error {
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
		AssetTxMaxWeightRatio:         float64(settings.AssetTxMaxWeightRatio),
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

	if err := withWriteQuerier(ctx, r.db, func(q *queries.Queries) error {
		return q.UpsertSettings(ctx, params)
	}); err != nil {
		return err
	}

	// Dispatch synchronously so the cache refresh is ordered with the committed
	// write: the caller serializes updates, so the cache can't end up behind the DB.
	r.dispatch(settings, changelog)

	return nil
}

func (r *settingsRepository) Close() {
	_ = r.db.Close()
}

func (r *settingsRepository) dispatch(settings domain.Settings, changelog []string) {
	r.updateHandlerMu.Lock()
	handler := r.updateHandler
	r.updateHandlerMu.Unlock()
	if handler != nil {
		handler(settings, changelog)
	}
}

// timeToUnix encodes a time.Time as a unix timestamp, mapping the zero time to 0
// (rather than the year-1 unix value).
func timeToUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// timeFromUnix decodes a unix timestamp produced by timeToUnix, mapping 0 back
// to the zero time (rather than the 1970 epoch).
func timeFromUnix(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}
