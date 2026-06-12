package pgdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/postgres/sqlc/queries"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
)

// splitFallbackAddrs decodes the comma-separated wallet_fallback_addrs column
// back into a slice (empty string -> nil).
func splitFallbackAddrs(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

type settingsRepository struct {
	db      *sql.DB
	querier *queries.Queries

	updateHandlerMu *sync.Mutex
	updateHandler   func(domain.Settings, []string)
}

func NewSettingsRepository(config ...interface{}) (domain.SettingsRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf(
			"cannot open settings repository: invalid config, expected db at 0",
		)
	}

	return &settingsRepository{
		db:              db,
		querier:         queries.New(db),
		updateHandlerMu: &sync.Mutex{},
	}, nil
}

func (r *settingsRepository) RegisterUpdatesHandler(handler func(domain.Settings, []string)) {
	r.updateHandlerMu.Lock()
	defer r.updateHandlerMu.Unlock()
	r.updateHandler = handler
}

func (r *settingsRepository) Get(ctx context.Context) (*domain.Settings, error) {
	row, err := r.querier.SelectSettings(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
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
		AssetTxMaxWeightRatio:         row.AssetTxMaxWeightRatio,
		NoteUriPrefix:                 row.NoteUriPrefix,
		BuildVersionHeader:            row.BuildVersionHeader,
		BuildVersionHeaderRequired:    row.BuildVersionHeaderRequired,
		DigestHeaderRequired:          row.DigestHeaderRequired,
		WalletAddr:                    row.WalletAddr,
		WalletFallbackAddrs:           splitFallbackAddrs(row.WalletFallbackAddrs),
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

// Upsert writes the singleton settings row (id defaults to 0) and, in the same
// transaction, appends a settings_history record whose changed_fields is the
// changelog and whose snapshot is built from the row via to_jsonb.
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
		AssetTxMaxWeightRatio:         settings.AssetTxMaxWeightRatio,
		NoteUriPrefix:                 settings.NoteUriPrefix,
		BuildVersionHeader:            settings.BuildVersionHeader,
		BuildVersionHeaderRequired:    settings.BuildVersionHeaderRequired,
		DigestHeaderRequired:          settings.DigestHeaderRequired,
		WalletAddr:                    settings.WalletAddr,
		WalletFallbackAddrs:           strings.Join(settings.WalletFallbackAddrs, ","),
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

	txBody := func(q *queries.Queries) error {
		if err := q.UpsertSettings(ctx, params); err != nil {
			return fmt.Errorf("failed to upsert settings: %w", err)
		}
		// Only record history for actual changes (skips e.g. the first-boot seed).
		if len(changelog) > 0 {
			if err := q.InsertSettingsHistory(ctx, changelog); err != nil {
				return fmt.Errorf("failed to insert settings history: %w", err)
			}
		}
		return nil
	}
	if err := execTx(ctx, r.db, txBody); err != nil {
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
