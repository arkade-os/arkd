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

type scheduledSessionRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewScheduledSessionRepository(config ...interface{}) (domain.ScheduledSessionRepo, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf(
			"cannot open scheduled session repository: invalid config, expected db at 0",
		)
	}

	return &scheduledSessionRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (r *scheduledSessionRepository) Get(ctx context.Context) (*domain.ScheduledSession, error) {
	scheduledSession, err := r.querier.SelectLatestScheduledSession(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &domain.ScheduledSession{
		StartTime:                 time.Unix(scheduledSession.StartTime, 0),
		EndTime:                   time.Unix(scheduledSession.EndTime, 0),
		Period:                    time.Duration(scheduledSession.Period),
		Duration:                  time.Duration(scheduledSession.Duration),
		RoundMinParticipantsCount: scheduledSession.RoundMinParticipants,
		RoundMaxParticipantsCount: scheduledSession.RoundMaxParticipants,
		UpdatedAt:                 time.Unix(scheduledSession.UpdatedAt, 0),
	}, nil
}

func (r *scheduledSessionRepository) Upsert(
	ctx context.Context, scheduledSession domain.ScheduledSession,
) error {
	return r.querier.UpsertScheduledSession(ctx, queries.UpsertScheduledSessionParams{
		StartTime:            scheduledSession.StartTime.Unix(),
		EndTime:              scheduledSession.EndTime.Unix(),
		Period:               int64(scheduledSession.Period),
		Duration:             int64(scheduledSession.Duration),
		RoundMinParticipants: scheduledSession.RoundMinParticipantsCount,
		RoundMaxParticipants: scheduledSession.RoundMaxParticipantsCount,
		UpdatedAt:            scheduledSession.UpdatedAt.Unix(),
	})
}

func (r *scheduledSessionRepository) Clear(ctx context.Context) error {
	return r.querier.ClearScheduledSession(ctx)
}

func (r *scheduledSessionRepository) Close() {
	_ = r.db.Close()
}
