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

type scheduledSessionRepository struct {
	db SQLiteDB
}

func NewScheduledSessionRepository(config ...interface{}) (domain.ScheduledSessionRepo, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config: expected 1 argument, got %d", len(config))
	}
	db, ok := config[0].(SQLiteDB)
	if !ok {
		return nil, fmt.Errorf(
			"cannot open scheduled session repository: expected SQLiteDB but got %T", config[0],
		)
	}

	return &scheduledSessionRepository{
		db: db,
	}, nil
}

func (r *scheduledSessionRepository) Get(ctx context.Context) (*domain.ScheduledSession, error) {
	var scheduledSession queries.ScheduledSession
	err := withReadQuerier(ctx, r.db, func(q *queries.Queries) error {
		var err error
		scheduledSession, err = q.SelectLatestScheduledSession(ctx)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get scheduled session: %w", err)
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
	return withWriteQuerier(ctx, r.db, func(q *queries.Queries) error {
		return q.UpsertScheduledSession(ctx, queries.UpsertScheduledSessionParams{
			StartTime:            scheduledSession.StartTime.Unix(),
			EndTime:              scheduledSession.EndTime.Unix(),
			Period:               int64(scheduledSession.Period),
			Duration:             int64(scheduledSession.Duration),
			RoundMinParticipants: scheduledSession.RoundMinParticipantsCount,
			RoundMaxParticipants: scheduledSession.RoundMaxParticipantsCount,
			UpdatedAt:            scheduledSession.UpdatedAt.Unix(),
		})
	})
}

func (r *scheduledSessionRepository) Clear(ctx context.Context) error {
	return withWriteQuerier(ctx, r.db, func(q *queries.Queries) error {
		return q.ClearScheduledSession(ctx)
	})
}

func (r *scheduledSessionRepository) Close() {
	_ = r.db.Close()
}
