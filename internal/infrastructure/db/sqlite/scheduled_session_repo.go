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
	db      *sql.DB
	querier *queries.Queries
}

func NewScheduledSessionRepository(config ...interface{}) (domain.ScheduledSessionRepo, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config: expected 1 argument, got %d", len(config))
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf(
			"cannot open scheduled session repository: expected *sql.DB but got %T", config[0],
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
		return nil, fmt.Errorf("failed to get scheduled session: %w", err)
	}

	return &domain.ScheduledSession{
		StartTime: time.Unix(scheduledSession.StartTime, 0),
		EndTime:   time.Unix(scheduledSession.EndTime, 0),
		Period:    time.Duration(scheduledSession.Period),
		Duration:  time.Duration(scheduledSession.Duration),
		UpdatedAt: time.Unix(scheduledSession.UpdatedAt, 0),
	}, nil
}

func (r *scheduledSessionRepository) Upsert(
	ctx context.Context, scheduledSession domain.ScheduledSession,
) error {
	return r.querier.UpsertScheduledSession(ctx, queries.UpsertScheduledSessionParams{
		StartTime: scheduledSession.StartTime.Unix(),
		EndTime:   scheduledSession.EndTime.Unix(),
		Period:    int64(scheduledSession.Period),
		Duration:  int64(scheduledSession.Duration),
		UpdatedAt: scheduledSession.UpdatedAt.Unix(),
	})
}

func (r *scheduledSessionRepository) Close() {
	_ = r.db.Close()
}
