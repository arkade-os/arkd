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

type marketHourRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewMarketHourRepository(config ...interface{}) (domain.MarketHourRepo, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config: expected 1 argument, got %d", len(config))
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf(
			"cannot open market hour repository: expected *sql.DB but got %T", config[0],
		)
	}

	return &marketHourRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (r *marketHourRepository) Get(ctx context.Context) (*domain.MarketHour, error) {
	marketHour, err := r.querier.SelectLatestMarketHour(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get market hour: %w", err)
	}

	return &domain.MarketHour{
		StartTime:     time.Unix(marketHour.StartTime, 0),
		EndTime:       time.Unix(marketHour.EndTime, 0),
		Period:        time.Duration(marketHour.Period),
		RoundInterval: time.Duration(marketHour.RoundInterval),
		UpdatedAt:     time.Unix(marketHour.UpdatedAt, 0),
	}, nil
}

func (r *marketHourRepository) Upsert(ctx context.Context, marketHour domain.MarketHour) error {
	return r.querier.UpsertMarketHour(ctx, queries.UpsertMarketHourParams{
		StartTime:     marketHour.StartTime.Unix(),
		EndTime:       marketHour.EndTime.Unix(),
		Period:        int64(marketHour.Period),
		RoundInterval: int64(marketHour.RoundInterval),
		UpdatedAt:     marketHour.UpdatedAt.Unix(),
	})
}

func (r *marketHourRepository) Close() {
	_ = r.db.Close()
}
