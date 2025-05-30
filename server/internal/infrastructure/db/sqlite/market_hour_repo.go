package sqlitedb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/infrastructure/db/sqlite/sqlc/queries"
)

type marketHourRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewMarketHourRepository(config ...interface{}) (domain.MarketHourRepo, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open market hour repository: invalid config, expected db at 0")
	}

	return &marketHourRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (r *marketHourRepository) Get(ctx context.Context) (*domain.MarketHour, error) {
	marketHour, err := r.querier.GetLatestMarketHour(ctx)
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
	latest, err := r.querier.GetLatestMarketHour(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to get latest market hour: %w", err)
	}

	var upsertFn func() error
	if errors.Is(err, sql.ErrNoRows) {
		upsertFn = func() error {
			_, err = r.querier.InsertMarketHour(ctx, queries.InsertMarketHourParams{
				StartTime:     marketHour.StartTime.Unix(),
				EndTime:       marketHour.EndTime.Unix(),
				Period:        int64(marketHour.Period),
				RoundInterval: int64(marketHour.RoundInterval),
				UpdatedAt:     marketHour.UpdatedAt.Unix(),
			})
			return err
		}

	} else {
		upsertFn = func() error {
			_, err = r.querier.UpdateMarketHour(ctx, queries.UpdateMarketHourParams{
				StartTime:     marketHour.StartTime.Unix(),
				EndTime:       marketHour.EndTime.Unix(),
				Period:        int64(marketHour.Period),
				RoundInterval: int64(marketHour.RoundInterval),
				UpdatedAt:     marketHour.UpdatedAt.Unix(),
				ID:            latest.ID,
			})
			return err
		}
	}
	if err := upsertFn(); err != nil {
		if isConflictError(err) {
			attempts := 1
			for isConflictError(err) && attempts <= maxRetries {
				time.Sleep(100 * time.Millisecond)
				err = upsertFn()
				attempts++
			}
		}
		return err
	}
	return nil
}

func (r *marketHourRepository) Close() {
	_ = r.db.Close()
}
