package pgdb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/postgres/sqlc/queries"
)

type intentFeesRepo struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewIntentFeesRepository(config ...interface{}) (domain.FeeRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open intent fee repository: invalid config")
	}

	return &intentFeesRepo{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (r *intentFeesRepo) GetIntentFees(ctx context.Context) (*domain.IntentFees, error) {
	row, err := r.querier.SelectLatestIntentFees(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return &domain.IntentFees{}, nil
		}
		return nil, fmt.Errorf("failed to get intent fees: %w", err)
	}

	return &domain.IntentFees{
		OnchainInputFee:   row.OnchainInputFeeProgram,
		OffchainInputFee:  row.OffchainInputFeeProgram,
		OnchainOutputFee:  row.OnchainOutputFeeProgram,
		OffchainOutputFee: row.OffchainOutputFeeProgram,
	}, nil
}

func (r *intentFeesRepo) UpsertIntentFees(ctx context.Context, fees domain.IntentFees) error {
	err := r.querier.UpsertIntentFees(ctx, queries.UpsertIntentFeesParams{
		CreatedAt:                time.Now().Unix(),
		OnchainInputFeeProgram:   fees.OnchainInputFee,
		OffchainInputFeeProgram:  fees.OffchainInputFee,
		OnchainOutputFeeProgram:  fees.OnchainOutputFee,
		OffchainOutputFeeProgram: fees.OffchainOutputFee,
	})
	if err != nil {
		return fmt.Errorf("failed to upsert intent fees: %w", err)
	}

	return nil
}

func (r *intentFeesRepo) ClearIntentFees(ctx context.Context) error {
	err := r.querier.ClearIntentFees(ctx, queries.ClearIntentFeesParams{
		CreatedAt: time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("failed to clear intent fees: %w", err)
	}

	return nil
}
func (r *intentFeesRepo) Close() {
}
