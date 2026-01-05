package pgdb

import (
	"context"
	"database/sql"
	"fmt"

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

func (r *intentFeesRepo) UpdateIntentFees(ctx context.Context, fees domain.IntentFees) error {
	// do not allow empty updates
	emptyFees := domain.IntentFees{}
	if fees == emptyFees {
		return fmt.Errorf("missing fees to update")
	}

	if err := r.querier.AddIntentFees(ctx, queries.AddIntentFeesParams{
		OnchainInputFeeProgram:   fees.OnchainInputFee,
		OffchainInputFeeProgram:  fees.OffchainInputFee,
		OnchainOutputFeeProgram:  fees.OnchainOutputFee,
		OffchainOutputFeeProgram: fees.OffchainOutputFee,
	}); err != nil {
		return fmt.Errorf("failed to add intent fees: %w", err)
	}

	return nil
}

func (r *intentFeesRepo) ClearIntentFees(ctx context.Context) error {
	if err := r.querier.ClearIntentFees(ctx); err != nil {
		return fmt.Errorf("failed to clear intent fees: %w", err)
	}

	return nil
}
func (r *intentFeesRepo) Close() {
	// nolint:all
	r.db.Close()
}
