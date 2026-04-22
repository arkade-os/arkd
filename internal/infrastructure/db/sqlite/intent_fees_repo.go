package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
)

type intentFeesRepo struct {
	db SQLiteDB
}

func NewIntentFeesRepository(config ...interface{}) (domain.FeeRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(SQLiteDB)
	if !ok {
		return nil, fmt.Errorf(
			"cannot open intent fees repository: invalid config, expected db at 0",
		)
	}

	return &intentFeesRepo{
		db: db,
	}, nil
}

func (r *intentFeesRepo) Close() {
	// nolint:all
	r.db.Close()
}

func (r *intentFeesRepo) GetIntentFees(ctx context.Context) (*domain.IntentFees, error) {
	var intentFees queries.IntentFee
	if err := withReadQuerier(ctx, r.db, func(q *queries.Queries) error {
		var err error
		intentFees, err = q.SelectLatestIntentFees(ctx)
		return err
	}); err != nil {
		if err == sql.ErrNoRows {
			return &domain.IntentFees{}, nil
		}
		return nil, fmt.Errorf("failed to get intent fees: %w", err)
	}

	return &domain.IntentFees{
		OnchainInputFee:   intentFees.OnchainInputFeeProgram,
		OffchainInputFee:  intentFees.OffchainInputFeeProgram,
		OnchainOutputFee:  intentFees.OnchainOutputFeeProgram,
		OffchainOutputFee: intentFees.OffchainOutputFeeProgram,
	}, nil
}

func (r *intentFeesRepo) UpdateIntentFees(ctx context.Context, fees domain.IntentFees) error {
	// do not allow empty updates
	emptyFees := domain.IntentFees{}
	if fees == emptyFees {
		return fmt.Errorf("missing fees to update")
	}

	if err := withWriteQuerier(ctx, r.db, func(q *queries.Queries) error {
		return q.AddIntentFees(ctx, queries.AddIntentFeesParams{
			OnchainInputFeeProgram:   fees.OnchainInputFee,
			OffchainInputFeeProgram:  fees.OffchainInputFee,
			OnchainOutputFeeProgram:  fees.OnchainOutputFee,
			OffchainOutputFeeProgram: fees.OffchainOutputFee,
		})
	}); err != nil {
		return fmt.Errorf("failed to add intent fees: %w", err)
	}

	return nil
}

func (r *intentFeesRepo) ClearIntentFees(ctx context.Context) error {
	if err := withWriteQuerier(ctx, r.db, func(q *queries.Queries) error {
		return q.ClearIntentFees(ctx)
	}); err != nil {
		return fmt.Errorf("failed to clear intent fees: %w", err)
	}

	return nil
}
