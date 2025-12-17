package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
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
		return nil, fmt.Errorf(
			"cannot open intent fees repository: invalid config, expected db at 0",
		)
	}

	return &intentFeesRepo{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (r *intentFeesRepo) Close() {
	// nolint:all
	r.db.Close()
}

func (r *intentFeesRepo) GetIntentFees(ctx context.Context) (*domain.IntentFees, error) {
	intentFees, err := r.querier.SelectLatestIntentFees(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
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

func (r *intentFeesRepo) UpsertIntentFees(ctx context.Context, fees domain.IntentFees) error {
	// determine if any of the fees passed are empty, if so we need to grab existing fees to avoid overwriting with empty values
	if fees.OnchainInputFee == "" || fees.OffchainInputFee == "" || fees.OnchainOutputFee == "" ||
		fees.OffchainOutputFee == "" {
		currentIntentFees, err := r.querier.SelectLatestIntentFees(ctx)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("failed to get current intent fees: %w", err)
		}
		if fees.OnchainInputFee == "" {
			fees.OnchainInputFee = currentIntentFees.OnchainInputFeeProgram
		}
		if fees.OffchainInputFee == "" {
			fees.OffchainInputFee = currentIntentFees.OffchainInputFeeProgram
		}
		if fees.OnchainOutputFee == "" {
			fees.OnchainOutputFee = currentIntentFees.OnchainOutputFeeProgram
		}
		if fees.OffchainOutputFee == "" {
			fees.OffchainOutputFee = currentIntentFees.OffchainOutputFeeProgram
		}
	}
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
