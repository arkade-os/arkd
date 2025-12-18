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
	fmt.Printf("postgres getting latest intent fees...\n")
	row, err := r.querier.SelectLatestIntentFees(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return &domain.IntentFees{}, nil
		}
		return nil, fmt.Errorf("failed to get intent fees: %w", err)
	}
	fmt.Printf("postgres latest fees date: %d\n", row.CreatedAt)

	return &domain.IntentFees{
		OnchainInputFee:   row.OnchainInputFeeProgram,
		OffchainInputFee:  row.OffchainInputFeeProgram,
		OnchainOutputFee:  row.OnchainOutputFeeProgram,
		OffchainOutputFee: row.OffchainOutputFeeProgram,
	}, nil
}

func (r *intentFeesRepo) UpsertIntentFees(ctx context.Context, fees domain.IntentFees) error {
	fmt.Printf("postgres UpsertIntentFees: %+v\n", fees)
	// determine if any of the fees passed are empty, if so we need to grab existing fees to avoid overwriting with empty values
	if fees.OnchainInputFee == "" || fees.OffchainInputFee == "" || fees.OnchainOutputFee == "" ||
		fees.OffchainOutputFee == "" {
		fmt.Printf("one of the postgres fees was empty!!!\n")
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
	} else {
		fmt.Printf("all of the postgres fees were non-empty!!!\n")
		fmt.Printf("here they were: %+v\n", fees)
	}
	err := r.querier.AddIntentFees(ctx, queries.AddIntentFeesParams{
		CreatedAt:                time.Now().UnixMilli(),
		OnchainInputFeeProgram:   fees.OnchainInputFee,
		OffchainInputFeeProgram:  fees.OffchainInputFee,
		OnchainOutputFeeProgram:  fees.OnchainOutputFee,
		OffchainOutputFeeProgram: fees.OffchainOutputFee,
	})
	if err != nil {
		return fmt.Errorf("failed to upsert intent fees: %w", err)
	}
	fmt.Printf("postgres added the new intent fees\n")
	return nil
}

func (r *intentFeesRepo) ClearIntentFees(ctx context.Context) error {
	fmt.Printf("postgres intent_fees.go ClearIntentFees\n")
	err := r.querier.ClearIntentFees(ctx, time.Now().UnixMilli())
	if err != nil {
		return fmt.Errorf("failed to clear intent fees: %w", err)
	}

	return nil
}
func (r *intentFeesRepo) Close() {
}
