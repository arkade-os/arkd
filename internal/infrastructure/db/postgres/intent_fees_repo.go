package pgdb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/postgres/sqlc/queries"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee/celenv"
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
			return nil, fmt.Errorf("no intent fees found")
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

	if fees.OnchainInputFee != "" {
		_, err := arkfee.Parse(fees.OnchainInputFee, celenv.IntentOnchainInputEnv)
		if err != nil {
			return fmt.Errorf("invalid onchain input fee: %w", err)
		}
	}

	if fees.OffchainInputFee != "" {
		_, err := arkfee.Parse(fees.OffchainInputFee, celenv.IntentOffchainInputEnv)
		if err != nil {
			return fmt.Errorf("invalid offchain input fee: %w", err)
		}
	}
	if fees.OnchainOutputFee != "" {
		_, err := arkfee.Parse(fees.OnchainOutputFee, celenv.IntentOutputEnv)
		if err != nil {
			return fmt.Errorf("invalid onchain output fee: %w", err)
		}
	}
	if fees.OffchainOutputFee != "" {
		_, err := arkfee.Parse(fees.OffchainOutputFee, celenv.IntentOutputEnv)
		if err != nil {
			return fmt.Errorf("invalid offchain output fee: %w", err)
		}
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
	if err := r.UpdateIntentFees(ctx, domain.IntentFees{
		OnchainInputFee:   "0.0",
		OffchainInputFee:  "0.0",
		OnchainOutputFee:  "0.0",
		OffchainOutputFee: "0.0",
	}); err != nil {
		return fmt.Errorf("failed to clear intent fees: %w", err)
	}

	return nil
}
func (r *intentFeesRepo) Close() {
}
