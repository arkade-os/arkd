package badgerdb

import (
	"context"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

type intentFeesRepo struct {
	store *badgerhold.Store
}

func NewIntentFeesRepository(config ...interface{}) (domain.FeeRepository, error) {
	if len(config) != 2 {
		return nil, fmt.Errorf("invalid config")
	}
	baseDir, ok := config[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid base directory")
	}
	var logger badger.Logger
	if config[1] != nil {
		logger, ok = config[1].(badger.Logger)
		if !ok {
			return nil, fmt.Errorf("invalid logger")
		}
	}

	var dir string
	if len(baseDir) > 0 {
		dir = baseDir
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open intent fees store: %s", err)
	}

	repo := &intentFeesRepo{store}
	// only initialize intent fees if none exist in the DB
	var existing IntentFees
	err = repo.store.FindOne(&existing, badgerhold.Where("ID").Eq("intent_fees"))
	if err != nil {
		if err == badgerhold.ErrNotFound {
			// initialize intent fees to zero values
			if cerr := repo.ClearIntentFees(context.Background()); cerr != nil {
				return nil, fmt.Errorf("failed to initialize intent fees: %w", cerr)
			}
		} else {
			return nil, fmt.Errorf("failed to check existing intent fees: %w", err)
		}
	}

	return repo, nil
}

func (r *intentFeesRepo) Close() {
	// nolint:all
	r.store.Close()
}

func (r *intentFeesRepo) GetIntentFees(ctx context.Context) (*domain.IntentFees, error) {
	var intentFees IntentFees
	if err := r.store.FindOne(&intentFees, badgerhold.Where("ID").Eq("intent_fees")); err != nil {
		if err == badgerhold.ErrNotFound {
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
	var existing IntentFees
	err := r.store.FindOne(&existing, badgerhold.Where("ID").Eq("intent_fees"))
	if err != nil && err != badgerhold.ErrNotFound {
		return fmt.Errorf("failed to get existing intent fees: %w", err)
	}

	// Start from existing values (if any), then overwrite only non-empty incoming fields.
	// This allows for partial updates.
	intentFees := existing
	if intentFees.ID == "" {
		intentFees.ID = "intent_fees"
	}
	// update timestamp
	intentFees.CreatedAt = time.Now().Unix()

	if fees.OnchainInputFee != "" {
		intentFees.OnchainInputFeeProgram = fees.OnchainInputFee
	}
	if fees.OffchainInputFee != "" {
		intentFees.OffchainInputFeeProgram = fees.OffchainInputFee
	}
	if fees.OnchainOutputFee != "" {
		intentFees.OnchainOutputFeeProgram = fees.OnchainOutputFee
	}
	if fees.OffchainOutputFee != "" {
		intentFees.OffchainOutputFeeProgram = fees.OffchainOutputFee
	}

	if err := r.store.Upsert("intent_fees", &intentFees); err != nil {
		return fmt.Errorf("failed to upsert intent fees: %w", err)
	}

	return nil
}

func (r *intentFeesRepo) ClearIntentFees(ctx context.Context) error {
	intentFees := IntentFees{
		ID:                       "intent_fees",
		CreatedAt:                time.Now().Unix(),
		OnchainInputFeeProgram:   "0.0",
		OffchainInputFeeProgram:  "0.0",
		OnchainOutputFeeProgram:  "0.0",
		OffchainOutputFeeProgram: "0.0",
	}

	if err := r.store.Upsert("intent_fees", &intentFees); err != nil {
		return fmt.Errorf("failed to clear intent fees: %w", err)
	}

	return nil
}

type IntentFees struct {
	ID                       string `badgerhold:"key"`
	CreatedAt                int64
	OnchainInputFeeProgram   string
	OffchainInputFeeProgram  string
	OnchainOutputFeeProgram  string
	OffchainOutputFeeProgram string
}
