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
		return nil, fmt.Errorf("failed to open intent fees store: %w", err)
	}

	return &intentFeesRepo{store}, nil
}

func (r *intentFeesRepo) Close() {
	// nolint:all
	r.store.Close()
}

func (r *intentFeesRepo) GetIntentFees(ctx context.Context) (*domain.IntentFees, error) {
	var latest intentFeesDTO

	// get the most recent intent fees
	query := new(badgerhold.Query).
		SortBy("CreatedAt").
		Reverse().
		Limit(1)

	err := r.store.FindOne(&latest, query)
	if err != nil {
		if err == badgerhold.ErrNotFound {
			return &domain.IntentFees{}, nil
		}
		return nil, fmt.Errorf("failed to get latest intent fees: %w", err)
	}

	return &domain.IntentFees{
		OnchainInputFee:   latest.OnchainInputFeeProgram,
		OffchainInputFee:  latest.OffchainInputFeeProgram,
		OnchainOutputFee:  latest.OnchainOutputFeeProgram,
		OffchainOutputFee: latest.OffchainOutputFeeProgram,
	}, nil
}

func (r *intentFeesRepo) UpdateIntentFees(ctx context.Context, fees domain.IntentFees) error {
	// do not allow empty updates
	emptyFees := domain.IntentFees{}
	if fees == emptyFees {
		return fmt.Errorf("missing fees to update")
	}

	var newEntry intentFeesDTO
	if fees.OnchainInputFee == "" || fees.OffchainInputFee == "" || fees.OnchainOutputFee == "" ||
		fees.OffchainOutputFee == "" {
		// fetch existing fees to allow partial updates
		existingFees, err := r.GetIntentFees(ctx)
		if err != nil {
			return fmt.Errorf("failed to get existing intent fees for partial update: %w", err)
		}
		newEntry.OnchainInputFeeProgram = existingFees.OnchainInputFee
		newEntry.OffchainInputFeeProgram = existingFees.OffchainInputFee
		newEntry.OnchainOutputFeeProgram = existingFees.OnchainOutputFee
		newEntry.OffchainOutputFeeProgram = existingFees.OffchainOutputFee
	}

	now := time.Now().UnixMilli()
	nowKey := fmt.Sprintf("intent_fees-%d", now)
	newEntry.ID = nowKey
	newEntry.CreatedAt = now

	// allow partial updates to fees by using existing values if empty
	if fees.OnchainInputFee != "" {
		newEntry.OnchainInputFeeProgram = fees.OnchainInputFee
	}
	if fees.OffchainInputFee != "" {
		newEntry.OffchainInputFeeProgram = fees.OffchainInputFee
	}
	if fees.OnchainOutputFee != "" {
		newEntry.OnchainOutputFeeProgram = fees.OnchainOutputFee
	}
	if fees.OffchainOutputFee != "" {
		newEntry.OffchainOutputFeeProgram = fees.OffchainOutputFee
	}
	if err := r.store.Insert(nowKey, &newEntry); err != nil {
		return fmt.Errorf("failed to insert intent fees: %w", err)
	}

	return nil
}

func (r *intentFeesRepo) ClearIntentFees(ctx context.Context) error {
	now := time.Now().UnixMilli()
	nowKey := fmt.Sprintf("intent_fees-%d", now)
	newEntry := intentFeesDTO{
		ID:                       nowKey,
		CreatedAt:                now,
		OnchainInputFeeProgram:   "",
		OffchainInputFeeProgram:  "",
		OnchainOutputFeeProgram:  "",
		OffchainOutputFeeProgram: "",
	}

	if err := r.store.Insert(nowKey, &newEntry); err != nil {
		return fmt.Errorf("failed to clear intent fees: %w", err)
	}

	return nil
}

type intentFeesDTO struct {
	ID                       string `badgerhold:"key"`
	CreatedAt                int64
	OnchainInputFeeProgram   string
	OffchainInputFeeProgram  string
	OnchainOutputFeeProgram  string
	OffchainOutputFeeProgram string
}
