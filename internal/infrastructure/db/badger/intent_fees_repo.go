package badgerdb

import (
	"context"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee/celenv"
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

	repo := &intentFeesRepo{store}
	// only initialize intent fees if none exist in the DB
	var all []intentFeesDTO
	err = repo.store.Find(&all, nil)
	if err != nil && err != badgerhold.ErrNotFound {
		return nil, fmt.Errorf("failed to check existing intent fees: %w", err)
	}

	if len(all) == 0 {
		if err := repo.ClearIntentFees(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to initialize intent fees: %w", err)
		}
	}

	return repo, nil
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
			return nil, fmt.Errorf("no intent fees found")
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
		_, err := arkfee.Parse(fees.OnchainInputFee, celenv.IntentOnchainInputEnv)
		if err != nil {
			return fmt.Errorf("invalid onchain input fee: %w", err)
		}
		newEntry.OnchainInputFeeProgram = fees.OnchainInputFee
	}
	if fees.OffchainInputFee != "" {
		_, err := arkfee.Parse(fees.OffchainInputFee, celenv.IntentOffchainInputEnv)
		if err != nil {
			return fmt.Errorf("invalid offchain input fee: %w", err)
		}
		newEntry.OffchainInputFeeProgram = fees.OffchainInputFee
	}
	if fees.OnchainOutputFee != "" {
		_, err := arkfee.Parse(fees.OnchainOutputFee, celenv.IntentOutputEnv)
		if err != nil {
			return fmt.Errorf("invalid onchain output fee: %w", err)
		}
		newEntry.OnchainOutputFeeProgram = fees.OnchainOutputFee
	}
	if fees.OffchainOutputFee != "" {
		_, err := arkfee.Parse(fees.OffchainOutputFee, celenv.IntentOutputEnv)
		if err != nil {
			return fmt.Errorf("invalid offchain output fee: %w", err)
		}
		newEntry.OffchainOutputFeeProgram = fees.OffchainOutputFee
	}

	if err := r.store.Insert(nowKey, &newEntry); err != nil {
		return fmt.Errorf("failed to insert intent fees: %w", err)
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

type intentFeesDTO struct {
	ID                       string `badgerhold:"key"`
	CreatedAt                int64
	OnchainInputFeeProgram   string
	OffchainInputFeeProgram  string
	OnchainOutputFeeProgram  string
	OffchainOutputFeeProgram string
}
