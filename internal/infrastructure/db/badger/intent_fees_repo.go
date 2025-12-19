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
	var all []intentFeesDTO
	if err := r.store.Find(&all, nil); err != nil && err != badgerhold.ErrNotFound {
		return nil, fmt.Errorf("failed to list intent fees: %w", err)
	}

	if len(all) == 0 {
		return nil, fmt.Errorf("no intent fees found")
	}

	latestIdx := 0
	for i := 1; i < len(all); i++ {
		if all[i].CreatedAt > all[latestIdx].CreatedAt {
			latestIdx = i
		}
	}
	intentFees := all[latestIdx]

	return &domain.IntentFees{
		OnchainInputFee:   intentFees.OnchainInputFeeProgram,
		OffchainInputFee:  intentFees.OffchainInputFeeProgram,
		OnchainOutputFee:  intentFees.OnchainOutputFeeProgram,
		OffchainOutputFee: intentFees.OffchainOutputFeeProgram,
	}, nil
}

func (r *intentFeesRepo) UpdateIntentFees(ctx context.Context, fees domain.IntentFees) error {
	var newEntry intentFeesDTO
	if fees.OnchainInputFee == "" || fees.OffchainInputFee == "" || fees.OnchainOutputFee == "" ||
		fees.OffchainOutputFee == "" {
		// load all entries and pick the most recent by CreatedAt
		var all []intentFeesDTO
		if err := r.store.Find(&all, nil); err != nil && err != badgerhold.ErrNotFound {
			return fmt.Errorf("failed to list intent fees: %w", err)
		}

		if len(all) == 0 {
			return fmt.Errorf("no intent fees found")
		}
		latestIdx := 0
		for i := 1; i < len(all); i++ {
			if all[i].CreatedAt > all[latestIdx].CreatedAt {
				latestIdx = i
			}
		}
		newEntry = all[latestIdx]
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
	_, err := arkfee.Parse(fees.OnchainInputFee, celenv.IntentOnchainInputEnv)
	if err != nil {
		return fmt.Errorf("invalid onchain input fee: %w", err)
	}
	_, err = arkfee.Parse(fees.OffchainInputFee, celenv.IntentOffchainInputEnv)
	if err != nil {
		return fmt.Errorf("invalid offchain input fee: %w", err)
	}
	_, err = arkfee.Parse(fees.OnchainOutputFee, celenv.IntentOutputEnv)
	if err != nil {
		return fmt.Errorf("invalid onchain output fee: %w", err)
	}
	_, err = arkfee.Parse(fees.OffchainOutputFee, celenv.IntentOutputEnv)
	if err != nil {
		return fmt.Errorf("invalid offchain output fee: %w", err)
	}

	if err := r.store.Insert(nowKey, &newEntry); err != nil {
		return fmt.Errorf("failed to insert intent fees: %w", err)
	}

	return nil
}

func (r *intentFeesRepo) ClearIntentFees(ctx context.Context) error {
	now := time.Now().UnixMilli()
	nowKey := fmt.Sprintf("intent_fees-%d", now)
	intentFees := intentFeesDTO{
		ID:                       nowKey,
		CreatedAt:                now,
		OnchainInputFeeProgram:   "0.0",
		OffchainInputFeeProgram:  "0.0",
		OnchainOutputFeeProgram:  "0.0",
		OffchainOutputFeeProgram: "0.0",
	}

	if err := r.store.Insert(nowKey, &intentFees); err != nil {
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
