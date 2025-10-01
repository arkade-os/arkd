package badgerdb

import (
	"context"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

type convictionRepository struct {
	store *badgerhold.Store
}

func NewConvictionRepository(config ...interface{}) (domain.ConvictionRepository, error) {
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
		return nil, fmt.Errorf("failed to open conviction store: %s", err)
	}

	return &convictionRepository{store}, nil
}

func (r *convictionRepository) Close() {
	// nolint:all
	r.store.Close()
}

func (r *convictionRepository) Get(ctx context.Context, id string) (domain.Conviction, error) {

	var conviction Conviction
	if err := r.store.FindOne(&conviction, badgerhold.Where("ID").Eq(id)); err != nil {
		if err == badgerhold.ErrNotFound {
			return nil, fmt.Errorf("conviction with id %s not found", id)
		}
		return nil, fmt.Errorf("failed to get conviction: %w", err)
	}

	return r.convertToDomainConviction(conviction)
}

func (r *convictionRepository) GetActiveScriptConvictions(
	ctx context.Context,
	script string,
) ([]domain.ScriptConviction, error) {
	currentTime := time.Now()

	// Get all convictions for the script that are not pardoned
	query := badgerhold.Where("Script").Eq(script).
		And("Pardoned").Eq(false)

	var allConvictions []Conviction
	if err := r.store.Find(&allConvictions, query); err != nil {
		return nil, fmt.Errorf("failed to get convictions: %w", err)
	}

	// Filter for active convictions in memory
	var activeConvictions []Conviction
	for _, c := range allConvictions {
		// Include convictions that never expire (ExpiresAt is nil)
		if c.ExpiresAt == nil {
			activeConvictions = append(activeConvictions, c)
			continue
		}

		// Include convictions that are not expired (ExpiresAt > currentTime)
		if *c.ExpiresAt > currentTime.Unix() {
			activeConvictions = append(activeConvictions, c)
		}
	}

	if len(activeConvictions) == 0 {
		return nil, nil
	}

	domainConvictions := make([]domain.ScriptConviction, 0, len(activeConvictions))
	for _, c := range activeConvictions {
		domainConviction, err := r.convertToDomainConviction(c)
		if err != nil {
			return nil, fmt.Errorf("failed to convert conviction: %w", err)
		}
		domainConvictions = append(domainConvictions, domainConviction)
	}

	return domainConvictions, nil
}

func (r *convictionRepository) Add(ctx context.Context, convictions ...domain.Conviction) error {

	for _, conviction := range convictions {
		dbConviction, err := r.convertToDBConviction(conviction)
		if err != nil {
			return fmt.Errorf("failed to convert conviction to db format: %w", err)
		}

		if err := r.store.Upsert(dbConviction.ID, dbConviction); err != nil {
			return fmt.Errorf("failed to upsert conviction: %w", err)
		}
	}

	return nil
}

func (r *convictionRepository) GetAll(
	ctx context.Context,
	from, to time.Time,
) ([]domain.Conviction, error) {
	var convictions []Conviction

	// Convert time.Time to Unix timestamp for comparison
	fromUnix := from.Unix()
	toUnix := to.Unix()

	query := badgerhold.Where("CreatedAt").Ge(fromUnix).And("CreatedAt").Le(toUnix)

	if err := r.store.Find(&convictions, query); err != nil {
		return nil, fmt.Errorf("failed to get convictions in time range: %w", err)
	}

	result := make([]domain.Conviction, len(convictions))
	for i, conviction := range convictions {
		domainConviction, err := r.convertToDomainConviction(conviction)
		if err != nil {
			return nil, fmt.Errorf("failed to convert conviction: %w", err)
		}
		result[i] = domainConviction
	}

	return result, nil
}

func (r *convictionRepository) GetByRoundID(
	ctx context.Context,
	roundID string,
) ([]domain.Conviction, error) {
	var convictions []Conviction

	query := badgerhold.Where("CrimeRoundID").Eq(roundID)

	if err := r.store.Find(&convictions, query); err != nil {
		return nil, fmt.Errorf("failed to get convictions by round ID: %w", err)
	}

	result := make([]domain.Conviction, len(convictions))
	for i, conviction := range convictions {
		domainConviction, err := r.convertToDomainConviction(conviction)
		if err != nil {
			return nil, fmt.Errorf("failed to convert conviction: %w", err)
		}
		result[i] = domainConviction
	}

	return result, nil
}

func (r *convictionRepository) Pardon(ctx context.Context, id string) error {

	var conviction Conviction
	if err := r.store.FindOne(&conviction, badgerhold.Where("ID").Eq(id)); err != nil {
		if err == badgerhold.ErrNotFound {
			return fmt.Errorf("conviction with id %s not found", id)
		}
		return fmt.Errorf("failed to get conviction: %w", err)
	}

	conviction.Pardoned = true

	if err := r.store.Upsert(conviction.ID, conviction); err != nil {
		return fmt.Errorf("failed to update conviction: %w", err)
	}

	return nil
}

func (r *convictionRepository) convertToDomainConviction(
	c Conviction,
) (domain.ScriptConviction, error) {
	var expiresAt *time.Time
	if c.ExpiresAt != nil {
		t := time.Unix(*c.ExpiresAt, 0)
		expiresAt = &t
	}

	crime := domain.Crime{
		Type:    domain.CrimeType(c.CrimeType),
		RoundID: c.CrimeRoundID,
		Reason:  c.CrimeReason,
	}

	baseConviction := domain.BaseConviction{
		ID:        c.ID,
		Type:      domain.ConvictionType(c.Type),
		CreatedAt: time.Unix(c.CreatedAt, 0),
		ExpiresAt: expiresAt,
		Crime:     crime,
		Pardoned:  c.Pardoned,
	}

	if c.Script != "" {
		return domain.ScriptConviction{
			BaseConviction: baseConviction,
			Script:         c.Script,
		}, nil
	}

	return domain.ScriptConviction{}, fmt.Errorf("unknown conviction type")
}

func (r *convictionRepository) convertToDBConviction(
	conviction domain.Conviction,
) (Conviction, error) {
	var expiresAt *int64
	if conviction.GetExpiresAt() != nil {
		ts := conviction.GetExpiresAt().Unix()
		expiresAt = &ts
	}

	var script string
	if scriptConviction, ok := conviction.(domain.ScriptConviction); ok {
		script = scriptConviction.Script
	}

	return Conviction{
		ID:           conviction.GetID(),
		Type:         int(conviction.GetType()),
		CreatedAt:    conviction.GetCreatedAt().Unix(),
		ExpiresAt:    expiresAt,
		CrimeType:    int(conviction.GetCrime().Type),
		CrimeRoundID: conviction.GetCrime().RoundID,
		CrimeReason:  conviction.GetCrime().Reason,
		Pardoned:     conviction.IsPardoned(),
		Script:       script,
	}, nil
}

// Conviction represents a conviction in the database
type Conviction struct {
	ID           string `badgerhold:"key"`
	Type         int
	CreatedAt    int64
	ExpiresAt    *int64
	CrimeType    int
	CrimeRoundID string
	CrimeReason  string
	Pardoned     bool
	Script       string
}
