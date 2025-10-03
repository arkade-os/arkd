package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
)

type convictionRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewConvictionRepository(config ...interface{}) (domain.ConvictionRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf(
			"cannot open conviction repository: invalid config, expected db at 0",
		)
	}

	return &convictionRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (r *convictionRepository) Close() {
	// nolint:all
	r.db.Close()
}

func (r *convictionRepository) Get(ctx context.Context, id string) (domain.Conviction, error) {
	conviction, err := r.querier.SelectConviction(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
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
	currentTime := time.Now().Unix()

	convictions, err := r.querier.SelectActiveScriptConvictions(
		ctx,
		queries.SelectActiveScriptConvictionsParams{
			Script: sql.NullString{
				String: script,
				Valid:  true,
			},
			ExpiresAt: sql.NullInt64{
				Int64: currentTime,
				Valid: true,
			},
		},
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get active script convictions: %w", err)
	}

	domainConvictions := make([]domain.ScriptConviction, 0, len(convictions))
	for _, conviction := range convictions {
		domainConviction, err := r.convertToDomainConviction(conviction)
		if err != nil {
			return nil, fmt.Errorf("failed to convert conviction: %w", err)
		}
		domainConvictions = append(domainConvictions, domainConviction)
	}

	return domainConvictions, nil
}

func (r *convictionRepository) Add(ctx context.Context, convictions ...domain.Conviction) error {

	for _, conviction := range convictions {
		params, err := r.convertToDBParams(conviction)
		if err != nil {
			return fmt.Errorf("failed to convert conviction to db params: %w", err)
		}

		if err := r.querier.UpsertConviction(ctx, params); err != nil {
			return fmt.Errorf("failed to upsert conviction: %w", err)
		}
	}

	return nil
}

func (r *convictionRepository) GetAll(
	ctx context.Context,
	from, to time.Time,
) ([]domain.Conviction, error) {

	convictions, err := r.querier.SelectConvictionsInTimeRange(
		ctx,
		queries.SelectConvictionsInTimeRangeParams{
			FromTime: from.Unix(),
			ToTime:   to.Unix(),
		},
	)
	if err != nil {
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

	convictions, err := r.querier.SelectConvictionsByRoundID(ctx, roundID)
	if err != nil {
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

	if err := r.querier.UpdateConvictionPardoned(ctx, id); err != nil {
		return fmt.Errorf("failed to pardon conviction: %w", err)
	}

	return nil
}

func (r *convictionRepository) convertToDomainConviction(
	c queries.Conviction,
) (domain.ScriptConviction, error) {
	var expiresAt *time.Time
	if c.ExpiresAt.Valid {
		t := time.Unix(c.ExpiresAt.Int64, 0)
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

	if c.Script.Valid {
		return domain.ScriptConviction{
			BaseConviction: baseConviction,
			Script:         c.Script.String,
		}, nil
	}

	return domain.ScriptConviction{}, fmt.Errorf("unknown conviction type")
}

func (r *convictionRepository) convertToDBParams(
	conviction domain.Conviction,
) (queries.UpsertConvictionParams, error) {
	var expiresAt sql.NullInt64
	if conviction.GetExpiresAt() != nil {
		expiresAt = sql.NullInt64{
			Int64: conviction.GetExpiresAt().Unix(),
			Valid: true,
		}
	}

	var script sql.NullString
	if scriptConviction, ok := conviction.(domain.ScriptConviction); ok {
		script = sql.NullString{
			String: scriptConviction.Script,
			Valid:  true,
		}
	}

	return queries.UpsertConvictionParams{
		ID:           conviction.GetID(),
		Type:         int64(conviction.GetType()),
		CreatedAt:    conviction.GetCreatedAt().Unix(),
		ExpiresAt:    expiresAt,
		CrimeType:    int64(conviction.GetCrime().Type),
		CrimeRoundID: conviction.GetCrime().RoundID,
		CrimeReason:  conviction.GetCrime().Reason,
		Pardoned:     conviction.IsPardoned(),
		Script:       script,
	}, nil
}
