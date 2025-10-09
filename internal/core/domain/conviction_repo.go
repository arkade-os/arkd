package domain

import (
	"context"
	"time"
)

type ConvictionRepository interface {
	Get(ctx context.Context, id string) (Conviction, error)
	GetAll(ctx context.Context, from, to time.Time) ([]Conviction, error)
	GetByRoundID(ctx context.Context, roundID string) ([]Conviction, error)
	// GetActiveScriptConviction returns all not-expired convictions associated with a given script
	GetActiveScriptConvictions(ctx context.Context, script string) ([]ScriptConviction, error)
	Add(ctx context.Context, convictions ...Conviction) error
	Pardon(ctx context.Context, id string) error
	Close()
}
