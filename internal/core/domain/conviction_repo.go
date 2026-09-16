package domain

import (
	"context"
	"time"
)

type ConvictionRepository interface {
	Get(ctx context.Context, id string) (Conviction, error)
	GetAll(ctx context.Context, from, to time.Time) ([]Conviction, error)
	GetByRoundID(ctx context.Context, roundID string) ([]Conviction, error)
	// GetActiveScriptsConvictions returns all non-expired convictions for the given list of
	// scripts. It returns a map script -> list of convictions. If a script has no convictions, it
	// will not be present in the map.
	GetActiveScriptsConvictions(
		ctx context.Context, scripts []string,
	) (map[string][]ScriptConviction, error)
	Add(ctx context.Context, convictions ...Conviction) error
	Pardon(ctx context.Context, id string) error
	Close()
}
