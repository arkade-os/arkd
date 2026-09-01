package domain

import (
	"context"
)

type SettingsRepository interface {
	Get(ctx context.Context) (*Settings, error)
	Upsert(ctx context.Context, settings Settings, changelog []string) error
	RegisterUpdatesHandler(handler func(Settings, []string))
	Close()
}
