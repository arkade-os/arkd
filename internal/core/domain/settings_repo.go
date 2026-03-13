package domain

import "context"

type SettingsRepository interface {
	Get(ctx context.Context) (*Settings, error)
	Upsert(ctx context.Context, settings Settings) error
	Clear(ctx context.Context) error
	Close()
}
