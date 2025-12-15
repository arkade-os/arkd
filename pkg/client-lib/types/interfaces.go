package types

import (
	"context"
)

type Store interface {
	ConfigStore() ConfigStore
	Clean(ctx context.Context)
	Close()
}

type ConfigStore interface {
	GetType() string
	GetDatadir() string
	AddData(ctx context.Context, data Config) error
	GetData(ctx context.Context) (*Config, error)
	CleanData(ctx context.Context) error
	Close()
}
