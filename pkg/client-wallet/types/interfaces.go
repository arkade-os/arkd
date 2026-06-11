package types

import (
	"context"
)

type Store interface {
	GetType() string
	GetDatadir() string
	AddData(ctx context.Context, data Config) error
	GetData(ctx context.Context) (*Config, error)
	Clean(ctx context.Context) error
	Close()
}
