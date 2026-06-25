package types

import (
	"context"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
)

type Store interface {
	GetType() string
	GetDatadir() string
	AddData(ctx context.Context, data clientlib.ServerParams) error
	GetData(ctx context.Context) (*clientlib.ServerParams, error)
	Clean(ctx context.Context) error
	Close()
}
