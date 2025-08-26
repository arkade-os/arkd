package ports

import "context"

type SeedRepository interface {
	IsInitialized(context.Context) bool
	GetEncryptedSeed(context.Context) ([]byte, error)
	SetEncryptedSeed(context.Context, []byte) error
}
