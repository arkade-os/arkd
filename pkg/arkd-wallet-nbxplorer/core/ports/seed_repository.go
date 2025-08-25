package ports

import "context"

type SeedRepository interface {
	GetEncryptedSeed(context.Context) ([]byte, error)
	SetEncryptedSeed(context.Context, []byte) error
}
