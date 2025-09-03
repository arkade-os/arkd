package ports

import "context"

// SeedRepository is the service storing the encrypted seed data.
type SeedRepository interface {
	IsInitialized(context.Context) bool
	GetEncryptedSeed(context.Context) ([]byte, error)
	AddEncryptedSeed(context.Context, []byte) error
	Close()
}
