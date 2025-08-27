package ports

import "context"

// Crypto is a service encrypting and decrypting seed data.
type Crypto interface {
	Encrypt(ctx context.Context, seed []byte, password string) (encryptedSeed []byte, err error)
	Decrypt(ctx context.Context, encryptedSeed []byte, password string) (seed []byte, err error)
}
