package ports

import "context"

type Crypto interface {
	Encrypt(ctx context.Context, seed []byte, password string) (encryptedSeed []byte, err error)
	Decrypt(ctx context.Context, encryptedSeed []byte, password string) (seed []byte, err error)
}
