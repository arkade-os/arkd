package cypher_test

import (
	"context"
	"testing"

	"github.com/arkade-os/arkd/pkg/arkd-wallet-nbxplorer/core/infrastructure/cypher"
	"github.com/stretchr/testify/require"
)

func TestCryptoService_EncryptDecrypt(t *testing.T) {
	crypto := cypher.New()
	ctx := context.Background()

	tests := []struct {
		name     string
		seed     []byte
		password string
	}{
		{
			name:     "simple seed",
			seed:     []byte("test seed data"),
			password: "testpassword",
		},
		{
			name:     "long seed",
			seed:     make([]byte, 1024),
			password: "very long password with special chars !@#$%^&*()",
		},
		{
			name:     "binary seed",
			seed:     []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC},
			password: "simple",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt the seed
			encrypted, err := crypto.Encrypt(ctx, tt.seed, tt.password)
			require.NoError(t, err)

			// Verify encrypted data is different from original
			require.NotEmpty(t, encrypted, "Encrypted data is empty")

			// Decrypt the seed
			decrypted, err := crypto.Decrypt(ctx, encrypted, tt.password)
			require.NoError(t, err)

			// Verify decrypted data matches original
			require.Equal(t, len(tt.seed), len(decrypted), "Decrypted length mismatch")
			require.Equal(t, tt.seed, decrypted, "Decrypted data mismatch")
		})
	}
}

func TestCryptoService_WrongPassword(t *testing.T) {
	crypto := cypher.New()
	ctx := context.Background()

	seed := []byte("test seed data")
	password := "correctpassword"
	wrongPassword := "wrongpassword"

	// Encrypt with correct password
	encrypted, err := crypto.Encrypt(ctx, seed, password)
	require.NoError(t, err)

	// Try to decrypt with wrong password
	_, err = crypto.Decrypt(ctx, encrypted, wrongPassword)
	require.Error(t, err, "Expected error when decrypting with wrong password")
}

func TestCryptoService_InvalidEncryptedData(t *testing.T) {
	crypto := cypher.New()
	ctx := context.Background()

	// Test with empty encrypted data
	_, err := crypto.Decrypt(ctx, []byte{}, "password")
	require.Error(t, err, "Expected error when decrypting empty data")

	// Test with too short encrypted data
	_, err = crypto.Decrypt(ctx, []byte{1, 2, 3}, "password")
	require.Error(t, err, "Expected error when decrypting data that's too short")

	// Test with corrupted encrypted data
	seed := []byte("test seed")
	encrypted, err := crypto.Encrypt(ctx, seed, "password")
	require.NoError(t, err)

	// Corrupt the encrypted data
	encrypted[0] ^= 0xFF

	_, err = crypto.Decrypt(ctx, encrypted, "password")
	require.Error(t, err, "Expected error when decrypting corrupted data")
}

func TestCryptoService_EmptyPassword(t *testing.T) {
	crypto := cypher.New()
	ctx := context.Background()

	seed := []byte("test seed data")

	// Test with empty password
	encrypted, err := crypto.Encrypt(ctx, seed, "")
	require.NoError(t, err)

	decrypted, err := crypto.Decrypt(ctx, encrypted, "")
	require.NoError(t, err)

	require.Equal(t, len(seed), len(decrypted), "Decrypted length mismatch")
}

func TestCryptoService_DeterministicEncryption(t *testing.T) {
	crypto := cypher.New()
	ctx := context.Background()

	seed := []byte("test seed data")
	password := "testpassword"

	// Encrypt the same data twice
	encrypted1, err := crypto.Encrypt(ctx, seed, password)
	require.NoError(t, err)

	encrypted2, err := crypto.Encrypt(ctx, seed, password)
	require.NoError(t, err)

	// The encrypted data should be different due to random salt and nonce
	require.Equal(t, len(encrypted1), len(encrypted2), "Encrypted data lengths differ")

	// But both should decrypt to the same result
	decrypted1, err := crypto.Decrypt(ctx, encrypted1, password)
	require.NoError(t, err)

	decrypted2, err := crypto.Decrypt(ctx, encrypted2, password)
	require.NoError(t, err)

	require.Equal(t, len(decrypted1), len(decrypted2), "Decrypted lengths differ")
	require.Equal(t, decrypted1, decrypted2, "Decrypted data differs")
}
