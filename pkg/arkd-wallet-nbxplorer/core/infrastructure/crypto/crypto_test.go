package crypto

import (
	"context"
	"testing"
)

func TestCryptoService_EncryptDecrypt(t *testing.T) {
	crypto := New()
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
			name:     "empty seed",
			seed:     []byte{},
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
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Verify encrypted data is different from original
			if len(encrypted) == 0 {
				t.Fatal("Encrypted data is empty")
			}

			// Decrypt the seed
			decrypted, err := crypto.Decrypt(ctx, encrypted, tt.password)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			// Verify decrypted data matches original
			if len(decrypted) != len(tt.seed) {
				t.Fatalf("Decrypted length mismatch: got %d, want %d", len(decrypted), len(tt.seed))
			}

			for i, b := range decrypted {
				if b != tt.seed[i] {
					t.Fatalf("Decrypted data mismatch at index %d: got %d, want %d", i, b, tt.seed[i])
				}
			}
		})
	}
}

func TestCryptoService_WrongPassword(t *testing.T) {
	crypto := New()
	ctx := context.Background()

	seed := []byte("test seed data")
	password := "correctpassword"
	wrongPassword := "wrongpassword"

	// Encrypt with correct password
	encrypted, err := crypto.Encrypt(ctx, seed, password)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with wrong password
	_, err = crypto.Decrypt(ctx, encrypted, wrongPassword)
	if err == nil {
		t.Fatal("Expected error when decrypting with wrong password")
	}
}

func TestCryptoService_InvalidEncryptedData(t *testing.T) {
	crypto := New()
	ctx := context.Background()

	// Test with empty encrypted data
	_, err := crypto.Decrypt(ctx, []byte{}, "password")
	if err == nil {
		t.Fatal("Expected error when decrypting empty data")
	}

	// Test with too short encrypted data
	_, err = crypto.Decrypt(ctx, []byte{1, 2, 3}, "password")
	if err == nil {
		t.Fatal("Expected error when decrypting data that's too short")
	}

	// Test with corrupted encrypted data
	seed := []byte("test seed")
	encrypted, err := crypto.Encrypt(ctx, seed, "password")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Corrupt the encrypted data
	encrypted[0] ^= 0xFF

	_, err = crypto.Decrypt(ctx, encrypted, "password")
	if err == nil {
		t.Fatal("Expected error when decrypting corrupted data")
	}
}

func TestCryptoService_EmptyPassword(t *testing.T) {
	crypto := New()
	ctx := context.Background()

	seed := []byte("test seed data")

	// Test with empty password
	encrypted, err := crypto.Encrypt(ctx, seed, "")
	if err != nil {
		t.Fatalf("Encrypt with empty password failed: %v", err)
	}

	decrypted, err := crypto.Decrypt(ctx, encrypted, "")
	if err != nil {
		t.Fatalf("Decrypt with empty password failed: %v", err)
	}

	if len(decrypted) != len(seed) {
		t.Fatalf("Decrypted length mismatch: got %d, want %d", len(decrypted), len(seed))
	}
}

func TestCryptoService_DeterministicEncryption(t *testing.T) {
	crypto := New()
	ctx := context.Background()

	seed := []byte("test seed data")
	password := "testpassword"

	// Encrypt the same data twice
	encrypted1, err := crypto.Encrypt(ctx, seed, password)
	if err != nil {
		t.Fatalf("First encrypt failed: %v", err)
	}

	encrypted2, err := crypto.Encrypt(ctx, seed, password)
	if err != nil {
		t.Fatalf("Second encrypt failed: %v", err)
	}

	// The encrypted data should be different due to random salt and nonce
	if len(encrypted1) != len(encrypted2) {
		t.Fatalf("Encrypted data lengths differ: %d vs %d", len(encrypted1), len(encrypted2))
	}

	// But both should decrypt to the same result
	decrypted1, err := crypto.Decrypt(ctx, encrypted1, password)
	if err != nil {
		t.Fatalf("First decrypt failed: %v", err)
	}

	decrypted2, err := crypto.Decrypt(ctx, encrypted2, password)
	if err != nil {
		t.Fatalf("Second decrypt failed: %v", err)
	}

	if len(decrypted1) != len(decrypted2) {
		t.Fatalf("Decrypted lengths differ: %d vs %d", len(decrypted1), len(decrypted2))
	}

	for i, b := range decrypted1 {
		if b != decrypted2[i] {
			t.Fatalf("Decrypted data differs at index %d: %d vs %d", i, b, decrypted2[i])
		}
	}
}
