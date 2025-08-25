package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

const (
	// Scrypt parameters for key derivation
	scryptN = 32768 // CPU/memory cost parameter
	scryptR = 8     // Block size parameter
	scryptP = 1     // Parallelization parameter

	// AES-GCM parameters
	saltSize  = 32
	nonceSize = 12
)

type cryptoService struct{}

func New() *cryptoService {
	return &cryptoService{}
}

// Encrypt encrypts the seed using AES-GCM with a key derived from the password using scrypt
func (c *cryptoService) Encrypt(ctx context.Context, seed []byte, password string) (encryptedSeed []byte, err error) {
	// Generate a random salt for key derivation
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive encryption key from password using scrypt
	key, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the seed
	ciphertext := gcm.Seal(nil, nonce, seed, nil)

	// Combine salt + nonce + ciphertext
	encryptedData := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	encryptedData = append(encryptedData, salt...)
	encryptedData = append(encryptedData, nonce...)
	encryptedData = append(encryptedData, ciphertext...)

	return encryptedData, nil
}

// Decrypt decrypts the encrypted seed using AES-GCM with a key derived from the password using scrypt
func (c *cryptoService) Decrypt(ctx context.Context, encryptedSeed []byte, password string) (seed []byte, err error) {
	// Check minimum length (salt + nonce + at least some ciphertext)
	if len(encryptedSeed) < saltSize+nonceSize+1 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract salt, nonce, and ciphertext
	salt := encryptedSeed[:saltSize]
	nonce := encryptedSeed[saltSize : saltSize+nonceSize]
	ciphertext := encryptedSeed[saltSize+nonceSize:]

	// Derive encryption key from password using scrypt
	key, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the seed
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}
