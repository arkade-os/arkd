package cypher

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
	if len(seed) == 0 {
		return nil, fmt.Errorf("seed is empty")
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	key, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, seed, nil)

	encryptedData := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	encryptedData = append(encryptedData, salt...)
	encryptedData = append(encryptedData, nonce...)
	encryptedData = append(encryptedData, ciphertext...)

	return encryptedData, nil
}

// Decrypt decrypts the encrypted seed using AES-GCM with a key derived from the password using scrypt
func (c *cryptoService) Decrypt(ctx context.Context, encryptedSeed []byte, password string) (seed []byte, err error) {
	if len(encryptedSeed) < saltSize+nonceSize+1 {
		return nil, fmt.Errorf("encrypted data too short: got %d bytes, need at least %d", len(encryptedSeed), saltSize+nonceSize+1)
	}

	// Extract salt, nonce, and ciphertext
	salt := encryptedSeed[:saltSize]
	nonce := encryptedSeed[saltSize : saltSize+nonceSize]
	ciphertext := encryptedSeed[saltSize+nonceSize:]

	if len(salt) != saltSize {
		return nil, fmt.Errorf("invalid salt length: got %d, expected %d", len(salt), saltSize)
	}
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("invalid nonce length: got %d, expected %d", len(nonce), nonceSize)
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext is empty")
	}

	key, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w (data length: %d, salt: %x, nonce: %x)",
			err, len(encryptedSeed), salt[:4], nonce[:4])
	}

	return plaintext, nil
}
