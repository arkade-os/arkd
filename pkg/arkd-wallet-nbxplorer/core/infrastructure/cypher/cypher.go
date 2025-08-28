package cypher

import (
	"context"
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/pbkdf2"

	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"
)

type cryptoService struct{}

func New() *cryptoService {
	return &cryptoService{}
}

func (c *cryptoService) Encrypt(_ context.Context, seed []byte, password string) ([]byte, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("missing plaintext private key")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("missing encryption password")
	}

	key, salt, err := deriveKey([]byte(password), nil)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, seed, nil)
	ciphertext = append(ciphertext, salt...)

	return ciphertext, nil
}

func (c *cryptoService) Decrypt(_ context.Context, encryptedSeed []byte, password string) ([]byte, error) {
	if len(encryptedSeed) == 0 {
		return nil, fmt.Errorf("missing encrypted seed")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("missing decryption password")
	}

	salt := encryptedSeed[len(encryptedSeed)-32:]
	data := encryptedSeed[:len(encryptedSeed)-32]

	key, _, err := deriveKey([]byte(password), salt)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce, text := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	// #nosec G407
	plaintext, err := gcm.Open(nil, nonce, text, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}
	return plaintext, nil
}

var lock sync.Mutex

// deriveKey derives a 32 byte array key from a custom passhprase
func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	lock.Lock()
	defer lock.Unlock()

	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	iterations := 10000
	keySize := 32
	key := pbkdf2.Key(password, salt, iterations, keySize, sha256.New)
	return key, salt, nil
}
