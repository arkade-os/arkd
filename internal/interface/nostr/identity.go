package nostr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	nostr "github.com/nbd-wtf/go-nostr"
)

// Identity is the server's long-lived Nostr keypair. The private key is
// persisted to disk so the server keeps a stable Nostr pubkey across restarts.
type Identity struct {
	privKey string // 32-byte hex-encoded secret key
	pubKey  string // 32-byte hex-encoded x-only public key
}

// LoadOrCreate loads the Nostr private key from keyPath, or generates and
// persists a new one if the file does not yet exist. The key file is written
// with 0600 permissions since it holds a secret.
func LoadOrCreate(keyPath string) (*Identity, error) {
	if raw, err := os.ReadFile(keyPath); err == nil {
		sk := strings.TrimSpace(string(raw))
		return fromPrivateKey(sk)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read nostr key file %q: %w", keyPath, err)
	}

	sk := nostr.GeneratePrivateKey()
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create nostr key dir: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(sk), 0600); err != nil {
		return nil, fmt.Errorf("failed to persist nostr key file %q: %w", keyPath, err)
	}
	return fromPrivateKey(sk)
}

func fromPrivateKey(sk string) (*Identity, error) {
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		return nil, fmt.Errorf("invalid nostr private key: %w", err)
	}
	return &Identity{privKey: sk, pubKey: pk}, nil
}

// PubKeyHex returns the hex-encoded x-only public key.
func (i *Identity) PubKeyHex() string { return i.pubKey }

// PrivKeyHex returns the hex-encoded private key. Keep it secret.
func (i *Identity) PrivKeyHex() string { return i.privKey }
