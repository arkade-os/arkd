package db

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/arkade-os/arkd/pkg/arkd-wallet-nbxplorer/core/ports"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const (
	seedStoreDir = "seed"
	seedKey      = "encrypted_seed"
)

type seedRepository struct {
	store *badgerhold.Store
}

func NewSeedRepository(baseDir string, logger badger.Logger) (ports.SeedRepository, error) {
	var dir string
	if baseDir != "" {
		dir = filepath.Join(baseDir, seedStoreDir)
	}

	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open seed store: %w", err)
	}

	return &seedRepository{store: store}, nil
}

func (r *seedRepository) GetEncryptedSeed(ctx context.Context) ([]byte, error) {
	var seed []byte

	err := r.store.Get(seedKey, &seed)
	if err != nil {
		if err == badgerhold.ErrNotFound {
			return nil, fmt.Errorf("encrypted seed not found")
		}
		return nil, fmt.Errorf("failed to get encrypted seed: %w", err)
	}

	return seed, nil
}

func (r *seedRepository) SetEncryptedSeed(ctx context.Context, seed []byte) error {
	err := r.store.Upsert(seedKey, seed)
	if err != nil {
		return fmt.Errorf("failed to set encrypted seed: %w", err)
	}

	return nil
}

func createDB(dbDir string, logger badger.Logger) (*badgerhold.Store, error) {
	isInMemory := len(dbDir) <= 0

	opts := badger.DefaultOptions(dbDir)
	opts.Logger = logger

	if isInMemory {
		opts.InMemory = true
	}

	db, err := badgerhold.Open(badgerhold.Options{
		Encoder:          badgerhold.DefaultEncode,
		Decoder:          badgerhold.DefaultDecode,
		SequenceBandwith: 100,
		Options:          opts,
	})
	if err != nil {
		return nil, err
	}

	return db, nil
}
