package badgerdb

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/arkade-os/arkd/pkg/arkd-wallet-nbxplorer/core/ports"
	"github.com/dgraph-io/badger/v4"
	log "github.com/sirupsen/logrus"
	"github.com/timshannon/badgerhold/v4"
)

const (
	seedStoreDir = "seed"
	seedKey      = "encrypted_seed"
)

type encryptedSeedDTO struct {
	Seed []byte
}

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

func (r *seedRepository) IsInitialized(ctx context.Context) bool {
	var dto encryptedSeedDTO
	err := r.store.Get(seedKey, &dto)
	if err != nil {
		return false
	}

	return len(dto.Seed) > 0
}

func (r *seedRepository) GetEncryptedSeed(ctx context.Context) ([]byte, error) {
	var dto encryptedSeedDTO

	err := r.store.Get(seedKey, &dto)
	if err != nil {
		if err == badgerhold.ErrNotFound {
			return nil, fmt.Errorf("encrypted seed not found")
		}
		return nil, fmt.Errorf("failed to get encrypted seed: %w", err)
	}

	return dto.Seed, nil
}

func (r *seedRepository) AddEncryptedSeed(ctx context.Context, seed []byte) error {
	dto := encryptedSeedDTO{Seed: seed}
	err := r.store.Upsert(seedKey, dto)
	if err != nil {
		return fmt.Errorf("failed to set encrypted seed: %w", err)
	}

	return nil
}

func (r *seedRepository) Close() {
	err := r.store.Close()
	if err != nil {
		log.Errorf("failed to close seed repository: %s", err)
	}
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
