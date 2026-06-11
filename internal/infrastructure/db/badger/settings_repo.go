package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const (
	settingsStoreDir = "settings"
	settingsKey      = "settings"
)

type settingsRepository struct {
	store *badgerhold.Store

	updateHandlerMu *sync.Mutex
	updateHandler   func(domain.Settings, []string)
}

func NewSettingsRepository(config ...interface{}) (domain.SettingsRepository, error) {
	if len(config) != 2 {
		return nil, fmt.Errorf("invalid config")
	}
	baseDir, ok := config[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid base directory")
	}
	var logger badger.Logger
	if config[1] != nil {
		logger, ok = config[1].(badger.Logger)
		if !ok {
			return nil, fmt.Errorf("invalid logger")
		}
	}

	var dir string
	if len(baseDir) > 0 {
		dir = filepath.Join(baseDir, settingsStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open settings store: %s", err)
	}

	return &settingsRepository{
		store:           store,
		updateHandlerMu: &sync.Mutex{},
	}, nil
}

func (r *settingsRepository) RegisterUpdatesHandler(handler func(domain.Settings, []string)) {
	r.updateHandlerMu.Lock()
	defer r.updateHandlerMu.Unlock()
	r.updateHandler = handler
}

func (r *settingsRepository) Get(ctx context.Context) (*domain.Settings, error) {
	var settings domain.Settings
	err := r.store.Get(settingsKey, &settings)
	if errors.Is(err, badgerhold.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}
	return &settings, nil
}

func (r *settingsRepository) Upsert(
	ctx context.Context, settings domain.Settings, changelog []string,
) error {
	if err := r.store.Upsert(settingsKey, &settings); err != nil {
		if errors.Is(err, badger.ErrConflict) {
			attempts := 1
			for errors.Is(err, badger.ErrConflict) && attempts <= maxRetries {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(100 * time.Millisecond):
				}
				err = r.store.Upsert(settingsKey, &settings)
				attempts++
			}
		}
		return err
	}

	go r.dispatch(settings, changelog)

	return nil
}

func (r *settingsRepository) Clear(ctx context.Context) error {
	var settings domain.Settings
	if err := r.store.Delete(settingsKey, &settings); err != nil {
		if errors.Is(err, badgerhold.ErrNotFound) {
			return nil
		}
		return err
	}
	return nil
}

func (r *settingsRepository) Close() {
	// nolint:all
	r.store.Close()
}

func (r *settingsRepository) dispatch(settings domain.Settings, changelog []string) {
	if r.updateHandler != nil {
		r.updateHandler(settings, changelog)
	}
}
