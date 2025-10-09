package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const (
	scheduledSessionStoreDir = "scheduled_session"
	scheduledSessionKey      = "scheduled_session"
)

type scheduledSessionRepository struct {
	store *badgerhold.Store
}

func NewScheduledSessionRepository(config ...interface{}) (domain.ScheduledSessionRepo, error) {
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
		dir = filepath.Join(baseDir, scheduledSessionStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open scheduled session store: %s", err)
	}

	return &scheduledSessionRepository{store}, nil
}

func (r *scheduledSessionRepository) Get(ctx context.Context) (*domain.ScheduledSession, error) {
	var scheduledSession domain.ScheduledSession
	err := r.store.Get(scheduledSessionKey, &scheduledSession)
	if errors.Is(err, badgerhold.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get scheduled session: %w", err)
	}
	return &scheduledSession, nil
}

func (r *scheduledSessionRepository) Upsert(
	ctx context.Context, scheduledSession domain.ScheduledSession,
) error {
	if err := r.store.Upsert(scheduledSessionKey, &scheduledSession); err != nil {
		if errors.Is(err, badger.ErrConflict) {
			attempts := 1
			for errors.Is(err, badger.ErrConflict) && attempts <= maxRetries {
				time.Sleep(100 * time.Millisecond)
				err = r.store.Upsert(scheduledSessionKey, &scheduledSession)
				attempts++
			}
		}
		return err
	}
	return nil
}

func (r *scheduledSessionRepository) Close() {
	// nolint:all
	r.store.Close()
}
