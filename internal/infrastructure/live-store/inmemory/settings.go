package inmemorylivestore

import (
	"context"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/ports"
)

type settingsStore struct {
	lock     *sync.RWMutex
	settings *ports.Settings
}

func NewSettingsStore() ports.SettingsStore {
	return &settingsStore{
		lock: &sync.RWMutex{},
	}
}

func (s *settingsStore) Get(ctx context.Context) (*ports.Settings, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if s.settings == nil {
		return nil, nil
	}
	settings := *s.settings
	return &settings, nil
}

func (s *settingsStore) Upsert(ctx context.Context, settings ports.Settings) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.settings = &settings
	return nil
}

func (s *settingsStore) UpdateLastBatch(ctx context.Context, at time.Time, id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.settings == nil {
		s.settings = &ports.Settings{
			LastBatchAt: at,
			LastBatchId: id,
		}
		return nil
	}
	s.settings.LastBatchAt = at
	s.settings.LastBatchId = id
	return nil
}
