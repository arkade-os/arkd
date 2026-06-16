package inmemorylivestore

import (
	"context"
	"sync"

	"github.com/arkade-os/arkd/internal/core/ports"
)

type settingsStore struct {
	lock     *sync.RWMutex
	settings ports.Settings
}

func NewSettingsStore() ports.SettingsStore {
	return &settingsStore{
		lock: &sync.RWMutex{},
	}
}

func (s *settingsStore) Get(ctx context.Context) (*ports.Settings, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	settings := s.settings
	return &settings, nil
}

func (s *settingsStore) Upsert(ctx context.Context, settings ports.Settings) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.settings = settings
	return nil
}
