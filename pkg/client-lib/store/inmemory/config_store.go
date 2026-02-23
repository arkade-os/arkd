package inmemorystore

import (
	"context"
	"sync"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

type store struct {
	data *types.Config
	lock *sync.RWMutex
}

func NewConfigStore() (types.ConfigStore, error) {
	lock := &sync.RWMutex{}
	return &store{lock: lock}, nil
}

func (s *store) Close() {}

func (s *store) GetType() string {
	return "inmemory"
}

func (s *store) GetDatadir() string {
	return ""
}

func (s *store) AddData(
	_ context.Context, data types.Config,
) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data = &data
	return nil
}

func (s *store) GetData(_ context.Context) (*types.Config, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.data == nil {
		return nil, nil
	}

	return s.data, nil
}

func (s *store) CleanData(_ context.Context) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data = nil
	return nil
}
