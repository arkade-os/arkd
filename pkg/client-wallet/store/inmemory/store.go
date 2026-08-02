package inmemorystore

import (
	"context"
	"sync"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-wallet/types"
)

type service struct {
	data *clientlib.ServerParams
	lock *sync.RWMutex
}

func NewStore() (types.Store, error) {
	lock := &sync.RWMutex{}
	return &service{lock: lock}, nil
}

func (s *service) Close() {}

func (s *service) GetType() string {
	return "inmemory"
}

func (s *service) GetDatadir() string {
	return ""
}

func (s *service) AddData(
	_ context.Context, data clientlib.ServerParams,
) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	dataCopy := data
	s.data = &dataCopy
	return nil
}

func (s *service) GetData(_ context.Context) (*clientlib.ServerParams, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.data == nil {
		return nil, nil
	}

	data := *s.data
	return &data, nil
}

func (s *service) Clean(_ context.Context) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data = nil
	return nil
}
