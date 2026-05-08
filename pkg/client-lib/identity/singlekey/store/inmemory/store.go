package identityInmemoryStore

import (
	"sync"

	identityStore "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey/store"
)

type inmemoryStore struct {
	data *identityStore.IdentityData
	lock *sync.RWMutex
}

func NewStore() (identityStore.IdentityStore, error) {
	lock := &sync.RWMutex{}
	return &inmemoryStore{lock: lock}, nil
}

func (s *inmemoryStore) Add(data identityStore.IdentityData) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data = &data
	return nil
}

func (s *inmemoryStore) Get() (*identityStore.IdentityData, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.data, nil
}
