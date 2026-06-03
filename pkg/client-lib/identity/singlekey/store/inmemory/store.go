package identityinmemorystore

import (
	"sync"

	identitystore "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey/store"
)

type inmemoryStore struct {
	data *identitystore.IdentityData
	lock *sync.RWMutex
}

func NewStore() (identitystore.IdentityStore, error) {
	lock := &sync.RWMutex{}
	return &inmemoryStore{lock: lock}, nil
}

func (s *inmemoryStore) Add(data identitystore.IdentityData) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data = &data
	return nil
}

func (s *inmemoryStore) Get() (*identitystore.IdentityData, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.data, nil
}
