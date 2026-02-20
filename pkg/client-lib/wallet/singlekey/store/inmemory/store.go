package inmemorystore

import (
	"sync"

	walletstore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store"
)

type inmemoryStore struct {
	data *walletstore.WalletData
	lock *sync.RWMutex
}

func NewWalletStore() (walletstore.WalletStore, error) {
	lock := &sync.RWMutex{}
	return &inmemoryStore{lock: lock}, nil
}

func (s *inmemoryStore) AddWallet(data walletstore.WalletData) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data = &data
	return nil
}

func (s *inmemoryStore) GetWallet() (*walletstore.WalletData, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.data, nil
}
