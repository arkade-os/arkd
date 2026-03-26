package inmemorystore

import (
	"sync"

	walletstore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store"
)

type inmemoryStore struct {
	data                *walletstore.WalletData
	boardingDescriptors []walletstore.BoardingDescriptor
	lock                *sync.RWMutex
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

func (s *inmemoryStore) AddBoardingDescriptor(descriptor walletstore.BoardingDescriptor) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, d := range s.boardingDescriptors {
		if d.Address == descriptor.Address {
			return nil
		}
	}

	s.boardingDescriptors = append(s.boardingDescriptors, cloneDescriptor(descriptor))
	return nil
}

func (s *inmemoryStore) GetBoardingDescriptors() ([]walletstore.BoardingDescriptor, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	result := make([]walletstore.BoardingDescriptor, 0, len(s.boardingDescriptors))
	for _, d := range s.boardingDescriptors {
		result = append(result, cloneDescriptor(d))
	}
	return result, nil
}

func cloneDescriptor(d walletstore.BoardingDescriptor) walletstore.BoardingDescriptor {
	ts := make([]string, len(d.Tapscripts))
	copy(ts, d.Tapscripts)
	return walletstore.BoardingDescriptor{
		Address:    d.Address,
		Tapscripts: ts,
	}
}
