package inmemorylivestore

import (
	"context"
	"sync"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
)

type utxoStore struct {
	lock      sync.RWMutex
	outpoints map[domain.Outpoint]struct{}
}

func NewUtxoStore() ports.CosignedUtxosStore {
	return &utxoStore{
		outpoints: make(map[domain.Outpoint]struct{}),
	}
}

// AddUtxos reserves the outpoints as a whole: if any of them is already reserved none is
// added and ports.ErrUtxosAlreadyExist is returned.
func (m *utxoStore) AddUtxos(_ context.Context, outpoints []domain.Outpoint) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, outpoint := range outpoints {
		if _, ok := m.outpoints[outpoint]; ok {
			return ports.ErrUtxosAlreadyExist
		}
	}
	for _, outpoint := range outpoints {
		m.outpoints[outpoint] = struct{}{}
	}
	return nil
}

func (m *utxoStore) RemoveUtxos(_ context.Context, outpoints []domain.Outpoint) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, outpoint := range outpoints {
		delete(m.outpoints, outpoint)
	}
	return nil
}

func (m *utxoStore) IncludesAny(
	_ context.Context, outpoints []domain.Outpoint,
) ([]domain.Outpoint, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	var included []domain.Outpoint
	for _, outpoint := range outpoints {
		if _, ok := m.outpoints[outpoint]; ok {
			included = append(included, outpoint)
		}
	}
	return included, nil
}
