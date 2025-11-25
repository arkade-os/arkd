package inmemorylivestore

import (
	"context"
	"sync"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
)

type currentRoundStore struct {
	lock  sync.RWMutex
	round *domain.Round
}

func NewCurrentRoundStore() ports.CurrentRoundStore {
	return &currentRoundStore{}
}

func (s *currentRoundStore) Upsert(
	_ context.Context, fn func(m *domain.Round) *domain.Round,
) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.round = fn(s.round)
	return nil
}
func (s *currentRoundStore) Get(_ context.Context) (*domain.Round, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.round, nil
}
