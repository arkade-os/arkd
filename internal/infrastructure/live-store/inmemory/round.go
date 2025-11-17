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
	_ context.Context,
	fn func(m *domain.Round) *domain.Round,
) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.round = fn(s.round)
	return nil
}
func (s *currentRoundStore) Get(_ context.Context) *domain.Round {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.round
}
func (s *currentRoundStore) Fail(_ context.Context, err error) []domain.Event {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.round.Fail(err)
}

type boardingInputsStore struct {
	lock        sync.RWMutex
	numOfInputs int
}

func NewBoardingInputsStore() ports.BoardingInputsStore {
	return &boardingInputsStore{}
}

func (b *boardingInputsStore) Set(numOfInputs int) {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.numOfInputs = numOfInputs
}

func (b *boardingInputsStore) Get() int {
	b.lock.RLock()
	defer b.lock.RUnlock()
	return b.numOfInputs
}
