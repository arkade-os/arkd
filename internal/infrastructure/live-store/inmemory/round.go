package inmemorylivestore

import (
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

func (s *currentRoundStore) Upsert(fn func(m *domain.Round) *domain.Round) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.round = fn(s.round)
	return nil
}
func (s *currentRoundStore) Get() *domain.Round {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.round
}
func (s *currentRoundStore) Fail(err error) []domain.Event {
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
