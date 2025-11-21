package inmemorylivestore

import (
	"context"
	"fmt"
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
	lock        *sync.RWMutex
	numOfInputs int
	sigs        map[uint32]ports.SignedBoardingInput
}

func NewBoardingInputsStore() ports.BoardingInputsStore {
	return &boardingInputsStore{
		lock: &sync.RWMutex{},
		sigs: make(map[uint32]ports.SignedBoardingInput),
	}
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

func (b *boardingInputsStore) AddSignatures(
	ctx context.Context, _ string, inputSigs map[uint32]ports.SignedBoardingInput,
) error {
	if len(inputSigs) <= 0 {
		return fmt.Errorf("missing boarding input signature")
	}

	b.lock.Lock()
	defer b.lock.Unlock()
	for inIndex, sigs := range inputSigs {
		if _, ok := b.sigs[inIndex]; ok {
			continue
		}
		b.sigs[inIndex] = sigs
	}
	return nil
}

func (b *boardingInputsStore) GetSignatures(
	ctx context.Context, _ string,
) (map[uint32]ports.SignedBoardingInput, error) {
	b.lock.RLock()
	defer b.lock.RUnlock()
	return b.sigs, nil
}

func (b *boardingInputsStore) DeleteSignatures(ctx context.Context, _ string) error {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.sigs = make(map[uint32]ports.SignedBoardingInput)
	return nil
}
