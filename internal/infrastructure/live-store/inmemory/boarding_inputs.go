package inmemorylivestore

import (
	"context"
	"fmt"
	"sync"

	"github.com/arkade-os/arkd/internal/core/ports"
)

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

func (b *boardingInputsStore) Set(_ context.Context, numOfInputs int) error {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.numOfInputs = numOfInputs
	return nil
}

func (b *boardingInputsStore) Get(_ context.Context) (int, error) {
	b.lock.RLock()
	defer b.lock.RUnlock()
	return b.numOfInputs, nil
}

func (b *boardingInputsStore) AddSignatures(
	_ context.Context, _ string, inputSigs map[uint32]ports.SignedBoardingInput,
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
	_ context.Context, _ string,
) (map[uint32]ports.SignedBoardingInput, error) {
	b.lock.RLock()
	defer b.lock.RUnlock()
	return b.sigs, nil
}

func (b *boardingInputsStore) DeleteSignatures(_ context.Context, _ string) error {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.sigs = make(map[uint32]ports.SignedBoardingInput)
	return nil
}
