package inmemorylivestore

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
)

type intentStore struct {
	lock            sync.RWMutex
	intents         map[string]*ports.TimedIntent
	vtxos           map[string]struct{}
	vtxosToRemove   []string
	selectedIntents []ports.TimedIntent
}

func NewIntentStore() ports.IntentStore {
	intentsById := make(map[string]*ports.TimedIntent)
	vtxos := make(map[string]struct{})
	vtxosToRemove := make([]string, 0)
	selectedIntents := make([]ports.TimedIntent, 0)
	return &intentStore{
		intents:         intentsById,
		vtxos:           vtxos,
		vtxosToRemove:   vtxosToRemove,
		selectedIntents: selectedIntents,
	}
}

func (m *intentStore) Len(_ context.Context) (int64, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	count := int64(0)
	for _, p := range m.intents {
		if len(p.Receivers) > 0 {
			count++
		}
	}
	return count, nil
}

func (m *intentStore) Push(
	_ context.Context, intent domain.Intent,
	boardingInputs []ports.BoardingInput, cosignersPubkeys []string,
) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.intents[intent.Id]; ok {
		return fmt.Errorf("duplicated intent %s", intent.Id)
	}

	for _, input := range intent.Inputs {
		for _, pay := range m.intents {
			for _, pInput := range pay.Inputs {
				if input.Txid == pInput.Txid && input.VOut == pInput.VOut {
					return fmt.Errorf(
						"duplicated input, %s already registered by another intent",
						input.Outpoint.String(),
					)
				}
			}
		}
	}

	for _, input := range boardingInputs {
		for _, intent := range m.intents {
			for _, pBoardingInput := range intent.BoardingInputs {
				if input.Txid == pBoardingInput.Txid && input.VOut == pBoardingInput.VOut {
					return fmt.Errorf(
						"duplicated input, %s already registered by another intent",
						input.String(),
					)
				}
			}
		}
	}

	now := time.Now()
	m.intents[intent.Id] = &ports.TimedIntent{
		Intent:              intent,
		BoardingInputs:      boardingInputs,
		Timestamp:           now,
		CosignersPublicKeys: cosignersPubkeys,
	}
	for _, vtxo := range intent.Inputs {
		if vtxo.IsNote() {
			continue
		}
		m.vtxos[vtxo.Outpoint.String()] = struct{}{}
	}
	return nil
}

func (m *intentStore) Pop(_ context.Context, num int64) ([]ports.TimedIntent, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.selectedIntents = make([]ports.TimedIntent, 0)

	intentsByTime := make([]ports.TimedIntent, 0, len(m.intents))
	for _, p := range m.intents {
		// Skip intents without registered receivers.
		if len(p.Receivers) <= 0 {
			continue
		}

		intentsByTime = append(intentsByTime, *p)
	}
	sort.SliceStable(intentsByTime, func(i, j int) bool {
		return intentsByTime[i].Timestamp.Before(intentsByTime[j].Timestamp)
	})

	if num < 0 || num > int64(len(intentsByTime)) {
		num = int64(len(intentsByTime))
	}

	result := make([]ports.TimedIntent, 0, num)

	for _, p := range intentsByTime[:num] {
		result = append(result, p)
		for _, vtxo := range m.intents[p.Id].Inputs {
			m.vtxosToRemove = append(m.vtxosToRemove, vtxo.Outpoint.String())
		}
		delete(m.intents, p.Id)
	}

	m.selectedIntents = result
	return result, nil
}

func (m *intentStore) GetSelectedIntents(_ context.Context) ([]ports.TimedIntent, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return m.selectedIntents, nil
}

func (m *intentStore) Update(
	_ context.Context, intent domain.Intent, cosignersPubkeys []string,
) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	r, ok := m.intents[intent.Id]
	if !ok {
		return fmt.Errorf("intent %s not found", intent.Id)
	}

	// sum inputs = vtxos + boarding utxos + notes + recovered vtxos
	sumOfInputs := uint64(0)
	for _, input := range intent.Inputs {
		sumOfInputs += input.Amount
	}

	for _, boardingInput := range r.BoardingInputs {
		sumOfInputs += boardingInput.Amount
	}

	// sum outputs = receivers VTXOs
	sumOfOutputs := uint64(0)
	for _, receiver := range intent.Receivers {
		sumOfOutputs += receiver.Amount
	}

	if sumOfInputs != sumOfOutputs {
		return fmt.Errorf(
			"sum of inputs %d does not match sum of outputs %d", sumOfInputs, sumOfOutputs,
		)
	}

	r.Intent = intent

	if len(cosignersPubkeys) > 0 {
		r.CosignersPublicKeys = cosignersPubkeys
	}
	return nil
}

func (m *intentStore) Delete(_ context.Context, ids []string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, id := range ids {
		intent, ok := m.intents[id]
		if !ok {
			continue
		}
		for _, vtxo := range intent.Inputs {
			delete(m.vtxos, vtxo.Outpoint.String())
		}
		delete(m.intents, id)
	}
	return nil
}

func (m *intentStore) DeleteAll(_ context.Context) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.intents = make(map[string]*ports.TimedIntent)
	m.vtxos = make(map[string]struct{})
	m.selectedIntents = make([]ports.TimedIntent, 0)
	return nil
}

func (m *intentStore) DeleteVtxos(_ context.Context) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, vtxo := range m.vtxosToRemove {
		delete(m.vtxos, vtxo)
	}
	m.vtxosToRemove = make([]string, 0)
	return nil
}

func (m *intentStore) ViewAll(_ context.Context, ids []string) ([]ports.TimedIntent, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	intents := make([]ports.TimedIntent, 0, len(m.intents))
	for _, intent := range m.intents {
		if len(ids) > 0 {
			for _, id := range ids {
				if intent.Id == id {
					intents = append(intents, *intent)
					break
				}
			}
			continue
		}
		intents = append(intents, *intent)
	}
	return intents, nil
}

func (m *intentStore) IncludesAny(_ context.Context, outpoints []domain.Outpoint) (bool, string) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	for _, out := range outpoints {
		if _, exists := m.vtxos[out.String()]; exists {
			return true, out.String()
		}
	}

	return false, ""
}
