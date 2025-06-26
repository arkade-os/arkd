package inmemorylivestore

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
)

type txRequestStore struct {
	lock          sync.RWMutex
	requests      map[string]*ports.TimedTxRequest
	vtxos         map[string]struct{}
	vtxosToRemove []string
}

func NewTxRequestsStore() ports.TxRequestsStore {
	requestsById := make(map[string]*ports.TimedTxRequest)
	vtxos := make(map[string]struct{})
	vtxosToRemove := make([]string, 0)
	return &txRequestStore{
		requests:      requestsById,
		vtxos:         vtxos,
		vtxosToRemove: vtxosToRemove,
	}
}

func (m *txRequestStore) Len() int64 {
	m.lock.RLock()
	defer m.lock.RUnlock()

	count := int64(0)
	for _, p := range m.requests {
		if len(p.Receivers) > 0 {
			count++
		}
	}
	return count
}

func (m *txRequestStore) Push(request domain.TxRequest, boardingInputs []ports.BoardingInput, cosignersPubkeys []string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.requests[request.Id]; ok {
		return fmt.Errorf("duplicated tx request %s", request.Id)
	}

	for _, input := range request.Inputs {
		for _, pay := range m.requests {
			for _, pInput := range pay.Inputs {
				if input.Txid == pInput.Txid && input.VOut == pInput.VOut {
					return fmt.Errorf("duplicated input, %s already registered by another request", input.String())
				}
			}
		}
	}

	for _, input := range boardingInputs {
		for _, request := range m.requests {
			for _, pBoardingInput := range request.BoardingInputs {
				if input.Txid == pBoardingInput.Txid && input.VOut == pBoardingInput.VOut {
					return fmt.Errorf("duplicated input, %s already registered by another request", input.String())
				}
			}
		}
	}

	now := time.Now()
	m.requests[request.Id] = &ports.TimedTxRequest{
		TxRequest:           request,
		BoardingInputs:      boardingInputs,
		Timestamp:           now,
		CosignersPublicKeys: cosignersPubkeys,
	}
	for _, vtxo := range request.Inputs {
		if vtxo.IsNote() {
			continue
		}
		m.vtxos[vtxo.String()] = struct{}{}
	}
	return nil
}

func (m *txRequestStore) Pop(num int64) []ports.TimedTxRequest {
	m.lock.Lock()
	defer m.lock.Unlock()

	requestsByTime := make([]ports.TimedTxRequest, 0, len(m.requests))
	for _, p := range m.requests {
		// Skip tx requests without registered receivers.
		if len(p.Receivers) <= 0 {
			continue
		}

		requestsByTime = append(requestsByTime, *p)
	}
	sort.SliceStable(requestsByTime, func(i, j int) bool {
		return requestsByTime[i].Timestamp.Before(requestsByTime[j].Timestamp)
	})

	if num < 0 || num > int64(len(requestsByTime)) {
		num = int64(len(requestsByTime))
	}

	result := make([]ports.TimedTxRequest, 0, num)

	for _, p := range requestsByTime[:num] {
		result = append(result, p)
		for _, vtxo := range m.requests[p.Id].Inputs {
			m.vtxosToRemove = append(m.vtxosToRemove, vtxo.String())
		}
		delete(m.requests, p.Id)
	}

	return result
}

func (m *txRequestStore) Update(request domain.TxRequest, cosignersPubkeys []string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	r, ok := m.requests[request.Id]
	if !ok {
		return fmt.Errorf("tx request %s not found", request.Id)
	}

	// sum inputs = vtxos + boarding utxos + notes + recovered vtxos
	sumOfInputs := uint64(0)
	for _, input := range request.Inputs {
		sumOfInputs += input.Amount
	}

	for _, boardingInput := range r.BoardingInputs {
		sumOfInputs += boardingInput.Amount
	}

	// sum outputs = receivers VTXOs
	sumOfOutputs := uint64(0)
	for _, receiver := range request.Receivers {
		sumOfOutputs += receiver.Amount
	}

	if sumOfInputs != sumOfOutputs {
		return fmt.Errorf("sum of inputs %d does not match sum of outputs %d", sumOfInputs, sumOfOutputs)
	}

	r.TxRequest = request

	if len(cosignersPubkeys) > 0 {
		r.CosignersPublicKeys = cosignersPubkeys
	}
	return nil
}

func (m *txRequestStore) Delete(ids []string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for _, id := range ids {
		req, ok := m.requests[id]
		if !ok {
			continue
		}
		for _, vtxo := range req.Inputs {
			delete(m.vtxos, vtxo.String())
		}
		delete(m.requests, id)
	}
	return nil
}

func (m *txRequestStore) DeleteAll() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.requests = make(map[string]*ports.TimedTxRequest)
	m.vtxos = make(map[string]struct{})
	return nil
}

func (m *txRequestStore) DeleteVtxos() {
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, vtxo := range m.vtxosToRemove {
		delete(m.vtxos, vtxo)
	}
	m.vtxosToRemove = make([]string, 0)
}

func (m *txRequestStore) ViewAll(ids []string) ([]ports.TimedTxRequest, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	requests := make([]ports.TimedTxRequest, 0, len(m.requests))
	for _, request := range m.requests {
		if len(ids) > 0 {
			for _, id := range ids {
				if request.Id == id {
					requests = append(requests, *request)
					break
				}
			}
			continue
		}
		requests = append(requests, *request)
	}
	return requests, nil
}

func (m *txRequestStore) View(id string) (*domain.TxRequest, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	request, ok := m.requests[id]
	if !ok {
		return nil, false
	}

	return &domain.TxRequest{
		Id:        request.Id,
		Inputs:    request.Inputs,
		Receivers: request.Receivers,
	}, true
}

func (m *txRequestStore) IncludesAny(outpoints []domain.Outpoint) (bool, string) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	for _, out := range outpoints {
		if _, exists := m.vtxos[out.String()]; exists {
			return true, out.String()
		}
	}

	return false, ""
}
