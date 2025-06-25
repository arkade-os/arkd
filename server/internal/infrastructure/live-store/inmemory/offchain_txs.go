package inmemorylivestore

import (
	"strings"
	"sync"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

type offChainTxStore struct {
	lock        sync.RWMutex
	offchainTxs map[string]domain.OffchainTx
	inputs      map[string]struct{}
}

func NewOffChainTxStore() ports.OffChainTxStore {
	return &offChainTxStore{
		offchainTxs: make(map[string]domain.OffchainTx),
		inputs:      make(map[string]struct{}),
	}
}

func (m *offChainTxStore) Add(offchainTx domain.OffchainTx) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.offchainTxs[offchainTx.VirtualTxid] = offchainTx
	for _, tx := range offchainTx.CheckpointTxs {
		ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		for _, in := range ptx.UnsignedTx.TxIn {
			m.inputs[in.PreviousOutPoint.String()] = struct{}{}
		}
	}
}

func (m *offChainTxStore) Remove(virtualTxid string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	offchainTx, ok := m.offchainTxs[virtualTxid]
	if !ok {
		return
	}

	for _, tx := range offchainTx.CheckpointTxs {
		ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		for _, in := range ptx.UnsignedTx.TxIn {
			delete(m.inputs, in.PreviousOutPoint.String())
		}
	}
	delete(m.offchainTxs, virtualTxid)
}

func (m *offChainTxStore) Get(virtualTxid string) (domain.OffchainTx, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	offchainTx, ok := m.offchainTxs[virtualTxid]
	return offchainTx, ok
}

func (m *offChainTxStore) Includes(outpoint domain.Outpoint) bool {
	m.lock.RLock()
	defer m.lock.RUnlock()
	_, exists := m.inputs[outpoint.String()]
	return exists
}
