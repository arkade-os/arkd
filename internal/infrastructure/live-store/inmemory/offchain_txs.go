package inmemorylivestore

import (
	"context"
	"strings"
	"sync"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
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

func (m *offChainTxStore) Add(_ context.Context, offchainTx domain.OffchainTx) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.offchainTxs[offchainTx.ArkTxid] = offchainTx
	for _, tx := range offchainTx.CheckpointTxs {
		ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		for _, in := range ptx.UnsignedTx.TxIn {
			m.inputs[in.PreviousOutPoint.String()] = struct{}{}
		}
	}
	return nil
}

func (m *offChainTxStore) Remove(_ context.Context, arkTxid string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	offchainTx, ok := m.offchainTxs[arkTxid]
	if !ok {
		return nil
	}

	for _, tx := range offchainTx.CheckpointTxs {
		ptx, _ := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		for _, in := range ptx.UnsignedTx.TxIn {
			delete(m.inputs, in.PreviousOutPoint.String())
		}
	}
	delete(m.offchainTxs, arkTxid)
	return nil
}

func (m *offChainTxStore) Get(_ context.Context, arkTxid string) (*domain.OffchainTx, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	offchainTx, ok := m.offchainTxs[arkTxid]
	if !ok {
		return nil, nil
	}
	return &offchainTx, nil
}

func (m *offChainTxStore) Includes(_ context.Context, outpoint domain.Outpoint) (bool, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	_, exists := m.inputs[outpoint.String()]
	return exists, nil
}

func (m *offChainTxStore) GetTxidByOutpoint(
	_ context.Context,
	outpoint domain.Outpoint,
) (string, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	outpointStr := outpoint.String()
	for txid, offchainTx := range m.offchainTxs {
		for _, tx := range offchainTx.CheckpointTxs {
			ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
			if err != nil {
				continue
			}
			for _, in := range ptx.UnsignedTx.TxIn {
				if in.PreviousOutPoint.String() == outpointStr {
					return txid, nil
				}
			}
		}
	}
	return "", nil
}
