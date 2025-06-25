package inmemorylivestore

import (
	"fmt"
	"sync"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/core/ports"
)

type forfeitTxsStore struct {
	lock            sync.RWMutex
	builder         ports.TxBuilder
	forfeitTxs      map[domain.Outpoint]ports.ValidForfeitTx
	connectors      []tree.TxGraphChunk
	connectorsIndex map[string]domain.Outpoint
	vtxos           []domain.Vtxo
}

func NewForfeitTxsStore(txBuilder ports.TxBuilder) ports.ForfeitTxsStore {
	return &forfeitTxsStore{
		builder:    txBuilder,
		forfeitTxs: make(map[domain.Outpoint]ports.ValidForfeitTx),
	}
}

func (m *forfeitTxsStore) Init(connectors []tree.TxGraphChunk, requests []domain.TxRequest) error {
	vtxosToSign := make([]domain.Vtxo, 0)
	for _, request := range requests {
		for _, vtxo := range request.Inputs {
			// If the vtxo is swept or is a note, it doens't require to be forfeited so we skip it
			if !vtxo.RequiresForfeit() {
				continue
			}
			vtxosToSign = append(vtxosToSign, vtxo)
		}
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	m.vtxos = vtxosToSign
	m.connectors = connectors

	// init the forfeit txs map
	for _, vtxo := range vtxosToSign {
		m.forfeitTxs[vtxo.Outpoint] = ports.ValidForfeitTx{}
	}

	// create the connectors index
	connectorsIndex := make(map[string]domain.Outpoint)

	if len(vtxosToSign) > 0 {
		connectorsOutpoints := make([]domain.Outpoint, 0)

		leaves := tree.TxGraphChunkList(connectors).Leaves()
		if len(leaves) == 0 {
			return fmt.Errorf("no connectors found")
		}

		for _, leaf := range leaves {
			connectorsOutpoints = append(connectorsOutpoints, domain.Outpoint{
				Txid: leaf.Txid,
				VOut: 0,
			})
		}

		if len(vtxosToSign) > len(connectorsOutpoints) {
			return fmt.Errorf("more vtxos to sign than outpoints, %d > %d", len(vtxosToSign), len(connectorsOutpoints))
		}

		for i, connectorOutpoint := range connectorsOutpoints {
			connectorsIndex[connectorOutpoint.String()] = vtxosToSign[i].Outpoint
		}
	}

	m.connectorsIndex = connectorsIndex

	return nil
}

func (m *forfeitTxsStore) Sign(txs []string) error {
	if len(txs) == 0 {
		return nil
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	if len(m.vtxos) == 0 || len(m.connectors) == 0 {
		return fmt.Errorf("forfeit txs map not initialized")
	}

	// verify the txs are valid
	validTxs, err := m.builder.VerifyForfeitTxs(m.vtxos, m.connectors, txs)
	if err != nil {
		return err
	}

	for vtxoKey, txs := range validTxs {
		if _, ok := m.forfeitTxs[vtxoKey]; !ok {
			return fmt.Errorf("unexpected forfeit tx, vtxo %s is not in the batch", vtxoKey)
		}
		m.forfeitTxs[vtxoKey] = txs
	}

	return nil
}
func (m *forfeitTxsStore) Reset() {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.forfeitTxs = make(map[domain.Outpoint]ports.ValidForfeitTx)
	m.connectors = nil
	m.connectorsIndex = nil
	m.vtxos = nil
}
func (m *forfeitTxsStore) Pop() ([]string, error) {
	m.lock.Lock()
	defer func() {
		m.lock.Unlock()
		m.Reset()
	}()

	txs := make([]string, 0)
	usedConnectors := make(map[domain.Outpoint]struct{})

	for vtxo, forfeit := range m.forfeitTxs {
		if len(forfeit.Tx) == 0 {
			return nil, fmt.Errorf("missing forfeit tx for vtxo %s", vtxo)
		}
		if _, used := usedConnectors[forfeit.Connector]; used {
			return nil, fmt.Errorf("connector %s for vtxo %s is used more than once", forfeit.Connector, vtxo)
		}
		usedConnectors[forfeit.Connector] = struct{}{}
		txs = append(txs, forfeit.Tx)
	}

	return txs, nil
}
func (m *forfeitTxsStore) AllSigned() bool {
	for _, forfeit := range m.forfeitTxs {
		if len(forfeit.Tx) == 0 {
			return false
		}
	}

	return true
}

func (m *forfeitTxsStore) Len() int {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return len(m.forfeitTxs)
}

func (m *forfeitTxsStore) GetConnectorsIndexes() map[string]domain.Outpoint {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return m.connectorsIndex
}
