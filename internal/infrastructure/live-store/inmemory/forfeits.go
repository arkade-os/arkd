package inmemorylivestore

import (
	"context"
	"fmt"
	"sync"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
)

type forfeitTxsStore struct {
	lock            sync.RWMutex
	builder         ports.TxBuilder
	forfeitTxs      map[domain.Outpoint]ports.ValidForfeitTx
	connectors      tree.FlatTxTree
	connectorsIndex map[string]domain.Outpoint
	vtxos           []domain.Vtxo
}

func NewForfeitTxsStore(txBuilder ports.TxBuilder) ports.ForfeitTxsStore {
	return &forfeitTxsStore{
		builder:    txBuilder,
		forfeitTxs: make(map[domain.Outpoint]ports.ValidForfeitTx),
	}
}

func (m *forfeitTxsStore) Init(
	_ context.Context, connectors tree.FlatTxTree, intents []domain.Intent,
) error {
	vtxosToSign := make([]domain.Vtxo, 0)
	for _, intent := range intents {
		for _, vtxo := range intent.Inputs {
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

		leaves := tree.FlatTxTree(connectors).Leaves()
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
			return fmt.Errorf(
				"more vtxos to sign than outpoints, %d > %d",
				len(vtxosToSign), len(connectorsOutpoints),
			)
		}

		for i, connectorOutpoint := range connectorsOutpoints {
			connectorsIndex[connectorOutpoint.String()] = vtxosToSign[i].Outpoint
		}
	}

	m.connectorsIndex = connectorsIndex

	return nil
}

func (m *forfeitTxsStore) Sign(_ context.Context, txs []string) error {
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
func (m *forfeitTxsStore) Reset(_ context.Context) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.forfeitTxs = make(map[domain.Outpoint]ports.ValidForfeitTx)
	m.connectors = nil
	m.connectorsIndex = nil
	m.vtxos = nil
	return nil
}
func (m *forfeitTxsStore) Pop(ctx context.Context) ([]string, error) {
	m.lock.Lock()
	defer func() {
		m.lock.Unlock()
		// nolint
		m.Reset(ctx)
	}()

	txs := make([]string, 0)
	usedConnectors := make(map[domain.Outpoint]struct{})

	for vtxo, forfeit := range m.forfeitTxs {
		if len(forfeit.Tx) == 0 {
			return nil, fmt.Errorf("missing forfeit tx for vtxo %s", vtxo)
		}
		if _, used := usedConnectors[forfeit.Connector]; used {
			return nil, fmt.Errorf(
				"connector %s for vtxo %s is used more than once", forfeit.Connector, vtxo,
			)
		}
		usedConnectors[forfeit.Connector] = struct{}{}
		txs = append(txs, forfeit.Tx)
	}

	return txs, nil
}
func (m *forfeitTxsStore) AllSigned(_ context.Context) (bool, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	if len(m.forfeitTxs) == 0 {
		return false, nil
	}

	for _, forfeit := range m.forfeitTxs {
		if len(forfeit.Tx) == 0 {
			return false, nil
		}
	}

	return true, nil
}

func (m *forfeitTxsStore) GetUnsignedInputs(_ context.Context) ([]domain.Outpoint, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	vtxoKeys := make([]domain.Outpoint, 0)
	for vtxo, forfeit := range m.forfeitTxs {
		if len(forfeit.Tx) == 0 {
			vtxoKeys = append(vtxoKeys, vtxo)
		}
	}
	return vtxoKeys, nil
}
func (m *forfeitTxsStore) Len(_ context.Context) (int, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return len(m.forfeitTxs), nil
}

func (m *forfeitTxsStore) GetConnectorsIndexes(
	_ context.Context) (map[string]domain.Outpoint, error,
) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	return m.connectorsIndex, nil
}
