package inmemorylivestore

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/psbt/v2"
)

type offChainTxStore struct {
	lock        sync.RWMutex
	offchainTxs map[string]domain.OffchainTx
	// inputs maps a registered spent-input outpoint to the arkTxid that owns it
	// (the owner tag). Shared by the off-chain and on-chain single-spend guards.
	inputs map[string]string
}

func NewOffChainTxStore() ports.OffChainTxStore {
	return &offChainTxStore{
		offchainTxs: make(map[string]domain.OffchainTx),
		inputs:      make(map[string]string),
	}
}

func (m *offChainTxStore) Add(
	_ context.Context, offchainTx domain.OffchainTx,
) (ports.ClaimStatus, *domain.Outpoint, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	inputs, err := checkpointInputs(offchainTx)
	if err != nil {
		return ports.ClaimFresh, nil, fmt.Errorf(
			"malformed checkpoint tx in offchain tx %s: %v", offchainTx.ArkTxid, err,
		)
	}
	status, conflict := m.claimLocked(offchainTx.ArkTxid, inputs)
	if status == ports.ClaimConflict {
		return status, conflict, nil
	}
	m.offchainTxs[offchainTx.ArkTxid] = offchainTx
	return status, nil, nil
}

func (m *offChainTxStore) Remove(_ context.Context, arkTxid string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	offchainTx, ok := m.offchainTxs[arkTxid]
	if !ok {
		return nil
	}
	inputs, err := checkpointInputs(offchainTx)
	if err != nil {
		return fmt.Errorf("malformed checkpoint tx in stored offchain tx %s: %v", arkTxid, err)
	}
	for _, o := range inputs {
		if owner, ok := m.inputs[o.String()]; ok && owner == arkTxid {
			delete(m.inputs, o.String())
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

func (m *offChainTxStore) ClaimOutpoints(
	_ context.Context, owner string, outpoints []domain.Outpoint,
) (ports.ClaimStatus, *domain.Outpoint, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	status, conflict := m.claimLocked(owner, outpoints)
	return status, conflict, nil
}

func (m *offChainTxStore) ReleaseOutpoints(
	_ context.Context, owner string, outpoints []domain.Outpoint,
) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	for i := range outpoints {
		key := outpoints[i].String()
		if cur, ok := m.inputs[key]; ok && cur == owner {
			delete(m.inputs, key)
		}
	}
	return nil
}

func (m *offChainTxStore) Includes(_ context.Context, outpoint domain.Outpoint) (bool, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	_, exists := m.inputs[outpoint.String()]
	return exists, nil
}

// claimLocked performs the owner-tagged claim and must be called under the
// write lock. It rejects the whole batch if any outpoint is held by a different
// owner (ClaimConflict + that outpoint, registering nothing), reports
// ClaimAlreadyOwned when the owner already held all of them (registering
// nothing), and otherwise registers every outpoint to the owner (ClaimFresh).
func (m *offChainTxStore) claimLocked(
	owner string, outpoints []domain.Outpoint,
) (ports.ClaimStatus, *domain.Outpoint) {
	for i := range outpoints {
		if cur, ok := m.inputs[outpoints[i].String()]; ok && cur != owner {
			return ports.ClaimConflict, &outpoints[i]
		}
	}
	// After the conflict pass every present outpoint is owned by owner, so a
	// still-new one can only be absent.
	anyNew := false
	for i := range outpoints {
		if _, ok := m.inputs[outpoints[i].String()]; !ok {
			anyNew = true
			break
		}
	}
	if !anyNew {
		return ports.ClaimAlreadyOwned, nil
	}
	for i := range outpoints {
		m.inputs[outpoints[i].String()] = owner
	}
	return ports.ClaimFresh, nil
}

// checkpointInputs returns every spent-input outpoint of every checkpoint tx of
// the offchain tx, matching what the conflict domain registers. It is all or
// nothing: a checkpoint tx that fails to parse fails the call, so no caller ever
// registers or releases a subset of a tx's inputs.
func checkpointInputs(offchainTx domain.OffchainTx) ([]domain.Outpoint, error) {
	out := make([]domain.Outpoint, 0)
	for _, tx := range offchainTx.CheckpointTxs {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
		if err != nil {
			return nil, err
		}
		for _, in := range ptx.UnsignedTx.TxIn {
			out = append(out, domain.Outpoint{
				Txid: in.PreviousOutPoint.Hash.String(),
				VOut: in.PreviousOutPoint.Index,
			})
		}
	}
	return out, nil
}
