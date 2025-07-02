package kvstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/dgraph-io/badger/v4"
	log "github.com/sirupsen/logrus"
	"github.com/timshannon/badgerhold/v4"
)

const (
	vtxoStoreDir = "vtxos"
)

type vtxoStore struct {
	db      *badgerhold.Store
	lock    *sync.Mutex
	eventCh chan types.VtxoEvent
}

func NewVtxoStore(dir string, logger badger.Logger) (types.VtxoStore, error) {
	if dir != "" {
		dir = filepath.Join(dir, vtxoStoreDir)
	}
	badgerDb, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open vtxo store: %s", err)
	}
	return &vtxoStore{
		db:      badgerDb,
		lock:    &sync.Mutex{},
		eventCh: make(chan types.VtxoEvent),
	}, nil
}

func (s *vtxoStore) AddVtxos(_ context.Context, vtxos []types.Vtxo) (int, error) {
	addedVtxos := make([]types.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if err := s.db.Insert(vtxo.Outpoint.String(), &vtxo); err != nil {
			if errors.Is(err, badgerhold.ErrKeyExists) {
				continue
			}
			return -1, err
		}
		addedVtxos = append(addedVtxos, vtxo)
	}

	if len(addedVtxos) > 0 {
		go s.sendEvent(types.VtxoEvent{Type: types.VtxosAdded, Vtxos: addedVtxos})
	}

	return len(addedVtxos), nil
}

func (s *vtxoStore) SpendVtxos(
	ctx context.Context, spentVtxoMap map[types.Outpoint]string, arkTxid string,
) (int, error) {
	outpoints := make([]types.Outpoint, 0, len(spentVtxoMap))
	for outpoint := range spentVtxoMap {
		outpoints = append(outpoints, outpoint)
	}
	vtxos, err := s.GetVtxos(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	spentVtxos := make([]types.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if vtxo.Spent {
			continue
		}
		vtxo.Spent = true
		vtxo.SpentBy = spentVtxoMap[vtxo.Outpoint]
		vtxo.ArkTxid = arkTxid

		if err := s.db.Update(vtxo.Outpoint.String(), &vtxo); err != nil {
			return -1, err
		}
		spentVtxos = append(spentVtxos, vtxo)
	}

	if len(spentVtxos) > 0 {
		go s.sendEvent(types.VtxoEvent{Type: types.VtxosSpent, Vtxos: spentVtxos})
	}

	return len(spentVtxos), nil
}

func (s *vtxoStore) SettleVtxos(
	ctx context.Context, spentVtxoMap map[types.Outpoint]string, settledBy string,
) (int, error) {
	outpoints := make([]types.Outpoint, 0, len(spentVtxoMap))
	for outpoint := range spentVtxoMap {
		outpoints = append(outpoints, outpoint)
	}
	vtxos, err := s.GetVtxos(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	spentVtxos := make([]types.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if vtxo.Spent {
			continue
		}
		vtxo.Spent = true
		vtxo.SpentBy = spentVtxoMap[vtxo.Outpoint]
		vtxo.SettledBy = settledBy

		if err := s.db.Update(vtxo.Outpoint.String(), &vtxo); err != nil {
			return -1, err
		}
		spentVtxos = append(spentVtxos, vtxo)
	}

	if len(spentVtxos) > 0 {
		go s.sendEvent(types.VtxoEvent{Type: types.VtxosSpent, Vtxos: spentVtxos})
	}

	return len(spentVtxos), nil
}

func (s *vtxoStore) UpdateVtxos(ctx context.Context, vtxos []types.Vtxo) (int, error) {
	for _, vtxo := range vtxos {
		if err := s.db.Upsert(vtxo.Outpoint.String(), &vtxo); err != nil {
			return -1, err
		}
	}
	go s.sendEvent(types.VtxoEvent{
		Type:  types.VtxosUpdated,
		Vtxos: vtxos,
	})
	return len(vtxos), nil
}

func (s *vtxoStore) GetAllVtxos(
	_ context.Context,
) (spendable, spent []types.Vtxo, err error) {
	var allVtxos []types.Vtxo
	err = s.db.Find(&allVtxos, nil)
	if err != nil {
		return nil, nil, err
	}

	for _, vtxo := range allVtxos {
		if vtxo.Spent {
			spent = append(spent, vtxo)
		} else {
			spendable = append(spendable, vtxo)
		}
	}
	return
}

func (s *vtxoStore) GetVtxos(
	_ context.Context, keys []types.Outpoint,
) ([]types.Vtxo, error) {
	var vtxos []types.Vtxo
	for _, key := range keys {
		var vtxo types.Vtxo
		err := s.db.Get(key.String(), &vtxo)
		if err != nil {
			if errors.Is(err, badgerhold.ErrNotFound) {
				continue
			}

			return nil, err
		}
		vtxos = append(vtxos, vtxo)
	}

	return vtxos, nil
}

func (s *vtxoStore) GetEventChannel() chan types.VtxoEvent {
	return s.eventCh
}

func (s *vtxoStore) Clean(_ context.Context) error {
	if err := s.db.Badger().DropAll(); err != nil {
		return fmt.Errorf("failed to clean the vtxo db: %s", err)
	}
	return nil
}

func (s *vtxoStore) Close() {
	if err := s.db.Close(); err != nil {
		log.Debugf("error on closing db: %s", err)
	}
}

func (s *vtxoStore) sendEvent(event types.VtxoEvent) {
	s.lock.Lock()
	defer s.lock.Unlock()

	select {
	case s.eventCh <- event:
		return
	default:
		time.Sleep(100 * time.Millisecond)
	}
}
