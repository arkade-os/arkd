package kvstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ark-network/ark/pkg/client-sdk/types"
	"github.com/dgraph-io/badger/v4"
	log "github.com/sirupsen/logrus"
	"github.com/timshannon/badgerhold/v4"
)

const (
	transactionStoreDir = "transactions"
)

type txStore struct {
	db      *badgerhold.Store
	lock    *sync.Mutex
	eventCh chan types.TransactionEvent
}

func NewTransactionStore(
	dir string, logger badger.Logger,
) (types.TransactionStore, error) {
	if dir != "" {
		dir = filepath.Join(dir, transactionStoreDir)
	}
	badgerDb, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open transaction store: %s", err)
	}
	return &txStore{
		db:      badgerDb,
		lock:    &sync.Mutex{},
		eventCh: make(chan types.TransactionEvent),
	}, nil
}

func (s *txStore) AddTransactions(
	_ context.Context, txs []types.Transaction,
) (int, error) {
	addedTxs := make([]types.Transaction, 0, len(txs))
	for _, tx := range txs {
		if err := s.db.Insert(tx.TransactionKey.String(), &tx); err != nil {
			if errors.Is(err, badgerhold.ErrKeyExists) {
				continue
			}
			return -1, err
		}
		addedTxs = append(addedTxs, tx)
	}

	if len(addedTxs) > 0 {
		go s.sendEvent(types.TransactionEvent{Type: types.TxsAdded, Txs: addedTxs})
	}

	return len(addedTxs), nil
}

func (s *txStore) SettleTransactions(
	ctx context.Context, txids []string, settledBy string,
) (int, error) {
	txs, err := s.GetTransactions(ctx, txids)
	if err != nil {
		return -1, err
	}

	settledTxs := make([]types.Transaction, 0, len(txs))
	for _, tx := range txs {
		if tx.Settled {
			continue
		}
		tx.Settled = true
		tx.SettledBy = settledBy
		if err := s.db.Upsert(tx.TransactionKey.String(), &tx); err != nil {
			return -1, err
		}
		settledTxs = append(settledTxs, tx)
	}

	if len(settledTxs) > 0 {
		go s.sendEvent(types.TransactionEvent{Type: types.TxsSettled, Txs: settledTxs})
	}

	return len(settledTxs), nil
}

func (s *txStore) ConfirmTransactions(
	ctx context.Context, txids []string, timestamp time.Time,
) (int, error) {
	txs, err := s.GetTransactions(ctx, txids)
	if err != nil {
		return -1, err
	}

	confirmedTxs := make([]types.Transaction, 0, len(txs))
	for _, tx := range txs {
		if !tx.CreatedAt.IsZero() {
			continue
		}
		tx.CreatedAt = timestamp
		if err := s.db.Upsert(tx.TransactionKey.String(), &tx); err != nil {
			return -1, err
		}
		confirmedTxs = append(confirmedTxs, tx)
	}

	if len(confirmedTxs) > 0 {
		go s.sendEvent(types.TransactionEvent{Type: types.TxsConfirmed, Txs: confirmedTxs})
	}

	return len(confirmedTxs), nil
}

func (s *txStore) RbfTransactions(
	ctx context.Context, rbfTxs map[string]types.Transaction,
) (int, error) {
	txids := make([]string, 0, len(rbfTxs))
	for txid := range rbfTxs {
		txids = append(txids, txid)
	}

	txs, err := s.GetTransactions(ctx, txids)
	if err != nil {
		return -1, err
	}

	if len(txs) == 0 {
		return 0, nil
	}

	txsToAdd := make([]types.Transaction, 0, len(txs))
	txsToDelete := make([]string, 0, len(txs))
	replacements := make(map[string]string)
	for _, tx := range txs {
		rbfTx := rbfTxs[tx.TransactionKey.String()]
		rbfTx.Type = tx.Type
		rbfTx.Amount = tx.Amount
		txsToAdd = append(txsToAdd, rbfTx)
		txsToDelete = append(txsToDelete, tx.TransactionKey.String())
		replacements[tx.TransactionKey.String()] = rbfTx.TransactionKey.String()
	}

	count, err := s.replaceTxs(txsToAdd, txsToDelete)
	if err != nil {
		return -1, err
	}

	go s.sendEvent(types.TransactionEvent{
		Type:         types.TxsReplaced,
		Txs:          txs,
		Replacements: replacements,
	})

	return count, nil
}

func (s *txStore) GetAllTransactions(
	_ context.Context,
) ([]types.Transaction, error) {
	var txs []types.Transaction
	err := s.db.Find(&txs, nil)

	sort.Slice(txs, func(i, j int) bool {
		txi := txs[i]
		txj := txs[j]
		if txi.CreatedAt.Equal(txj.CreatedAt) {
			return txi.Type > txj.Type
		}
		return txi.CreatedAt.After(txj.CreatedAt)
	})

	return txs, err
}

func (s *txStore) GetTransactions(
	_ context.Context, txids []string,
) ([]types.Transaction, error) {
	txs := make([]types.Transaction, 0, len(txids))
	for _, txid := range txids {
		var tx types.Transaction
		if err := s.db.Get(txid, &tx); err != nil {
			if errors.Is(err, badgerhold.ErrNotFound) {
				continue
			}

			return nil, err
		}
		txs = append(txs, tx)
	}
	return txs, nil
}

func (s *txStore) UpdateTransactions(_ context.Context, txs []types.Transaction) (int, error) {
	for _, tx := range txs {
		if err := s.db.Upsert(tx.TransactionKey.String(), &tx); err != nil {
			return -1, err
		}
	}

	go s.sendEvent(types.TransactionEvent{
		Type: types.TxsUpdated,
		Txs:  txs,
	})

	return len(txs), nil
}

func (s *txStore) GetEventChannel() chan types.TransactionEvent {
	return s.eventCh
}

func (s *txStore) Clean(_ context.Context) error {
	if err := s.db.Badger().DropAll(); err != nil {
		return fmt.Errorf("failed to clean the transaction db: %s", err)
	}
	return nil
}

func (s *txStore) Close() {
	if err := s.db.Close(); err != nil {
		log.Debugf("error on closing transactions db: %s", err)
	}
	close(s.eventCh)
}

func (s *txStore) replaceTxs(txsToAdd []types.Transaction, txsToDelete []string) (int, error) {
	count := 0
	dbtx := s.db.Badger().NewTransaction(true)
	for _, tx := range txsToAdd {
		if err := s.db.TxInsert(dbtx, tx.TransactionKey.String(), &tx); err != nil {
			if errors.Is(err, badgerhold.ErrKeyExists) {
				continue
			}
			return -1, err
		}
		count++
	}
	for _, txid := range txsToDelete {
		if err := s.db.TxDelete(dbtx, txid, &types.Transaction{}); err != nil {
			return -1, err
		}
	}
	if err := dbtx.Commit(); err != nil {
		return -1, err
	}

	return count, nil
}

func (s *txStore) sendEvent(event types.TransactionEvent) {
	s.lock.Lock()
	defer s.lock.Unlock()

	select {
	case s.eventCh <- event:
		return
	default:
		time.Sleep(100 * time.Millisecond)
	}
}
