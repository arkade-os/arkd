package sqlstore

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/pkg/client-sdk/store/sql/sqlc/queries"
	"github.com/ark-network/ark/pkg/client-sdk/types"
)

type txStore struct {
	db      *sql.DB
	querier *queries.Queries
	lock    *sync.Mutex
	eventCh chan types.TransactionEvent
}

func NewTransactionStore(db *sql.DB) types.TransactionStore {
	return &txStore{
		db:      db,
		querier: queries.New(db),
		lock:    &sync.Mutex{},
		eventCh: make(chan types.TransactionEvent),
	}
}

func (v *txStore) AddTransactions(ctx context.Context, txs []types.Transaction) (int, error) {
	addedTxs := make([]types.Transaction, 0, len(txs))
	txBody := func(querierWithTx *queries.Queries) error {
		for i := range txs {
			tx := txs[i]
			txidType := "commitment"
			if tx.ArkTxid != "" {
				txidType = "ark"
			}
			if tx.BoardingTxid != "" {
				txidType = "boarding"
			}
			var createdAt int64
			if !tx.CreatedAt.IsZero() {
				createdAt = tx.CreatedAt.Unix()
			}
			if err := querierWithTx.InsertTx(
				ctx, queries.InsertTxParams{
					Txid:      tx.TransactionKey.String(),
					TxidType:  txidType,
					Amount:    int64(tx.Amount),
					Type:      string(tx.Type),
					Settled:   tx.Settled,
					CreatedAt: createdAt,
					Hex:       sql.NullString{String: tx.Hex, Valid: true},
					SettledBy: sql.NullString{String: tx.SettledBy, Valid: true},
				},
			); err != nil {
				if strings.Contains(err.Error(), "UNIQUE constraint failed") {
					continue
				}
				return err
			}
			addedTxs = append(addedTxs, tx)
		}

		return nil
	}
	if err := execTx(ctx, v.db, txBody); err != nil {
		return -1, err
	}

	if len(addedTxs) > 0 {
		go v.sendEvent(types.TransactionEvent{Type: types.TxsAdded, Txs: addedTxs})
	}

	return len(addedTxs), nil
}

func (v *txStore) SettleTransactions(ctx context.Context, txids []string, settledBy string) (int, error) {
	txs, err := v.GetTransactions(ctx, txids)
	if err != nil {
		return -1, err
	}

	settledTxs := make([]types.Transaction, 0, len(txs))
	txBody := func(querierWithTx *queries.Queries) error {
		for _, tx := range txs {
			if tx.Settled {
				continue
			}
			tx.Settled = true
			tx.SettledBy = settledBy
			if err := querierWithTx.UpdateTx(ctx, queries.UpdateTxParams{
				Txid:      tx.TransactionKey.String(),
				Settled:   sql.NullBool{Bool: true, Valid: true},
				SettledBy: sql.NullString{String: settledBy, Valid: true},
			}); err != nil {
				return err
			}
			settledTxs = append(settledTxs, tx)
		}
		return nil
	}
	if err := execTx(ctx, v.db, txBody); err != nil {
		return -1, err
	}

	if len(settledTxs) > 0 {
		go v.sendEvent(types.TransactionEvent{Type: types.TxsSettled, Txs: settledTxs})
	}

	return len(settledTxs), nil
}

func (v *txStore) ConfirmTransactions(ctx context.Context, txids []string, timestamp time.Time) (int, error) {
	txs, err := v.GetTransactions(ctx, txids)
	if err != nil {
		return -1, err
	}

	confirmedTxs := make([]types.Transaction, 0, len(txs))
	txBody := func(querierWithTx *queries.Queries) error {
		for _, tx := range txs {
			if !tx.CreatedAt.IsZero() {
				continue
			}
			if err := querierWithTx.UpdateTx(ctx, queries.UpdateTxParams{
				Txid:      tx.TransactionKey.String(),
				CreatedAt: sql.NullInt64{Int64: timestamp.Unix(), Valid: true},
			}); err != nil {
				return err
			}
			confirmedTxs = append(confirmedTxs, tx)
		}
		return nil
	}
	if err := execTx(ctx, v.db, txBody); err != nil {
		return -1, err
	}

	if len(confirmedTxs) > 0 {
		go v.sendEvent(types.TransactionEvent{Type: types.TxsConfirmed, Txs: confirmedTxs})
	}

	return len(confirmedTxs), nil
}
func (v *txStore) RbfTransactions(ctx context.Context, rbfTxs map[string]types.Transaction) (int, error) {
	txids := make([]string, 0, len(rbfTxs))
	for txid := range rbfTxs {
		txids = append(txids, txid)
	}

	txs, err := v.GetTransactions(ctx, txids)
	if err != nil {
		return -1, err
	}

	if len(txs) == 0 {
		return 0, nil
	}

	replacements := make(map[string]string)
	txBody := func(querierWithTx *queries.Queries) error {
		for _, tx := range txs {
			replacedBy := rbfTxs[tx.TransactionKey.String()]
			txidType := "commitment"
			if replacedBy.ArkTxid != "" {
				txidType = "ark"
			}
			if replacedBy.BoardingTxid != "" {
				txidType = "boarding"
			}
			var createdAt int64
			if !replacedBy.CreatedAt.IsZero() {
				createdAt = replacedBy.CreatedAt.Unix()
			}
			if err := querierWithTx.ReplaceTx(ctx, queries.ReplaceTxParams{
				NewTxid:   replacedBy.TransactionKey.String(),
				TxidType:  txidType,
				Amount:    int64(replacedBy.Amount),
				Type:      string(replacedBy.Type),
				Settled:   replacedBy.Settled,
				CreatedAt: createdAt,
				Hex:       sql.NullString{String: replacedBy.Hex, Valid: true},
				OldTxid:   tx.TransactionKey.String(),
				SettledBy: sql.NullString{String: replacedBy.SettledBy, Valid: true},
			}); err != nil {
				return err
			}
			replacements[tx.TransactionKey.String()] = replacedBy.TransactionKey.String()
		}
		return nil
	}
	if err := execTx(ctx, v.db, txBody); err != nil {
		return -1, err
	}

	go v.sendEvent(types.TransactionEvent{
		Type:         types.TxsReplaced,
		Txs:          txs,
		Replacements: replacements,
	})

	return len(txs), nil
}

func (v *txStore) GetAllTransactions(ctx context.Context) ([]types.Transaction, error) {
	rows, err := v.querier.SelectAllTxs(ctx)
	if err != nil {
		return nil, err
	}
	return readTxRows(rows), nil
}

func (v *txStore) GetTransactions(ctx context.Context, txids []string) ([]types.Transaction, error) {
	rows, err := v.querier.SelectTxs(ctx, txids)
	if err != nil {
		return nil, err
	}
	return readTxRows(rows), nil
}

func (v *txStore) UpdateTransactions(ctx context.Context, txs []types.Transaction) (int, error) {
	txBody := func(querierWithTx *queries.Queries) error {
		for _, tx := range txs {
			var settled sql.NullBool
			var createdAt sql.NullInt64
			if tx.Settled {
				settled = sql.NullBool{Bool: true, Valid: true}
			}
			if !tx.CreatedAt.IsZero() {
				createdAt = sql.NullInt64{Int64: tx.CreatedAt.Unix(), Valid: true}
			}
			if settled.Valid || createdAt.Valid {
				if err := querierWithTx.UpdateTx(ctx, queries.UpdateTxParams{
					Txid:      tx.TransactionKey.String(),
					Settled:   settled,
					CreatedAt: createdAt,
				}); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := execTx(ctx, v.db, txBody); err != nil {
		return -1, err
	}

	return len(txs), nil
}

func (v *txStore) GetEventChannel() chan types.TransactionEvent {
	return v.eventCh
}

func (v *txStore) Clean(ctx context.Context) error {
	if err := v.querier.CleanTxs(ctx); err != nil {
		return err
	}
	// nolint:all
	v.db.ExecContext(ctx, "VACUUM")
	return nil
}

func (v *txStore) Close() {
	// nolint:all
	v.db.Close()
}

func (v *txStore) sendEvent(event types.TransactionEvent) {
	v.lock.Lock()
	defer v.lock.Unlock()

	select {
	case v.eventCh <- event:
		return
	default:
		time.Sleep(100 * time.Millisecond)
	}
}

func rowToTx(row queries.Tx) types.Transaction {
	var commitmentTxid, arkTxid, boardingTxid string
	if row.TxidType == "commitment" {
		commitmentTxid = row.Txid
	}
	if row.TxidType == "ark" {
		arkTxid = row.Txid
	}
	if row.TxidType == "boarding" {
		boardingTxid = row.Txid
	}
	var createdAt time.Time
	if row.CreatedAt != 0 {
		createdAt = time.Unix(row.CreatedAt, 0)
	}
	return types.Transaction{
		TransactionKey: types.TransactionKey{
			CommitmentTxid: commitmentTxid,
			ArkTxid:        arkTxid,
			BoardingTxid:   boardingTxid,
		},
		Amount:    uint64(row.Amount),
		Type:      types.TxType(row.Type),
		Settled:   row.Settled,
		SettledBy: row.SettledBy.String,
		CreatedAt: createdAt,
		Hex:       row.Hex.String,
	}
}

func readTxRows(rows []queries.Tx) []types.Transaction {
	txs := make([]types.Transaction, 0, len(rows))
	for _, tx := range rows {
		txs = append(txs, rowToTx(tx))
	}

	return txs
}
