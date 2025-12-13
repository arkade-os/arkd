package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/store/sql/sqlc/queries"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

type utxoRepository struct {
	db      *sql.DB
	querier *queries.Queries
	lock    *sync.Mutex
	eventCh chan types.UtxoEvent
}

func NewUtxoStore(db *sql.DB) types.UtxoStore {
	return &utxoRepository{
		db:      db,
		querier: queries.New(db),
		lock:    &sync.Mutex{},
		eventCh: make(chan types.UtxoEvent, 100),
	}
}

func (r *utxoRepository) ReplaceUtxo(
	ctx context.Context,
	from types.Outpoint,
	to types.Outpoint,
) error {
	utxo, err := r.querier.SelectUtxo(ctx, queries.SelectUtxoParams{
		Txid: from.Txid,
		Vout: int64(from.VOut),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("utxo not found at outpoint %s", from.String())
		}
		return err
	}

	existingUtxo := rowToUtxo(utxo)

	existingUtxo.Outpoint = to

	txBody := func(querierWithTx *queries.Queries) error {
		if err := querierWithTx.DeleteUtxo(ctx, queries.DeleteUtxoParams{
			Txid: from.Txid,
			Vout: int64(from.VOut),
		}); err != nil {
			return err
		}

		var createdAt, spendableAt int64
		if !existingUtxo.CreatedAt.IsZero() {
			createdAt = existingUtxo.CreatedAt.Unix()
		}
		if !existingUtxo.SpendableAt.IsZero() {
			spendableAt = existingUtxo.SpendableAt.Unix()
		}
		var delayType string
		emptyDelay := arklib.RelativeLocktime{}
		if existingUtxo.Delay != emptyDelay {
			delayType = "seconds"
			if existingUtxo.Delay.Type == arklib.LocktimeTypeBlock {
				delayType = "blocks"
			}
		}

		if err := querierWithTx.InsertUtxo(ctx, queries.InsertUtxoParams{
			Txid:        existingUtxo.Txid,
			Vout:        int64(existingUtxo.VOut),
			Script:      existingUtxo.Script,
			Amount:      int64(existingUtxo.Amount),
			SpendableAt: sql.NullInt64{Int64: spendableAt, Valid: spendableAt != 0},
			CreatedAt:   sql.NullInt64{Int64: createdAt, Valid: createdAt != 0},
			Spent:       existingUtxo.Spent,
			SpentBy:     sql.NullString{String: existingUtxo.SpentBy, Valid: existingUtxo.SpentBy != ""},
			Tapscripts: sql.NullString{
				String: strings.Join(existingUtxo.Tapscripts, ","),
				Valid:  len(existingUtxo.Tapscripts) > 0,
			},
			Tx: sql.NullString{String: existingUtxo.Tx, Valid: existingUtxo.Tx != ""},
			DelayValue: sql.NullInt64{
				Int64: int64(existingUtxo.Delay.Value),
				Valid: existingUtxo.Delay.Value != 0,
			},
			DelayType: sql.NullString{
				String: delayType,
				Valid:  delayType != "",
			},
		}); err != nil {
			return err
		}

		return nil
	}

	if err := execTx(ctx, r.db, txBody); err != nil {
		return err
	}

	go r.sendEvent(types.UtxoEvent{
		Type:  types.UtxosReplaced,
		Utxos: []types.Utxo{existingUtxo},
	})

	return nil
}

func (r *utxoRepository) AddUtxos(ctx context.Context, utxos []types.Utxo) (int, error) {
	addedUtxos := make([]types.Utxo, 0, len(utxos))
	txBody := func(querierWithTx *queries.Queries) error {
		for i := range utxos {
			utxo := utxos[i]
			var createdAt, spendableAt int64
			if !utxo.CreatedAt.IsZero() {
				createdAt = utxo.CreatedAt.Unix()
			}
			if !utxo.SpendableAt.IsZero() {
				spendableAt = utxo.SpendableAt.Unix()
			}
			var delayType string
			emptyDelay := arklib.RelativeLocktime{}
			if utxo.Delay != emptyDelay {
				delayType = "seconds"
				if utxo.Delay.Type == arklib.LocktimeTypeBlock {
					delayType = "blocks"
				}
			}
			if err := querierWithTx.InsertUtxo(
				ctx, queries.InsertUtxoParams{
					Txid:        utxo.Txid,
					Vout:        int64(utxo.VOut),
					Script:      utxo.Script,
					Amount:      int64(utxo.Amount),
					SpendableAt: sql.NullInt64{Int64: spendableAt, Valid: spendableAt != 0},
					CreatedAt:   sql.NullInt64{Int64: createdAt, Valid: createdAt != 0},
					Spent:       utxo.Spent,
					SpentBy:     sql.NullString{String: utxo.SpentBy, Valid: utxo.SpentBy != ""},
					Tapscripts: sql.NullString{
						String: strings.Join(utxo.Tapscripts, ","),
						Valid:  len(utxo.Tapscripts) > 0,
					},
					Tx: sql.NullString{String: utxo.Tx, Valid: utxo.Tx != ""},
					DelayValue: sql.NullInt64{
						Int64: int64(utxo.Delay.Value),
						Valid: utxo.Delay.Value != 0,
					},
					DelayType: sql.NullString{
						String: delayType,
						Valid:  delayType != "",
					},
				},
			); err != nil {
				if strings.Contains(err.Error(), "UNIQUE constraint failed") {
					continue
				}
				return err
			}
			addedUtxos = append(addedUtxos, utxo)
		}

		return nil
	}
	if err := execTx(ctx, r.db, txBody); err != nil {
		return -1, err
	}

	if len(addedUtxos) > 0 {
		go r.sendEvent(types.UtxoEvent{Type: types.UtxosAdded, Utxos: addedUtxos})
	}

	return len(addedUtxos), nil
}

func (r *utxoRepository) SpendUtxos(
	ctx context.Context, spentUtxoMap map[types.Outpoint]string,
) (int, error) {
	outpoints := make([]types.Outpoint, 0, len(spentUtxoMap))
	for outpoint := range spentUtxoMap {
		outpoints = append(outpoints, outpoint)
	}
	utxos, err := r.GetUtxos(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	spentUtxos := make([]types.Utxo, 0, len(utxos))
	txBody := func(querierWithTx *queries.Queries) error {
		for _, utxo := range utxos {
			if utxo.Spent {
				continue
			}
			if err := querierWithTx.UpdateUtxo(ctx, queries.UpdateUtxoParams{
				SpentBy: sql.NullString{String: spentUtxoMap[utxo.Outpoint], Valid: true},
				Spent:   true,
				Txid:    utxo.Txid,
				Vout:    int64(utxo.VOut),
			}); err != nil {
				return err
			}
			utxo.Spent = true
			utxo.SpentBy = spentUtxoMap[utxo.Outpoint]
			spentUtxos = append(spentUtxos, utxo)
		}
		return nil
	}
	if err := execTx(ctx, r.db, txBody); err != nil {
		return -1, err
	}

	if len(spentUtxos) > 0 {
		go r.sendEvent(types.UtxoEvent{Type: types.UtxosSpent, Utxos: spentUtxos})
	}

	return len(spentUtxos), nil
}

func (r *utxoRepository) ConfirmUtxos(
	ctx context.Context, confirmedUtxosMap map[types.Outpoint]int64,
) (int, error) {
	outpoints := make([]types.Outpoint, 0, len(confirmedUtxosMap))
	for outpoint := range confirmedUtxosMap {
		outpoints = append(outpoints, outpoint)
	}
	utxos, err := r.GetUtxos(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	confirmedUtxos := make([]types.Utxo, 0, len(utxos))
	txBody := func(querierWithTx *queries.Queries) error {
		for _, utxo := range utxos {
			if !utxo.CreatedAt.IsZero() {
				continue
			}

			createdAtUnix := confirmedUtxosMap[utxo.Outpoint]
			spendableAt := time.Unix(createdAtUnix, 0)
			if utxo.Delay.Value > 0 {
				spendableAt = spendableAt.Add(time.Duration(utxo.Delay.Seconds()) * time.Second)
			}

			if err := querierWithTx.UpdateUtxo(ctx, queries.UpdateUtxoParams{
				Txid:      utxo.Txid,
				Vout:      int64(utxo.VOut),
				CreatedAt: sql.NullInt64{Int64: createdAtUnix, Valid: true},
				SpendableAt: sql.NullInt64{
					Int64: spendableAt.Unix(),
					Valid: true,
				},
			}); err != nil {
				return err
			}
			utxo.CreatedAt = time.Unix(createdAtUnix, 0)
			utxo.SpendableAt = spendableAt
			confirmedUtxos = append(confirmedUtxos, utxo)
		}
		return nil
	}
	if err := execTx(ctx, r.db, txBody); err != nil {
		return -1, err
	}

	if len(confirmedUtxos) > 0 {
		go r.sendEvent(types.UtxoEvent{Type: types.UtxosConfirmed, Utxos: confirmedUtxos})
	}

	return len(confirmedUtxos), nil
}

func (r *utxoRepository) GetAllUtxos(
	ctx context.Context,
) (spendable, spent []types.Utxo, err error) {
	rows, err := r.querier.SelectAllUtxos(ctx)
	if err != nil {
		return
	}

	for _, row := range rows {
		utxo := rowToUtxo(row)
		if utxo.Spent {
			spent = append(spent, utxo)
		} else {
			spendable = append(spendable, utxo)
		}
	}
	return
}

func (r *utxoRepository) GetUtxos(
	ctx context.Context, keys []types.Outpoint,
) ([]types.Utxo, error) {
	vtxos := make([]types.Utxo, 0, len(keys))
	for _, key := range keys {
		row, err := r.querier.SelectUtxo(ctx, queries.SelectUtxoParams{
			Txid: key.Txid,
			Vout: int64(key.VOut),
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, err
		}
		vtxos = append(vtxos, rowToUtxo(row))
	}

	return vtxos, nil
}

func (r *utxoRepository) GetEventChannel() <-chan types.UtxoEvent {
	return r.eventCh
}

func (r *utxoRepository) Clean(ctx context.Context) error {
	if err := r.querier.CleanUtxos(ctx); err != nil {
		return err
	}
	// nolint:all
	r.db.ExecContext(ctx, "VACUUM")
	return nil
}

func (r *utxoRepository) Close() {
	// nolint:all
	r.db.Close()
}

func (r *utxoRepository) sendEvent(event types.UtxoEvent) {
	r.lock.Lock()
	defer r.lock.Unlock()

	select {
	case r.eventCh <- event:
		return
	default:
		time.Sleep(100 * time.Millisecond)
	}
}

func rowToUtxo(row queries.Utxo) types.Utxo {
	var createdAt, spendableAt time.Time
	if row.CreatedAt.Valid {
		createdAt = time.Unix(row.CreatedAt.Int64, 0)
	}
	if row.SpendableAt.Valid {
		spendableAt = time.Unix(row.SpendableAt.Int64, 0)
	}
	var tapscripts []string
	if row.Tapscripts.Valid {
		tapscripts = strings.Split(row.Tapscripts.String, ",")
	}
	var delay arklib.RelativeLocktime
	if row.DelayValue.Valid {
		delayType := arklib.LocktimeTypeSecond
		if row.DelayType.String == "blocks" {
			delayType = arklib.LocktimeTypeBlock
		}
		delay = arklib.RelativeLocktime{
			Value: uint32(row.DelayValue.Int64),
			Type:  delayType,
		}
	}
	return types.Utxo{
		Outpoint: types.Outpoint{
			Txid: row.Txid,
			VOut: uint32(row.Vout),
		},
		Amount:      uint64(row.Amount),
		Script:      row.Script,
		Delay:       delay,
		SpendableAt: spendableAt,
		CreatedAt:   createdAt,
		Tapscripts:  tapscripts,
		Spent:       row.Spent,
		SpentBy:     row.SpentBy.String,
		Tx:          row.Tx.String,
	}
}
