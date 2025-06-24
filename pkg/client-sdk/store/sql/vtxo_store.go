package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/ark-network/ark/pkg/client-sdk/store/sql/sqlc/queries"
	"github.com/ark-network/ark/pkg/client-sdk/types"
)

type vtxoRepository struct {
	db      *sql.DB
	querier *queries.Queries
	lock    *sync.Mutex
	eventCh chan types.VtxoEvent
}

func NewVtxoStore(db *sql.DB) types.VtxoStore {
	return &vtxoRepository{
		db:      db,
		querier: queries.New(db),
		lock:    &sync.Mutex{},
		eventCh: make(chan types.VtxoEvent),
	}
}

func (v *vtxoRepository) AddVtxos(ctx context.Context, vtxos []types.Vtxo) (int, error) {
	addedVtxos := make([]types.Vtxo, 0, len(vtxos))
	txBody := func(querierWithTx *queries.Queries) error {
		for i := range vtxos {
			vtxo := vtxos[i]
			var createdAt, expiresAt int64
			if !vtxo.ExpiresAt.IsZero() {
				expiresAt = vtxo.ExpiresAt.Unix()
			}
			if !vtxo.CreatedAt.IsZero() {
				createdAt = vtxo.CreatedAt.Unix()
			}
			if err := querierWithTx.InsertVtxo(
				ctx, queries.InsertVtxoParams{
					Txid:            vtxo.Txid,
					Vout:            int64(vtxo.VOut),
					Script:          vtxo.Script,
					Amount:          int64(vtxo.Amount),
					CommitmentTxids: strings.Join(vtxo.CommitmentTxids, ","),
					ExpiresAt:       expiresAt,
					CreatedAt:       createdAt,
					Preconfirmed:    vtxo.Preconfirmed,
					Swept:           vtxo.Swept,
					Redeemed:        vtxo.Redeemed,
					Spent:           vtxo.Spent,
					SpentBy:         sql.NullString{String: vtxo.SpentBy, Valid: true},
				},
			); err != nil {
				if strings.Contains(err.Error(), "UNIQUE constraint failed") {
					return nil
				}
				return err
			}
			addedVtxos = append(addedVtxos, vtxo)
		}

		return nil
	}
	if err := execTx(ctx, v.db, txBody); err != nil {
		return -1, err
	}

	if len(addedVtxos) > 0 {
		go v.sendEvent(types.VtxoEvent{Type: types.VtxosAdded, Vtxos: addedVtxos})
	}

	return len(addedVtxos), nil
}

func (v *vtxoRepository) SpendVtxos(ctx context.Context, outpoints []types.VtxoKey, spentBy string) (int, error) {
	vtxos, err := v.GetVtxos(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	spentVtxos := make([]types.Vtxo, 0, len(vtxos))
	txBody := func(querierWithTx *queries.Queries) error {
		for _, vtxo := range vtxos {
			if vtxo.Spent {
				continue
			}
			vtxo.Spent = true
			vtxo.SpentBy = spentBy
			if err := querierWithTx.UpdateVtxo(ctx, queries.UpdateVtxoParams{
				SpentBy: sql.NullString{String: vtxo.SpentBy, Valid: true},
				Txid:    vtxo.Txid,
				Vout:    int64(vtxo.VOut),
			}); err != nil {
				return err
			}
			spentVtxos = append(spentVtxos, vtxo)
		}
		return nil
	}
	if err := execTx(ctx, v.db, txBody); err != nil {
		return -1, err
	}

	if len(spentVtxos) > 0 {
		go v.sendEvent(types.VtxoEvent{Type: types.VtxosSpent, Vtxos: spentVtxos})
	}

	return len(spentVtxos), nil
}

func (v *vtxoRepository) UpdateVtxos(ctx context.Context, vtxos []types.Vtxo) (int, error) {
	updatedVtxos := make([]types.Vtxo, 0, len(vtxos))
	txBody := func(querierWithTx *queries.Queries) error {
		for _, vtxo := range vtxos {
			if err := querierWithTx.UpdateVtxo(ctx, queries.UpdateVtxoParams{
				SpentBy: sql.NullString{String: vtxo.SpentBy, Valid: true},
				Txid:    vtxo.Txid,
				Vout:    int64(vtxo.VOut),
			}); err != nil {
				return err
			}
			updatedVtxos = append(updatedVtxos, vtxo)
		}
		return nil
	}
	if err := execTx(ctx, v.db, txBody); err != nil {
		return -1, err
	}

	go v.sendEvent(types.VtxoEvent{
		Type:  types.VtxosUpdated,
		Vtxos: updatedVtxos,
	})

	return len(updatedVtxos), nil
}

func (v *vtxoRepository) GetAllVtxos(
	ctx context.Context,
) (spendable, spent []types.Vtxo, err error) {
	rows, err := v.querier.SelectAllVtxos(ctx)
	if err != nil {
		return
	}

	for _, row := range rows {
		vtxo := rowToVtxo(row)
		if vtxo.Spent {
			spent = append(spent, vtxo)
		} else {
			spendable = append(spendable, vtxo)
		}
	}
	return
}

func (v *vtxoRepository) GetVtxos(
	ctx context.Context, keys []types.VtxoKey,
) ([]types.Vtxo, error) {
	vtxos := make([]types.Vtxo, 0, len(keys))
	for _, key := range keys {
		row, err := v.querier.SelectVtxo(ctx, queries.SelectVtxoParams{
			Txid: key.Txid,
			Vout: int64(key.VOut),
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, err
		}
		vtxos = append(vtxos, rowToVtxo(row))
	}

	return vtxos, nil
}

func (v *vtxoRepository) GetEventChannel() chan types.VtxoEvent {
	return v.eventCh
}

func (v *vtxoRepository) Clean(ctx context.Context) error {
	if err := v.querier.CleanVtxos(ctx); err != nil {
		return err
	}
	// nolint:all
	v.db.ExecContext(ctx, "VACUUM")
	return nil
}

func (v *vtxoRepository) Close() {
	// nolint:all
	v.db.Close()
}

func (v *vtxoRepository) sendEvent(event types.VtxoEvent) {
	v.lock.Lock()
	defer v.lock.Unlock()

	select {
	case v.eventCh <- event:
		return
	default:
		time.Sleep(100 * time.Millisecond)
	}
}

func rowToVtxo(row queries.Vtxo) types.Vtxo {
	var expiresAt, createdAt time.Time
	if row.ExpiresAt != 0 {
		expiresAt = time.Unix(row.ExpiresAt, 0)
	}
	if row.CreatedAt != 0 {
		createdAt = time.Unix(row.CreatedAt, 0)
	}
	return types.Vtxo{
		VtxoKey: types.VtxoKey{
			Txid: row.Txid,
			VOut: uint32(row.Vout),
		},
		Script:          row.Script,
		Amount:          uint64(row.Amount),
		CommitmentTxids: strings.Split(row.CommitmentTxids, ","),
		ExpiresAt:       expiresAt,
		CreatedAt:       createdAt,
		Preconfirmed:    row.Preconfirmed,
		Swept:           row.Swept,
		Redeemed:        row.Redeemed,
		Spent:           row.Spent,
		SpentBy:         row.SpentBy.String,
	}
}
