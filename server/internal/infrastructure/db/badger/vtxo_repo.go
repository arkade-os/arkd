package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const vtxoStoreDir = "vtxos"

type vtxoRepository struct {
	store *badgerhold.Store
}

func (r *vtxoRepository) GetSpendableVtxosWithPubKey(ctx context.Context, pubkey string) ([]domain.Vtxo, error) {
	// TODO implement
	return nil, nil
}

func NewVtxoRepository(config ...interface{}) (domain.VtxoRepository, error) {
	if len(config) != 2 {
		return nil, fmt.Errorf("invalid config")
	}
	baseDir, ok := config[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid base directory")
	}
	var logger badger.Logger
	if config[1] != nil {
		logger, ok = config[1].(badger.Logger)
		if !ok {
			return nil, fmt.Errorf("invalid logger")
		}
	}

	var dir string
	if len(baseDir) > 0 {
		dir = filepath.Join(baseDir, vtxoStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open round events store: %s", err)
	}

	return &vtxoRepository{store}, nil
}

func (r *vtxoRepository) AddVtxos(
	ctx context.Context, vtxos []domain.Vtxo,
) error {
	return r.addVtxos(ctx, vtxos)
}

func (r *vtxoRepository) SettleVtxos(
	ctx context.Context, spentVtxos map[domain.Outpoint]string, commitmentTxid string,
) error {
	for vtxoKey, spentBy := range spentVtxos {
		if err := r.settleVtxo(ctx, vtxoKey, spentBy, commitmentTxid); err != nil {
			return err
		}
	}
	return nil
}

func (r *vtxoRepository) SpendVtxos(
	ctx context.Context, spentVtxos map[domain.Outpoint]string, arkTxid string,
) error {
	for vtxoKey, spentBy := range spentVtxos {
		if err := r.spendVtxo(ctx, vtxoKey, spentBy, arkTxid); err != nil {
			return err
		}
	}
	return nil
}

func (r *vtxoRepository) RedeemVtxos(
	ctx context.Context, vtxoKeys []domain.Outpoint,
) error {
	for _, vtxoKey := range vtxoKeys {
		_, err := r.redeemVtxo(ctx, vtxoKey)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *vtxoRepository) GetVtxos(
	ctx context.Context, vtxoKeys []domain.Outpoint,
) ([]domain.Vtxo, error) {
	vtxos := make([]domain.Vtxo, 0, len(vtxoKeys))
	for _, vtxoKey := range vtxoKeys {
		vtxo, err := r.getVtxo(ctx, vtxoKey)
		if err != nil {
			return nil, err
		}
		vtxos = append(vtxos, *vtxo)
	}
	return vtxos, nil
}

func (r *vtxoRepository) GetVtxosForRound(
	ctx context.Context, txid string,
) ([]domain.Vtxo, error) {
	query := badgerhold.Where("RoundTx").Eq(txid)
	return r.findVtxos(ctx, query)
}

func (r *vtxoRepository) GetLeafVtxosForRound(
	ctx context.Context, txid string,
) ([]domain.Vtxo, error) {
	query := badgerhold.Where("RoundTx").Eq(txid).And("RedeemTx").Eq("")
	return r.findVtxos(ctx, query)
}

func (r *vtxoRepository) GetAllNonRedeemedVtxos(
	ctx context.Context, pubkey string,
) ([]domain.Vtxo, []domain.Vtxo, error) {
	query := badgerhold.Where("Redeemed").Eq(false)
	if len(pubkey) > 0 {
		query = query.And("PubKey").Eq(pubkey)
	}
	vtxos, err := r.findVtxos(ctx, query)
	if err != nil {
		return nil, nil, err
	}

	spentVtxos := make([]domain.Vtxo, 0, len(vtxos))
	unspentVtxos := make([]domain.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if vtxo.Spent || vtxo.Swept {
			spentVtxos = append(spentVtxos, vtxo)
		} else {
			unspentVtxos = append(unspentVtxos, vtxo)
		}
	}
	return unspentVtxos, spentVtxos, nil
}

func (r *vtxoRepository) GetAllSweepableVtxos(ctx context.Context) ([]domain.Vtxo, error) {
	query := badgerhold.Where("Redeemed").Eq(false).And("Swept").Eq(false)
	return r.findVtxos(ctx, query)
}

func (r *vtxoRepository) GetAll(ctx context.Context) ([]domain.Vtxo, error) {
	return r.findVtxos(ctx, &badgerhold.Query{})
}

func (r *vtxoRepository) SweepVtxos(
	ctx context.Context, vtxoKeys []domain.Outpoint,
) error {
	for _, vtxoKey := range vtxoKeys {
		if err := r.sweepVtxo(ctx, vtxoKey); err != nil {
			return err
		}
	}
	return nil
}

func (r *vtxoRepository) UpdateExpireAt(ctx context.Context, vtxos []domain.Outpoint, expireAt int64) error {
	var err error

	for range maxRetries {
		err = func() error {
			tx := r.store.Badger().NewTransaction(true)
			defer tx.Discard()

			for _, vtxoKey := range vtxos {
				vtxo, err := r.getVtxo(ctx, vtxoKey)
				if err != nil {
					return err
				}
				vtxo.ExpireAt = expireAt
				if err := r.store.TxUpdate(tx, vtxo.Hash(), *vtxo); err != nil {
					return err
				}
			}

			return tx.Commit()
		}()
		if err == nil {
			return nil // Success
		}

		if errors.Is(err, badger.ErrConflict) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return err
	}

	return err
}

func (r *vtxoRepository) GetAllVtxosWithPubKey(
	ctx context.Context, pubkey string,
) ([]domain.Vtxo, []domain.Vtxo, error) {
	query := badgerhold.Where("PubKey").Eq(pubkey)
	vtxos, err := r.findVtxos(ctx, query)
	if err != nil {
		return nil, nil, err
	}

	spentVtxos := make([]domain.Vtxo, 0, len(vtxos))
	unspentVtxos := make([]domain.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if vtxo.Spent || vtxo.Swept {
			spentVtxos = append(spentVtxos, vtxo)
		} else {
			unspentVtxos = append(unspentVtxos, vtxo)
		}
	}
	return unspentVtxos, spentVtxos, nil
}

func (r *vtxoRepository) GetAllVtxosWithPubKeys(
	ctx context.Context, pubkeys []string, spendableOnly, spentOnly bool,
) ([]domain.Vtxo, error) {
	if spendableOnly && spendableOnly == spentOnly {
		return nil, fmt.Errorf("spendable and spent only can't be true at the same time")
	}

	allVtxos := make([]domain.Vtxo, 0)
	for _, pubkey := range pubkeys {
		query := badgerhold.Where("PubKey").Eq(pubkey)
		vtxos, err := r.findVtxos(ctx, query)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(vtxos, func(i, j int) bool {
			return vtxos[i].CreatedAt > vtxos[j].CreatedAt
		})

		if spendableOnly {
			spendableVtxos := make([]domain.Vtxo, 0, len(vtxos))
			for _, vtxo := range vtxos {
				if !vtxo.Spent && !vtxo.Swept && !vtxo.Redeemed {
					spendableVtxos = append(spendableVtxos, vtxo)
				}
			}
			vtxos = spendableVtxos
		}
		if spentOnly {
			spentVtxos := make([]domain.Vtxo, 0, len(vtxos))
			for _, vtxo := range vtxos {
				if vtxo.Spent || vtxo.Swept || vtxo.Redeemed {
					spentVtxos = append(spentVtxos, vtxo)
				}
			}
			vtxos = spentVtxos
		}
		allVtxos = append(allVtxos, vtxos...)
	}
	return allVtxos, nil
}

func (r *vtxoRepository) Close() {
	// nolint:all
	r.store.Close()
}

func (r *vtxoRepository) addVtxos(
	ctx context.Context, vtxos []domain.Vtxo,
) error {
	for _, vtxo := range vtxos {
		vtxoKey := vtxo.Hash()
		var insertFn func() error
		if ctx.Value("tx") != nil {
			tx := ctx.Value("tx").(*badger.Txn)
			insertFn = func() error {
				return r.store.TxInsert(tx, vtxoKey, vtxo)
			}
		} else {
			insertFn = func() error {
				return r.store.Insert(vtxoKey, vtxo)
			}
		}
		if err := insertFn(); err != nil {
			if errors.Is(err, badgerhold.ErrKeyExists) {
				continue
			}
			if errors.Is(err, badger.ErrConflict) {
				attempts := 1
				for errors.Is(err, badger.ErrConflict) && attempts <= maxRetries {
					time.Sleep(100 * time.Millisecond)
					err = insertFn()
					attempts++
				}
			}
			return err
		}
	}
	return nil
}

func (r *vtxoRepository) getVtxo(
	ctx context.Context, vtxoKey domain.Outpoint,
) (*domain.Vtxo, error) {
	var vtxo domain.Vtxo
	var err error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxGet(tx, vtxoKey.Hash(), &vtxo)
	} else {
		err = r.store.Get(vtxoKey.Hash(), &vtxo)
	}
	if err != nil && err == badgerhold.ErrNotFound {
		return nil, fmt.Errorf("vtxo %s:%d not found", vtxoKey.Txid, vtxoKey.VOut)
	}

	return &vtxo, nil
}

func (r *vtxoRepository) settleVtxo(ctx context.Context, vtxoKey domain.Outpoint, spentBy, settledBy string) error {
	vtxo, err := r.getVtxo(ctx, vtxoKey)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil
		}
		return err
	}
	if vtxo.Spent {
		return nil
	}

	vtxo.Spent = true
	vtxo.SpentBy = spentBy
	vtxo.SettledBy = settledBy

	return r.updateVtxo(ctx, vtxo)
}

func (r *vtxoRepository) spendVtxo(ctx context.Context, vtxoKey domain.Outpoint, spentBy, arkTxid string) error {
	vtxo, err := r.getVtxo(ctx, vtxoKey)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil
		}
		return err
	}
	if vtxo.Spent {
		return nil
	}

	vtxo.Spent = true
	vtxo.SpentBy = spentBy
	vtxo.ArkTxid = arkTxid

	return r.updateVtxo(ctx, vtxo)
}

func (r *vtxoRepository) redeemVtxo(ctx context.Context, vtxoKey domain.Outpoint) (*domain.Vtxo, error) {
	vtxo, err := r.getVtxo(ctx, vtxoKey)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, err
	}
	if vtxo.Redeemed {
		return nil, nil
	}

	vtxo.Redeemed = true
	vtxo.ExpireAt = 0
	if err := r.updateVtxo(ctx, vtxo); err != nil {
		return nil, err
	}
	return vtxo, nil
}

func (r *vtxoRepository) findVtxos(ctx context.Context, query *badgerhold.Query) ([]domain.Vtxo, error) {
	vtxos := make([]domain.Vtxo, 0)
	var err error

	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxFind(tx, &vtxos, query)
	} else {
		err = r.store.Find(&vtxos, query)
	}

	return vtxos, err
}

func (r *vtxoRepository) sweepVtxo(ctx context.Context, vtxoKey domain.Outpoint) error {
	vtxo, err := r.getVtxo(ctx, vtxoKey)
	if err != nil {
		return err
	}
	if vtxo.Swept {
		return nil
	}

	vtxo.Swept = true
	return r.updateVtxo(ctx, vtxo)
}

func (r *vtxoRepository) updateVtxo(ctx context.Context, vtxo *domain.Vtxo) error {
	var updateFn func() error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		updateFn = func() error {
			return r.store.TxUpdate(tx, vtxo.Hash(), *vtxo)
		}
	} else {
		updateFn = func() error {
			return r.store.Update(vtxo.Hash(), *vtxo)
		}
	}

	if err := updateFn(); err != nil {
		if errors.Is(err, badger.ErrConflict) {
			attempts := 1
			for errors.Is(err, badger.ErrConflict) && attempts <= maxRetries {
				time.Sleep(100 * time.Millisecond)
				err = updateFn()
				attempts++
			}
		}
		return err
	}
	return nil
}
