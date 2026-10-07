package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const utxoStoreDir = "utxos"

type utxoRepository struct {
	store    *badgerhold.Store
	arkStore *badgerhold.Store
}

func NewUtxoRepository(config ...interface{}) (domain.UtxoRepository, error) {
	if len(config) != 2 && len(config) != 3 {
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
	var arkStore *badgerhold.Store
	if len(config) == 3 && config[2] != nil {
		arkStore, ok = config[2].(*badgerhold.Store)
		if !ok {
			return nil, fmt.Errorf("invalid ark store")
		}
	}

	var dir string
	if len(baseDir) > 0 {
		dir = filepath.Join(baseDir, utxoStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open utxo store: %s", err)
	}

	return &utxoRepository{store: store, arkStore: arkStore}, nil
}

// AddUtxos ignores the spending tx: this store doesn't keep onchain txs.
func (r *utxoRepository) AddUtxos(
	ctx context.Context, utxos []domain.Utxo, _ string,
) error {
	return r.addUtxos(ctx, utxos)
}

func (r *utxoRepository) GetUtxos(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Utxo, error) {
	utxos := make([]domain.Utxo, 0, len(outpoints))
	for _, outpoint := range outpoints {
		utxo, err := r.getUtxo(ctx, outpoint)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				continue
			}
			return nil, err
		}
		if utxo == nil {
			continue
		}
		utxos = append(utxos, *utxo)
	}
	return utxos, nil
}

// GetUtxosWithPubKeys filters and pages in memory like the vtxo store does. Pointers to
// unrolled vtxos carry no pubkey of their own, so they are never matched here: the sql
// stores resolve it from the vtxo, this store is not expected to.
func (r *utxoRepository) GetUtxosWithPubKeys(
	ctx context.Context, pubkeys []string, page domain.Page,
) ([]domain.Utxo, int32, error) {
	keys := make([]interface{}, 0, len(pubkeys))
	for _, pubkey := range pubkeys {
		keys = append(keys, pubkey)
	}
	query := badgerhold.Where("PubKey").In(keys...)
	matched, err := r.findUtxos(ctx, query)
	if err != nil {
		return nil, 0, err
	}

	sort.SliceStable(matched, func(i, j int) bool {
		if matched[i].CreatedAt != matched[j].CreatedAt {
			return matched[i].CreatedAt > matched[j].CreatedAt
		}
		if matched[i].Txid != matched[j].Txid {
			return matched[i].Txid < matched[j].Txid
		}
		return matched[i].VOut < matched[j].VOut
	})

	// Clamp like the sql stores do: a page past the end is empty, not a panic,
	// and a non positive limit reads everything from the offset on.
	total := int32(len(matched))
	offset := max(page.Offset, 0)
	if offset >= total {
		return nil, total, nil
	}
	end := total
	if page.Limit > 0 {
		end = min(offset+page.Limit, total)
	}

	return matched[offset:end], total, nil
}

func (r *utxoRepository) GetUnconfirmedUtxos(ctx context.Context) ([]domain.Utxo, error) {
	query := badgerhold.Where("Spend.ConfirmedAtTime").Eq(0)
	return r.findUtxos(ctx, query)
}

func (r *utxoRepository) UpdateUtxos(ctx context.Context, utxos []domain.Utxo) error {
	var err error

	for range maxRetries {
		err = func() error {
			tx := r.store.Badger().NewTransaction(true)
			defer tx.Discard()

			for _, utxo := range utxos {
				if utxo.Spend.ConfirmedAtTime == 0 || utxo.Spend.ConfirmedAtHeight == 0 {
					return fmt.Errorf(
						"utxo %s has invalid confirmation info (time: %d, height: %d)",
						utxo.Outpoint, utxo.Spend.ConfirmedAtTime, utxo.Spend.ConfirmedAtHeight,
					)
				}
				if err := r.store.TxUpdate(tx, utxo.String(), utxo); err != nil {
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

func (r *utxoRepository) GetOnchainTxs(ctx context.Context, txids []string) ([]string, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *utxoRepository) Close() {
	// nolint:all
	r.store.Close()
}

func (r *utxoRepository) addUtxos(
	ctx context.Context, utxos []domain.Utxo,
) error {
	for _, utxo := range utxos {
		outpoint := utxo.String()
		var insertFn func() error
		if ctx.Value("tx") != nil {
			tx := ctx.Value("tx").(*badger.Txn)
			insertFn = func() error {
				return r.store.TxInsert(tx, outpoint, utxo)
			}
		} else {
			insertFn = func() error {
				return r.store.Insert(outpoint, utxo)
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

func (r *utxoRepository) findUtxos(
	ctx context.Context, query *badgerhold.Query,
) ([]domain.Utxo, error) {
	utxos := make([]domain.Utxo, 0)
	var err error

	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxFind(tx, &utxos, query)
	} else {
		err = r.store.Find(&utxos, query)
	}
	return utxos, err
}

func (r *utxoRepository) getUtxo(
	ctx context.Context, outpoint domain.Outpoint,
) (*domain.Utxo, error) {
	var utxo domain.Utxo
	var err error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxGet(tx, outpoint.String(), &utxo)
	} else {
		err = r.store.Get(outpoint.String(), &utxo)
	}
	if err != nil {
		if err == badgerhold.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	return &utxo, nil
}
