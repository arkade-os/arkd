package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const arkStoreDir = "ark"

type arkRepository struct {
	store *badgerhold.Store
}

type ArkRepository interface {
	domain.RoundRepository
	domain.OffchainTxRepository
}

func NewArkRepository(config ...interface{}) (ArkRepository, error) {
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
		dir = filepath.Join(baseDir, arkStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open round events store: %s", err)
	}

	return &arkRepository{store}, nil
}

func (r *arkRepository) AddOrUpdateRound(
	ctx context.Context, round domain.Round,
) error {
	if err := r.addOrUpdateRound(ctx, round); err != nil {
		return err
	}

	return r.addTxs(ctx, round)
}

func (r *arkRepository) GetRoundWithId(
	ctx context.Context, id string,
) (*domain.Round, error) {
	query := badgerhold.Where("Id").Eq(id)
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}
	if len(rounds) <= 0 {
		return nil, fmt.Errorf("round with id %s not found", id)
	}
	round := &rounds[0]
	return round, nil
}

func (r *arkRepository) GetRoundWithCommitmentTxid(
	ctx context.Context, txid string,
) (*domain.Round, error) {
	query := badgerhold.Where("CommitmentTxid").Eq(txid)
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}
	if len(rounds) <= 0 {
		return nil, fmt.Errorf("round with txid %s not found", txid)
	}
	round := &rounds[0]
	return round, nil
}

func (r *arkRepository) GetSweepableRounds(
	ctx context.Context,
) ([]string, error) {
	query := badgerhold.Where("Stage.Code").Eq(domain.RoundFinalizationStage).
		And("Stage.Ended").Eq(true).And("Swept").Eq(false)
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}

	txids := make([]string, 0, len(rounds))
	for _, r := range rounds {
		txids = append(txids, r.CommitmentTxid)
	}
	return txids, nil
}

func (r *arkRepository) GetRoundStats(
	ctx context.Context, commitmentTxid string,
) (*domain.RoundStats, error) {
	// TODO implement
	return nil, nil
}

func (r *arkRepository) GetRoundForfeitTxs(
	ctx context.Context, commitmentTxid string,
) ([]domain.ForfeitTx, error) {
	// TODO implement
	return nil, nil
}

func (r *arkRepository) GetRoundConnectorTree(
	ctx context.Context, commitmentTxid string,
) (tree.FlatTxTree, error) {
	// TODO implement
	return nil, nil
}

func (r *arkRepository) GetSweptRoundsConnectorAddress(
	ctx context.Context,
) ([]string, error) {
	query := badgerhold.Where("Stage.Code").Eq(domain.RoundFinalizationStage).
		And("Stage.Ended").Eq(true).And("Swept").Eq(true).And("ConnectorAddress").Ne("")
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}

	txids := make([]string, 0, len(rounds))
	for _, r := range rounds {
		txids = append(txids, r.CommitmentTxid)
	}
	return txids, nil
}

func (r *arkRepository) GetRoundIds(
	ctx context.Context, startedAfter, startedBefore int64,
) ([]string, error) {
	query := badgerhold.Where("Stage.Ended").Eq(true)

	if startedAfter > 0 {
		query = query.And("StartingTimestamp").Gt(startedAfter)
	}

	if startedBefore > 0 {
		query = query.And("StartingTimestamp").Lt(startedBefore)
	}

	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(rounds))
	for _, round := range rounds {
		ids = append(ids, round.Id)
	}

	return ids, nil
}

func (r *arkRepository) GetRoundVtxoTree(
	ctx context.Context, txid string,
) (tree.FlatTxTree, error) {
	round, err := r.GetRoundWithCommitmentTxid(ctx, txid)
	if err != nil {
		return nil, err
	}
	return round.VtxoTree, nil
}

func (r *arkRepository) GetTxsWithTxids(ctx context.Context, txids []string) ([]string, error) {
	return r.findTxs(ctx, txids)
}

func (r *arkRepository) GetRoundsWithCommitmentTxids(
	ctx context.Context, txids []string,
) (map[string]any, error) {
	query := badgerhold.Where("CommitmentTxid").In(txids)
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}

	resp := make(map[string]any)
	for _, round := range rounds {
		resp[round.CommitmentTxid] = nil
	}
	return resp, nil
}

func (r *arkRepository) AddOrUpdateOffchainTx(
	ctx context.Context, offchainTx *domain.OffchainTx,
) error {
	if err := r.addOrUpdateOffchainTx(ctx, *offchainTx); err != nil {
		return err
	}
	return r.addCheckpointTxs(ctx, *offchainTx)
}

func (r *arkRepository) GetOffchainTx(
	ctx context.Context, txid string,
) (*domain.OffchainTx, error) {
	return r.getOffchainTx(ctx, txid)
}

func (r *arkRepository) Close() {
	// nolint
	r.store.Close()
}

func (r *arkRepository) findRound(
	ctx context.Context, query *badgerhold.Query,
) ([]domain.Round, error) {
	var rounds []domain.Round
	var err error

	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxFind(tx, &rounds, query)
	} else {
		err = r.store.Find(&rounds, query)
	}

	return rounds, err
}

func (r *arkRepository) addOrUpdateRound(
	ctx context.Context, round domain.Round,
) error {
	rnd := domain.Round{
		Id:                 round.Id,
		StartingTimestamp:  round.StartingTimestamp,
		EndingTimestamp:    round.EndingTimestamp,
		Stage:              round.Stage,
		Intents:            round.Intents,
		CommitmentTxid:     round.CommitmentTxid,
		CommitmentTx:       round.CommitmentTx,
		ForfeitTxs:         round.ForfeitTxs,
		VtxoTree:           round.VtxoTree,
		Connectors:         round.Connectors,
		ConnectorAddress:   round.ConnectorAddress,
		Version:            round.Version,
		Swept:              round.Swept,
		VtxoTreeExpiration: round.VtxoTreeExpiration,
		SweepTxs:           round.SweepTxs,
	}
	var upsertFn func() error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		upsertFn = func() error {
			return r.store.TxUpsert(tx, round.Id, rnd)
		}
	} else {
		upsertFn = func() error {
			return r.store.Upsert(round.Id, rnd)
		}
	}
	if err := upsertFn(); err != nil {
		if errors.Is(err, badger.ErrConflict) {
			attempts := 1
			for errors.Is(err, badger.ErrConflict) && attempts <= maxRetries {
				time.Sleep(100 * time.Millisecond)
				err = upsertFn()
				attempts++
			}
		}
		return err
	}
	return nil
}

func (r *arkRepository) addOrUpdateOffchainTx(
	ctx context.Context, offchainTx domain.OffchainTx,
) error {
	var upsertFn func() error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		upsertFn = func() error {
			return r.store.TxUpsert(tx, offchainTx.ArkTxid, offchainTx)
		}
	} else {
		upsertFn = func() error {
			return r.store.Upsert(offchainTx.ArkTxid, offchainTx)
		}
	}
	if err := upsertFn(); err != nil {
		if errors.Is(err, badger.ErrConflict) {
			attempts := 1
			for errors.Is(err, badger.ErrConflict) && attempts <= maxRetries {
				time.Sleep(100 * time.Millisecond)
				err = upsertFn()
				attempts++
			}
		}
		return err
	}
	return nil
}

func (r *arkRepository) getOffchainTx(
	ctx context.Context, txid string,
) (*domain.OffchainTx, error) {
	var offchainTx domain.OffchainTx
	var err error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxGet(tx, txid, &offchainTx)
	} else {
		err = r.store.Get(txid, &offchainTx)
	}
	if err != nil && err == badgerhold.ErrNotFound {
		return nil, fmt.Errorf("offchain tx %s not found", txid)
	}
	if offchainTx.Stage.Code == int(domain.OffchainTxUndefinedStage) {
		return nil, fmt.Errorf("offchain tx %s not found", txid)
	}

	return &offchainTx, nil
}

func (r *arkRepository) addCheckpointTxs(
	ctx context.Context, offchainTx domain.OffchainTx,
) error {
	txs := make(map[string]Tx)
	for txid, tx := range offchainTx.CheckpointTxs {
		txs[txid] = Tx{
			Txid: txid,
			Tx:   tx,
		}
	}

	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		for k, v := range txs {
			if err := r.store.TxUpsert(tx, k, v); err != nil {
				return err
			}
		}
	} else {
		for k, v := range txs {
			if err := r.store.Upsert(k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *arkRepository) findCheckpointTxs(
	ctx context.Context, txids []string,
) ([]string, error) {
	resp := make([]string, 0)
	txs := make([]Tx, 0)

	var ids []interface{}
	for _, s := range txids {
		ids = append(ids, s)
	}
	query := badgerhold.Where(badgerhold.Key).In(ids...)
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		if err := r.store.TxFind(tx, &txs, query); err != nil {
			return nil, err
		}
	} else {
		if err := r.store.Find(&txs, query); err != nil {
			return nil, err
		}
	}

	for _, tx := range txs {
		resp = append(resp, tx.Tx)
	}

	return resp, nil
}

type Tx struct {
	Txid string
	Tx   string
}

func (r *arkRepository) addTxs(
	ctx context.Context, round domain.Round,
) (err error) {
	txs := make(map[string]Tx)
	if len(round.ForfeitTxs) > 0 || len(round.Connectors) > 0 ||
		len(round.VtxoTree) > 0 || len(round.SweepTxs) > 0 {
		for _, tx := range round.ForfeitTxs {
			txs[tx.Txid] = Tx{
				Txid: tx.Txid,
				Tx:   tx.Tx,
			}
		}

		for _, node := range round.Connectors {
			txs[node.Txid] = Tx{
				Txid: node.Txid,
				Tx:   node.Tx,
			}
		}

		for _, node := range round.VtxoTree {
			txs[node.Txid] = Tx{
				Txid: node.Txid,
				Tx:   node.Tx,
			}
		}

		for txid, tx := range round.SweepTxs {
			txs[txid] = Tx{
				Txid: txid,
				Tx:   tx,
			}
		}
	}

	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		for k, v := range txs {
			if err = r.store.TxUpsert(tx, k, v); err != nil {
				return
			}
		}
	} else {
		for k, v := range txs {
			if err = r.store.Upsert(k, v); err != nil {
				return
			}
		}
	}
	return
}

func (r *arkRepository) findTxs(
	ctx context.Context, txids []string,
) ([]string, error) {
	txs, err := r.findRoundTxs(ctx, txids)
	if err != nil {
		return nil, err
	}
	if len(txs) != len(txids) {
		offchainTxs, err := r.findOffchainTxs(ctx, txids)
		if err != nil {
			return nil, err
		}
		txs = append(txs, offchainTxs...)
	}
	return txs, nil
}

func (r *arkRepository) findRoundTxs(
	ctx context.Context, txids []string,
) ([]string, error) {
	resp := make([]string, 0)
	txs := make([]Tx, 0)

	var ids []interface{}
	for _, s := range txids {
		ids = append(ids, s)
	}
	query := badgerhold.Where(badgerhold.Key).In(ids...)
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		if err := r.store.TxFind(tx, &txs, query); err != nil {
			return nil, err
		}
	} else {
		if err := r.store.Find(&txs, query); err != nil {
			return nil, err
		}
	}

	for _, tx := range txs {
		resp = append(resp, tx.Tx)
	}

	return resp, nil
}

func (r arkRepository) findOffchainTxs(ctx context.Context, txids []string) ([]string, error) {
	txs := make([]string, 0, len(txids))
	txsLeftToFetch := make([]string, 0, len(txids))
	for _, txid := range txids {
		tx, err := r.getOffchainTx(ctx, txid)
		if err != nil {
			return nil, err
		}
		if tx != nil {
			txs = append(txs, tx.ArkTx)
			continue
		}
		txsLeftToFetch = append(txsLeftToFetch, txid)
	}
	if len(txsLeftToFetch) > 0 {
		checkpointTxs, err := r.findCheckpointTxs(ctx, txsLeftToFetch)
		if err != nil {
			return nil, err
		}
		txs = append(txs, checkpointTxs...)
	}
	return txs, nil
}
