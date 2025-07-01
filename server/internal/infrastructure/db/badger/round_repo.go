package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const roundStoreDir = "rounds"

type roundRepository struct {
	store *badgerhold.Store
}

func NewRoundRepository(config ...interface{}) (domain.RoundRepository, error) {
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
		dir = filepath.Join(baseDir, roundStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open round events store: %s", err)
	}

	return &roundRepository{store}, nil
}

func (r *roundRepository) AddOrUpdateRound(
	ctx context.Context, round domain.Round,
) error {
	if err := r.addOrUpdateRound(ctx, round); err != nil {
		return err
	}

	return r.addTxs(ctx, round)
}

func (r *roundRepository) GetRoundWithId(
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

func (r *roundRepository) GetRoundWithTxid(
	ctx context.Context, txid string,
) (*domain.Round, error) {
	query := badgerhold.Where("Txid").Eq(txid)
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

func (r *roundRepository) GetUnsweptRoundsTxid(
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
		txids = append(txids, r.Txid)
	}
	return txids, nil
}

func (r *roundRepository) GetRoundStats(ctx context.Context, roundTxid string) (*domain.RoundStats, error) {
	// TODO implement
	return nil, nil
}

func (r *roundRepository) GetRoundForfeitTxs(ctx context.Context, roundTxid string) ([]domain.ForfeitTx, error) {
	// TODO implement
	return nil, nil
}

func (r *roundRepository) GetRoundConnectorTree(ctx context.Context, roundTxid string) ([]tree.TxGraphChunk, error) {
	// TODO implement
	return nil, nil
}

func (r *roundRepository) GetSweptRoundsConnectorAddress(
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
		txids = append(txids, r.Txid)
	}
	return txids, nil
}

func (r *roundRepository) GetRoundsIds(ctx context.Context, startedAfter int64, startedBefore int64) ([]string, error) {
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

func (r *roundRepository) GetVtxoTreeWithTxid(
	ctx context.Context, txid string,
) ([]tree.TxGraphChunk, error) {
	round, err := r.GetRoundWithTxid(ctx, txid)
	if err != nil {
		return nil, err
	}
	return round.VtxoTree, nil
}

func (r *roundRepository) Close() {
	// nolint:all
	r.store.Close()
}

func (r *roundRepository) GetTxsWithTxids(ctx context.Context, txids []string) ([]string, error) {
	return r.findTxs(ctx, txids)
}

func (r *roundRepository) GetExistingRounds(ctx context.Context, txids []string) (map[string]any, error) {
	query := badgerhold.Where("Txid").In(txids)
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}

	resp := make(map[string]any)
	for _, round := range rounds {
		resp[round.Txid] = nil
	}
	return resp, nil
}

func (r *roundRepository) findRound(
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

func (r *roundRepository) addOrUpdateRound(
	ctx context.Context, round domain.Round,
) error {
	rnd := domain.Round{
		Id:                 round.Id,
		StartingTimestamp:  round.StartingTimestamp,
		EndingTimestamp:    round.EndingTimestamp,
		Stage:              round.Stage,
		TxRequests:         round.TxRequests,
		Txid:               round.Txid,
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

type Tx struct {
	Txid string
	Tx   string
}

func (r *roundRepository) addTxs(
	ctx context.Context, round domain.Round,
) (err error) {
	txs := make(map[string]Tx)
	if len(round.ForfeitTxs) > 0 || len(round.Connectors) > 0 || len(round.VtxoTree) > 0 || len(round.SweepTxs) > 0 {
		for _, tx := range round.ForfeitTxs {
			txs[tx.Txid] = Tx{
				Txid: tx.Txid,
				Tx:   tx.Tx,
			}
		}

		for _, chunk := range round.Connectors {
			txs[chunk.Txid] = Tx{
				Txid: chunk.Txid,
				Tx:   chunk.Tx,
			}
		}

		for _, chunk := range round.VtxoTree {
			txs[chunk.Txid] = Tx{
				Txid: chunk.Txid,
				Tx:   chunk.Tx,
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

func (r *roundRepository) findTxs(
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
