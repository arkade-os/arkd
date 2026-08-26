package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	arkerrors "github.com/arkade-os/arkd/pkg/errors"
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
	Store() *badgerhold.Store
}

type IntentIndex struct {
	Txid     string
	RoundId  string
	IntentId string
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
		return nil, arkerrors.ROUND_NOT_FOUND.
			New("round with id %s not found", id).
			WithMetadata(arkerrors.RoundNotFoundMetadata{RoundId: id})
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
		return nil, arkerrors.ROUND_NOT_FOUND.
			New("round with commitment txid %s not found", txid).
			WithMetadata(arkerrors.RoundNotFoundMetadata{RoundId: txid})
	}
	round := &rounds[0]
	return round, nil
}

func (r *arkRepository) GetSweepableRounds(
	ctx context.Context,
) ([]string, error) {
	query := badgerhold.Where("Stage.Code").Eq(int(domain.RoundFinalizationStage)).
		And("Stage.Ended").Eq(true).And("Swept").Eq(false)
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}

	txids := make([]string, 0, len(rounds))
	for _, r := range rounds {
		if len(r.VtxoTree) > 0 {
			txids = append(txids, r.CommitmentTxid)
		}
	}
	return txids, nil
}

func (r *arkRepository) GetScheduledSweeps(
	ctx context.Context, limit int64,
) ([]domain.ScheduledSweep, error) {
	query := badgerhold.Where("Stage.Code").Eq(int(domain.RoundFinalizationStage)).
		And("Stage.Ended").Eq(true).And("Swept").Eq(false)
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}

	sweeps := make([]domain.ScheduledSweep, 0, len(rounds))
	for _, round := range rounds {
		// skip non-sweepable rounds (no vtxo tree)
		if len(round.VtxoTree) == 0 {
			continue
		}
		// ExpiryTimestamp returns -1 for failed/not-ended rounds.
		sweepAt := round.ExpiryTimestamp()
		if sweepAt <= 0 {
			continue
		}
		sweeps = append(sweeps, domain.ScheduledSweep{
			RoundId:        round.Id,
			CommitmentTxid: round.CommitmentTxid,
			SweepAt:        sweepAt,
			TotalAmount:    0,
			VtxoCount:      0,
		})
	}

	sort.Slice(sweeps, func(i, j int) bool { return sweeps[i].SweepAt < sweeps[j].SweepAt })
	if limit > 0 && int64(len(sweeps)) > limit {
		sweeps = sweeps[:limit]
	}
	return sweeps, nil
}

func (r *arkRepository) SumCollectedFees(
	ctx context.Context, after, before int64,
) (uint64, error) {
	rounds, err := r.findRound(ctx, r.finalizedRoundsInRange(after, before))
	if err != nil {
		return 0, err
	}

	var total uint64
	for _, round := range rounds {
		total += round.CollectedFees
	}
	return total, nil
}

// finalizedRoundsInRange matches ended, non-failed rounds started in the given
// window; 0 means unbounded on either side.
func (r *arkRepository) finalizedRoundsInRange(after, before int64) *badgerhold.Query {
	query := badgerhold.Where("Stage.Ended").Eq(true).And("Stage.Failed").Eq(false)
	if after > 0 {
		query = query.And("StartingTimestamp").Gt(after)
	}
	if before > 0 {
		query = query.And("StartingTimestamp").Lt(before)
	}
	return query
}

func (r *arkRepository) GetExpiredRounds(
	ctx context.Context, expiredBefore int64,
) ([]domain.ExpiredRound, error) {
	query := badgerhold.Where("Stage.Code").Eq(int(domain.RoundFinalizationStage)).
		And("Stage.Ended").Eq(true).And("Swept").Eq(false)
	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}

	expiredRounds := make([]domain.ExpiredRound, 0, len(rounds))
	for _, round := range rounds {
		// skip non-sweepable rounds (no vtxo tree)
		if len(round.VtxoTree) == 0 {
			continue
		}
		// ExpiryTimestamp returns -1 for failed/not-ended rounds.
		expiredAt := round.ExpiryTimestamp()
		if expiredAt <= 0 || expiredAt >= expiredBefore {
			continue
		}
		expiredRounds = append(expiredRounds, domain.ExpiredRound{
			RoundId:        round.Id,
			CommitmentTxid: round.CommitmentTxid,
			ExpiredAt:      expiredAt,
		})
	}
	return expiredRounds, nil
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

func (r *arkRepository) GetSweepTxs(
	ctx context.Context, commitmentTxid string,
) (map[string]string, error) {
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

func (r *arkRepository) GetRoundSummaries(
	ctx context.Context, startedAfter, startedBefore int64,
	withFailed, withCompleted, onlyFailed bool, limit int64,
) ([]domain.RoundSummary, error) {
	query := badgerhold.Where("Id").Ne("")

	if startedAfter > 0 {
		query = query.And("StartingTimestamp").Gt(startedAfter)
	}
	if startedBefore > 0 {
		query = query.And("StartingTimestamp").Lt(startedBefore)
	}
	// Same order as the SQL predicates: only_failed narrows on top of the two
	// include filters, it does not replace them.
	if onlyFailed {
		withFailed = true
	}
	if !withFailed {
		query = query.And("Stage.Failed").Eq(false)
	}
	if !withCompleted {
		query = query.And("Stage.Ended").Eq(false)
	}
	if onlyFailed {
		query = query.And("Stage.Failed").Eq(true)
	}

	query = query.SortBy("StartingTimestamp").Reverse()
	if limit > 0 {
		query = query.Limit(int(limit))
	}

	rounds, err := r.findRound(ctx, query)
	if err != nil {
		return nil, err
	}

	summaries := make([]domain.RoundSummary, 0, len(rounds))
	for i := range rounds {
		round := rounds[i]
		summaries = append(summaries, domain.RoundSummary{
			RoundId:        round.Id,
			CommitmentTxid: round.CommitmentTxid,
			StartedAt:      round.StartingTimestamp,
			EndedAt:        round.EndingTimestamp,
			Stage:          domain.RoundStage(round.Stage.Code).String(),
			Ended:          round.IsEnded(),
			Failed:         round.IsFailed(),
			Swept:          round.Swept,
			FailReason:     round.FailReason,
			TotalIntents:   int64(len(round.Intents)),
		})
	}
	return summaries, nil
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

func (r *arkRepository) GetOffchainTxs(
	ctx context.Context, filter domain.OffchainTxFilter,
) ([]*domain.OffchainTx, error) {
	if err := filter.Validate(); err != nil {
		return nil, err
	}

	// NOTE: badgerhold has no per-field ordering or LIMIT push-down, so
	// this call reads every offchain_tx row into memory before any
	// predicate runs. Acceptable for the small-scale dev/test setups
	// that use the badger backend; production deployments should use
	// the SQL backends, which push the LIMIT to the DB engine.
	var all []domain.OffchainTx
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		if err := r.store.TxFind(tx, &all, nil); err != nil {
			return nil, err
		}
	} else {
		if err := r.store.Find(&all, nil); err != nil {
			return nil, err
		}
	}

	wantTxids := make(map[string]struct{}, len(filter.WithTxids))
	for _, t := range filter.WithTxids {
		wantTxids[t] = struct{}{}
	}

	out := make([]*domain.OffchainTx, 0)
	for i := range all {
		off := all[i]
		// Mirror the SQL backends' `stage_code = 2 OR stage_code = 3`.
		// Requested txs stay hidden so a submission that failed before
		// acceptance can be retried, while accepted and finalized txs stay
		// visible even once failed, so duplicate detection in
		// SubmitOffchainTx and the lookup in FinalizeOffchainTx still find
		// them. Skipping on IsFailed() here instead would hide those
		// accepted-then-failed txs from both.
		if off.Stage.Code != int(domain.OffchainTxAcceptedStage) &&
			off.Stage.Code != int(domain.OffchainTxFinalizedStage) {
			continue
		}
		if len(wantTxids) > 0 {
			if _, ok := wantTxids[off.ArkTxid]; !ok {
				continue
			}
		}
		if (filter.WithExtension || len(filter.WithPacket) > 0 || len(filter.WithPacketContains) > 0) &&
			len(off.Packets) == 0 {
			continue
		}
		if filter.WithAfterDate > 0 && off.StartingTimestamp < filter.WithAfterDate {
			continue
		}
		if filter.WithBeforeDate > 0 && off.StartingTimestamp > filter.WithBeforeDate {
			continue
		}
		offCopy := off
		match, err := filter.MatchPackets(&offCopy)
		if err != nil {
			return nil, err
		}
		if !match {
			continue
		}
		out = append(out, &offCopy)
	}

	// Match the SQL backends' ORDER BY starting_timestamp DESC, txid ASC
	// so the same filter yields the same row order regardless of
	// storage backend (important for client-side after=lastSeen
	// pagination).
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartingTimestamp != out[j].StartingTimestamp {
			return out[i].StartingTimestamp > out[j].StartingTimestamp
		}
		return out[i].ArkTxid < out[j].ArkTxid
	})

	// Apply the unconstrained-scan cap after sorting so the visible
	// page is deterministic for any caller paginating in Go.
	if len(wantTxids) == 0 && len(out) > domain.OffchainTxsScanLimit {
		out = out[:domain.OffchainTxsScanLimit]
	}
	return out, nil
}

// GetAnyOffchainTx is the same as GetOffchainTx: badger stores the whole aggregate, so
// the lookup never filtered by stage in the first place.
func (r *arkRepository) GetAnyOffchainTx(
	ctx context.Context, txid string,
) (*domain.OffchainTx, error) {
	return r.getOffchainTx(ctx, txid)
}

func (r *arkRepository) GetOffchainTxsInRange(
	ctx context.Context, after, before int64, onlyFailed, onlyCompleted bool, limit int64,
) ([]*domain.OffchainTx, error) {
	query := badgerhold.Where("ArkTxid").Ne("")

	if after > 0 {
		query = query.And("StartingTimestamp").Gt(after)
	}
	if before > 0 {
		query = query.And("StartingTimestamp").Lt(before)
	}
	if onlyFailed {
		query = query.And("Stage.Failed").Eq(true)
	}
	// Mirrors OffchainTx.IsFinalized, and the stage_code predicate the SQL repos use.
	if onlyCompleted {
		query = query.And("Stage.Code").Eq(int(domain.OffchainTxFinalizedStage)).
			And("Stage.Failed").Eq(false)
	}

	query = query.SortBy("StartingTimestamp").Reverse()
	if limit > 0 {
		query = query.Limit(int(limit))
	}

	var offchainTxs []domain.OffchainTx
	var err error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxFind(tx, &offchainTxs, query)
	} else {
		err = r.store.Find(&offchainTxs, query)
	}
	if err != nil {
		return nil, err
	}

	txs := make([]*domain.OffchainTx, 0, len(offchainTxs))
	for i := range offchainTxs {
		txs = append(txs, &offchainTxs[i])
	}
	return txs, nil
}

// isOffchainTxNotFound reports whether err is the structured not-found error
// getOffchainTx returns for a missing row.
func isOffchainTxNotFound(err error) bool {
	var structured arkerrors.Error
	if !errors.As(err, &structured) {
		return false
	}
	return structured.Code() == arkerrors.OFFCHAIN_TX_NOT_FOUND.Code
}

func (r *arkRepository) GetOffchainTxsByTxids(
	ctx context.Context, txids []string,
) ([]*domain.OffchainTx, error) {
	if len(txids) == 0 {
		return []*domain.OffchainTx{}, nil
	}

	txs := make([]*domain.OffchainTx, 0, len(txids))
	for _, txid := range txids {
		tx, err := r.getOffchainTx(ctx, txid)
		if err != nil {
			// A bulk fetch skips txids it cannot find rather than failing the
			// whole call. getOffchainTx reports a missing row as the structured
			// OFFCHAIN_TX_NOT_FOUND, which does not wrap badgerhold.ErrNotFound,
			// so match on the code as well.
			if errors.Is(err, badgerhold.ErrNotFound) || isOffchainTxNotFound(err) {
				continue
			}
			return nil, err
		}
		txs = append(txs, tx)
	}

	return txs, nil
}

func (r *arkRepository) Close() {
	// nolint:all
	r.store.Close()
}

func (r *arkRepository) Store() *badgerhold.Store {
	return r.store
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
		CollectedFees:      round.CollectedFees,
		FailReason:         round.FailReason,
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
	// upsert intent indexes for each intent
	for _, it := range rnd.Intents {
		// do not fail the whole round upsert if intent index upsert fails
		// nolint:errcheck
		r.upsertIntentIndex(ctx, it.Txid, rnd.Id, it.Id)
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
		return nil, arkerrors.OFFCHAIN_TX_NOT_FOUND.
			New("offchain tx %s not found", txid).
			WithMetadata(arkerrors.OffchainTxNotFoundMetadata{Txid: txid})
	}
	if offchainTx.Stage.Code == int(domain.OffchainTxUndefinedStage) {
		return nil, arkerrors.OFFCHAIN_TX_NOT_FOUND.
			New("offchain tx %s not found", txid).
			WithMetadata(arkerrors.OffchainTxNotFoundMetadata{Txid: txid})
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

func (r arkRepository) GetIntentByTxid(ctx context.Context, txid string) (*domain.Intent, error) {
	var idx IntentIndex
	var err error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxGet(tx, txid, &idx)
	} else {
		err = r.store.Get(txid, &idx)
	}
	if err != nil {
		if err == badgerhold.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	round, err := r.GetRoundWithId(ctx, idx.RoundId)
	if err != nil {
		return nil, err
	}

	for _, in := range round.Intents {
		if in.Id == idx.IntentId {
			return &in, nil
		}
	}

	return nil, nil
}

func (r *arkRepository) upsertIntentIndex(
	ctx context.Context,
	txid, roundId, intentId string,
) error {
	idx := IntentIndex{Txid: txid, RoundId: roundId, IntentId: intentId}
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		return r.store.TxUpsert(tx, txid, idx)
	}
	return r.store.Upsert(txid, idx)
}
