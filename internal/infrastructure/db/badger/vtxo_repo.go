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

const vtxoStoreDir = "vtxos"

type vtxoRepository struct {
	store *badgerhold.Store
}

type vtxoDTO struct {
	domain.Vtxo
	UpdatedAt int64
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
	for outpoint, spentBy := range spentVtxos {
		if err := r.settleVtxo(ctx, outpoint, spentBy, commitmentTxid); err != nil {
			return err
		}
	}
	return nil
}

func (r *vtxoRepository) SpendVtxos(
	ctx context.Context, spentVtxos map[domain.Outpoint]string, arkTxid string,
) error {
	for outpoint, spentBy := range spentVtxos {
		if err := r.spendVtxo(ctx, outpoint, spentBy, arkTxid); err != nil {
			return err
		}
	}
	return nil
}

func (r *vtxoRepository) UnrollVtxos(
	ctx context.Context, outpoints []domain.Outpoint,
) error {
	for _, outpoint := range outpoints {
		_, err := r.unrollVtxo(ctx, outpoint)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *vtxoRepository) GetVtxos(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	vtxos := make([]domain.Vtxo, 0, len(outpoints))
	for _, outpoint := range outpoints {
		vtxo, err := r.getVtxo(ctx, outpoint)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				continue
			}
			return nil, err
		}
		if vtxo == nil {
			return nil, nil
		}
		vtxos = append(vtxos, *vtxo)
	}
	return vtxos, nil
}

func (r *vtxoRepository) GetLeafVtxosForBatch(
	ctx context.Context, txid string,
) ([]domain.Vtxo, error) {
	query := badgerhold.Where("RootCommitmentTxid").Eq(txid).And("Preconfirmed").Eq(false)
	return r.findVtxos(ctx, query)
}

func (r *vtxoRepository) GetAllNonUnrolledVtxos(
	ctx context.Context, pubkey string,
) ([]domain.Vtxo, []domain.Vtxo, error) {
	query := badgerhold.Where("Unrolled").Eq(false)
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

func (r *vtxoRepository) GetAllSweepableUnrolledVtxos(
	ctx context.Context,
) ([]domain.Vtxo, error) {
	query := badgerhold.Where("Unrolled").
		Eq(true).
		And("Swept").
		Eq(false).
		And("SettledBy").
		Eq("").
		And("Spent").
		Eq(true)
	return r.findVtxos(ctx, query)
}

func (r *vtxoRepository) GetAllVtxos(ctx context.Context) ([]domain.Vtxo, error) {
	return r.findVtxos(ctx, &badgerhold.Query{})
}

func (r *vtxoRepository) SweepVtxos(
	ctx context.Context, outpoints []domain.Outpoint,
) (int, error) {
	sweptCount := 0
	for _, outpoint := range outpoints {
		vtxo, err := r.getVtxo(ctx, outpoint)
		if err != nil {
			return -1, err
		}
		if vtxo.Swept {
			continue // Skip already swept vtxos
		}

		// Mark as swept
		vtxo.Swept = true
		if err := r.updateVtxo(ctx, vtxo); err != nil {
			return -1, err
		}
		sweptCount++
	}
	return sweptCount, nil
}

func (r *vtxoRepository) UpdateVtxosExpiration(
	ctx context.Context, vtxos []domain.Outpoint, expiresAt int64,
) error {
	var err error

	for range maxRetries {
		err = func() error {
			tx := r.store.Badger().NewTransaction(true)
			defer tx.Discard()

			for _, outpoint := range vtxos {
				vtxo, err := r.getVtxo(ctx, outpoint)
				if err != nil {
					return err
				}
				if vtxo == nil {
					return nil
				}
				vtxo.ExpiresAt = expiresAt
				dto := vtxoDTO{
					Vtxo:      *vtxo,
					UpdatedAt: time.Now().UnixMilli(),
				}
				if err := r.store.TxUpdate(tx, vtxo.String(), dto); err != nil {
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

func (r *vtxoRepository) GetAllVtxosWithPubKeys(
	ctx context.Context, pubkeys []string, after, before int64,
) ([]domain.Vtxo, error) {
	if after < 0 || before < 0 {
		return nil, fmt.Errorf("after and before must be greater than or equal to 0")
	} else if before > 0 && after > 0 && before <= after {
		return nil, fmt.Errorf("before must be greater than after")
	}
	allVtxos := make([]domain.Vtxo, 0)
	for _, pubkey := range pubkeys {
		query := badgerhold.Where("PubKey").Eq(pubkey).And("UpdatedAt").Ge(after)
		if before > 0 {
			query = query.And("UpdatedAt").Le(before)
		}
		vtxos, err := r.findVtxos(ctx, query)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(vtxos, func(i, j int) bool {
			return vtxos[i].CreatedAt > vtxos[j].CreatedAt
		})

		allVtxos = append(allVtxos, vtxos...)
	}
	return allVtxos, nil
}

func (r *vtxoRepository) GetExpiringLiquidity(
	ctx context.Context, after, before int64,
) (uint64, error) {
	query := badgerhold.Where("Swept").Eq(false).
		And("Spent").Eq(false).
		And("Unrolled").Eq(false).
		And("ExpiresAt").Gt(after)

	if before > 0 {
		query = query.And("ExpiresAt").Lt(before)
	}

	vtxos, err := r.findVtxos(ctx, query)
	if err != nil {
		return 0, err
	}

	var sum uint64
	for _, vtxo := range vtxos {
		sum += vtxo.Amount
	}
	return sum, nil
}

func (r *vtxoRepository) GetRecoverableLiquidity(ctx context.Context) (uint64, error) {
	query := badgerhold.Where("Swept").Eq(true).And("Spent").Eq(false)
	vtxos, err := r.findVtxos(ctx, query)
	if err != nil {
		return 0, err
	}

	var sum uint64
	for _, vtxo := range vtxos {
		sum += vtxo.Amount
	}
	return sum, nil
}

func (r *vtxoRepository) GetVtxoPubKeysByCommitmentTxid(
	ctx context.Context, commitmentTxid string, amountFilter uint64,
) ([]string, error) {
	if commitmentTxid == "" {
		return nil, nil
	}

	// Query vtxos where RootCommitmentTxid matches or CommitmentTxids contains the commitmentTxid
	query1 := badgerhold.Where("RootCommitmentTxid").
		Eq(commitmentTxid).
		And("Amount").
		Ge(amountFilter)
	vtxos1, err := r.findVtxos(ctx, query1)
	if err != nil {
		return nil, err
	}

	query2 := badgerhold.Where("CommitmentTxids").
		Contains(commitmentTxid).
		And("Amount").
		Ge(amountFilter)
	vtxos2, err := r.findVtxos(ctx, query2)
	if err != nil {
		return nil, err
	}

	// Combine and deduplicate by pubkey
	pubkeyMap := make(map[string]bool)
	for _, vtxo := range vtxos1 {
		if vtxo.Amount > amountFilter {
			pubkeyMap[vtxo.PubKey] = true
		}
	}
	for _, vtxo := range vtxos2 {
		if vtxo.Amount > amountFilter {
			pubkeyMap[vtxo.PubKey] = true
		}
	}

	taprootKeys := make([]string, 0, len(pubkeyMap))
	for pubkey := range pubkeyMap {
		taprootKeys = append(taprootKeys, pubkey)
	}

	return taprootKeys, nil
}

func (r *vtxoRepository) GetPendingSpentVtxosWithPubKeys(
	ctx context.Context, pubkeys []string, after, before int64,
) ([]domain.Vtxo, error) {
	if after < 0 || before < 0 {
		return nil, fmt.Errorf("after and before must be greater than or equal to 0")
	} else if before > 0 && after > 0 && before <= after {
		return nil, fmt.Errorf("before must be greater than after")
	}
	indexedPubkeys := make(map[string]struct{})
	for _, pubkey := range pubkeys {
		indexedPubkeys[pubkey] = struct{}{}
	}
	// Get all candidates: vtxos that are spent, not unrolled and not settled, and are within time range
	query := badgerhold.Where("Spent").Eq(true).And("Unrolled").Eq(false).
		And("SettledBy").Eq("").And("ArkTxid").Ne("").And("UpdatedAt").Ge(after)
	if before > 0 {
		query = query.And("UpdatedAt").Le(before)
	}
	candidates, err := r.findVtxos(ctx, query)
	if err != nil {
		return nil, err
	}

	// Filter the candidates by excluding those with non-matching pubkeys and that for which
	// exists in db a vtxo matching their ark txid
	indexedCandidates := make(map[string][]domain.Vtxo)
	for _, vtxo := range candidates {
		if _, ok := indexedPubkeys[vtxo.PubKey]; !ok {
			continue
		}
		indexedCandidates[vtxo.ArkTxid] = append(indexedCandidates[vtxo.ArkTxid], vtxo)
	}

	vtxos := make([]domain.Vtxo, 0)
	for txid, candidates := range indexedCandidates {
		query := badgerhold.Where("Txid").Eq(txid)
		res, err := r.findVtxos(ctx, query)
		if err != nil {
			return nil, err
		}
		if len(res) == 0 {
			vtxos = append(vtxos, candidates...)
		}
	}

	sort.SliceStable(vtxos, func(i, j int) bool {
		return vtxos[i].CreatedAt > vtxos[j].CreatedAt
	})

	return vtxos, nil
}

func (r *vtxoRepository) GetPendingSpentVtxosWithOutpoints(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	// Get all candidates
	indexedCandidates := make(map[string][]domain.Vtxo)
	for _, outpoint := range outpoints {
		vtxo, err := r.getVtxo(ctx, outpoint)
		if err != nil {
			return nil, err
		}
		if vtxo == nil {
			continue
		}
		if !vtxo.Spent || vtxo.Unrolled || vtxo.SettledBy != "" {
			continue
		}
		if vtxo.ArkTxid == "" {
			continue
		}
		indexedCandidates[vtxo.ArkTxid] = append(indexedCandidates[vtxo.ArkTxid], *vtxo)
	}

	// Filter by including only those for which there's no vtxo in db matching their ark txid
	vtxos := make([]domain.Vtxo, 0)
	for txid, candidates := range indexedCandidates {
		query := badgerhold.Where("Txid").Eq(txid)
		res, err := r.findVtxos(ctx, query)
		if err != nil {
			return nil, err
		}
		if len(res) == 0 {
			vtxos = append(vtxos, candidates...)
		}
	}

	sort.SliceStable(vtxos, func(i, j int) bool {
		return vtxos[i].CreatedAt > vtxos[j].CreatedAt
	})

	return vtxos, nil
}

func (r *vtxoRepository) Close() {
	// nolint:all
	r.store.Close()
}

func (r *vtxoRepository) addVtxos(
	ctx context.Context, vtxos []domain.Vtxo,
) error {
	for _, vtxo := range vtxos {
		dto := vtxoDTO{
			Vtxo:      vtxo,
			UpdatedAt: time.Now().UnixMilli(),
		}
		outpoint := vtxo.Outpoint.String()
		var insertFn func() error
		if ctx.Value("tx") != nil {
			tx := ctx.Value("tx").(*badger.Txn)
			insertFn = func() error {
				return r.store.TxInsert(tx, outpoint, dto)
			}
		} else {
			insertFn = func() error {
				return r.store.Insert(outpoint, dto)
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
	ctx context.Context, outpoint domain.Outpoint,
) (*domain.Vtxo, error) {
	var dto vtxoDTO
	var err error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxGet(tx, outpoint.String(), &dto)
	} else {
		err = r.store.Get(outpoint.String(), &dto)
	}
	if err != nil && err == badgerhold.ErrNotFound {
		return nil, nil
	}

	return &dto.Vtxo, nil
}

func (r *vtxoRepository) settleVtxo(
	ctx context.Context, outpoint domain.Outpoint, spentBy, settledBy string,
) error {
	vtxo, err := r.getVtxo(ctx, outpoint)
	if err != nil {
		return err
	}
	if vtxo == nil {
		return nil
	}
	if vtxo.Spent {
		return nil
	}

	vtxo.Spent = true
	vtxo.SpentBy = spentBy
	vtxo.SettledBy = settledBy

	return r.updateVtxo(ctx, vtxo)
}

func (r *vtxoRepository) spendVtxo(
	ctx context.Context, outpoint domain.Outpoint, spentBy, arkTxid string,
) error {
	vtxo, err := r.getVtxo(ctx, outpoint)
	if err != nil {
		return err
	}
	if vtxo == nil {
		return nil
	}
	if vtxo.Spent {
		return nil
	}

	vtxo.Spent = true
	vtxo.SpentBy = spentBy
	vtxo.ArkTxid = arkTxid

	return r.updateVtxo(ctx, vtxo)
}

func (r *vtxoRepository) unrollVtxo(
	ctx context.Context, outpoint domain.Outpoint,
) (*domain.Vtxo, error) {
	vtxo, err := r.getVtxo(ctx, outpoint)
	if err != nil {
		return nil, err
	}
	if vtxo == nil {
		return nil, nil
	}
	if vtxo.Unrolled {
		return nil, nil
	}

	vtxo.Unrolled = true
	vtxo.ExpiresAt = 0
	if err := r.updateVtxo(ctx, vtxo); err != nil {
		return nil, err
	}
	return vtxo, nil
}

func (r *vtxoRepository) findVtxos(
	ctx context.Context, query *badgerhold.Query,
) ([]domain.Vtxo, error) {
	vtxos := make([]domain.Vtxo, 0)
	dtos := make([]vtxoDTO, 0)
	var err error

	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxFind(tx, &dtos, query)
	} else {
		err = r.store.Find(&dtos, query)
	}

	for _, dto := range dtos {
		vtxos = append(vtxos, dto.Vtxo)
	}
	return vtxos, err
}

func (r *vtxoRepository) updateVtxo(ctx context.Context, vtxo *domain.Vtxo) error {
	dto := vtxoDTO{
		Vtxo:      *vtxo,
		UpdatedAt: time.Now().UnixMilli(),
	}
	var updateFn func() error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		updateFn = func() error {
			return r.store.TxUpdate(tx, vtxo.Outpoint.String(), dto)
		}
	} else {
		updateFn = func() error {
			return r.store.Update(vtxo.Outpoint.String(), dto)
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

func (r *vtxoRepository) GetSweepableVtxosByCommitmentTxid(
	ctx context.Context,
	txid string,
) ([]domain.Outpoint, error) {
	visited := make(map[string]bool)
	visitedTxids := make(map[string]bool)
	var outpoints []domain.Outpoint

	queue := []string{txid}

	for len(queue) > 0 {
		currentTxid := queue[0]
		queue = queue[1:]

		if visitedTxids[currentTxid] {
			continue
		}
		visitedTxids[currentTxid] = true

		query := badgerhold.Where("CommitmentTxids").Contains(currentTxid).And("Swept").Eq(false)
		vtxos, err := r.findVtxos(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("failed to find vtxos for txid %s: %w", currentTxid, err)
		}

		for _, vtxo := range vtxos {
			outpointKey := vtxo.Outpoint.String()
			if !visited[outpointKey] {
				if _, seen := visited[outpointKey]; !seen {
					visited[outpointKey] = true
					outpoints = append(outpoints, vtxo.Outpoint)
				}

				if vtxo.ArkTxid != "" {
					queue = append(queue, vtxo.ArkTxid)
				}
			}
		}
	}

	return outpoints, nil
}

func (r *vtxoRepository) GetAllChildrenVtxos(
	ctx context.Context,
	txid string,
) ([]domain.Outpoint, error) {
	visited := make(map[string]bool)
	visitedTxids := make(map[string]bool)
	var outpoints []domain.Outpoint

	queue := []string{txid}

	for len(queue) > 0 {
		currentTxid := queue[0]
		queue = queue[1:]

		if visitedTxids[currentTxid] {
			continue
		}
		visitedTxids[currentTxid] = true

		query := badgerhold.Where("Txid").Eq(currentTxid)
		vtxos, err := r.findVtxos(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("failed to find vtxos for txid %s: %w", currentTxid, err)
		}

		for _, vtxo := range vtxos {
			outpointKey := vtxo.Outpoint.String()
			if !visited[outpointKey] {
				visited[outpointKey] = true
				outpoints = append(outpoints, vtxo.Outpoint)
				if vtxo.ArkTxid != "" {
					queue = append(queue, vtxo.ArkTxid)
				}
			}
		}
	}

	return outpoints, nil
}

func (r *vtxoRepository) GetVtxosUpdatedInTimeRange(
	ctx context.Context, after, before int64,
) ([]domain.Vtxo, error) {
	if after < 0 || before < 0 {
		return nil, fmt.Errorf("after and before must be greater than or equal to 0")
	} else if before > 0 && after > 0 && before <= after {
		return nil, fmt.Errorf("before must be greater than after")
	}
	query := badgerhold.Where("UpdatedAt").Ge(after)
	// only add before condition if it's greater than 0. allows for unbounded before time when before=0
	if before > 0 {
		query = query.And("UpdatedAt").Le(before)
	}
	return r.findVtxos(ctx, query)
}
