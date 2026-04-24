package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
)

// sqliteMaxBulkTxids caps the per-query batch for GetOffchainTxsByTxids to stay
// well under SQLITE_MAX_VARIABLE_NUMBER (default 999 on SQLite < 3.32). The
// SLICE expansion in the generated query emits one bound parameter per txid.
const sqliteMaxBulkTxids = 500

type offchainTxRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewOffchainTxRepository(config ...interface{}) (domain.OffchainTxRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open offchain tx repository: invalid config")
	}

	return &offchainTxRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (v *offchainTxRepository) AddOrUpdateOffchainTx(
	ctx context.Context, offchainTx *domain.OffchainTx,
) error {
	txBody := func(querierWithTx *queries.Queries) error {
		if err := querierWithTx.UpsertOffchainTx(ctx, queries.UpsertOffchainTxParams{
			Txid:              offchainTx.ArkTxid,
			Tx:                offchainTx.ArkTx,
			StartingTimestamp: offchainTx.StartingTimestamp,
			EndingTimestamp:   offchainTx.EndingTimestamp,
			ExpiryTimestamp:   offchainTx.ExpiryTimestamp,
			StageCode:         int64(offchainTx.Stage.Code),
			FailReason: sql.NullString{
				String: offchainTx.FailReason, Valid: offchainTx.FailReason != "",
			},
		}); err != nil {
			return err
		}

		for checkpointTxid, commitmentTxid := range offchainTx.CommitmentTxids {
			checkpointTx, ok := offchainTx.CheckpointTxs[checkpointTxid]
			if !ok {
				continue
			}
			isRoot := commitmentTxid == offchainTx.RootCommitmentTxId
			err := querierWithTx.UpsertCheckpointTx(ctx, queries.UpsertCheckpointTxParams{
				Txid:                 checkpointTxid,
				Tx:                   checkpointTx,
				CommitmentTxid:       commitmentTxid,
				IsRootCommitmentTxid: isRoot,
				OffchainTxid:         offchainTx.ArkTxid,
			})
			if err != nil {
				return err
			}
		}
		return nil
	}
	return execTx(ctx, v.db, txBody)
}

func (v *offchainTxRepository) GetOffchainTx(
	ctx context.Context, txid string,
) (*domain.OffchainTx, error) {
	rows, err := v.querier.SelectOffchainTx(ctx, txid)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("offchain tx %s not found", txid)
	}
	vt := rows[0].OffchainTxVw
	checkpointTxs := make(map[string]string)
	commitmentTxids := make(map[string]string)
	rootCommitmentTxId := ""
	for _, row := range rows {
		vw := row.OffchainTxVw
		if vw.CheckpointTxid != "" && vw.CheckpointTx != "" {
			checkpointTxs[vw.CheckpointTxid] = vw.CheckpointTx
			commitmentTxids[vw.CheckpointTxid] = vw.CommitmentTxid.String
			if vw.IsRootCommitmentTxid.Bool {
				rootCommitmentTxId = vw.CommitmentTxid.String
			}
		}
	}
	stage := domain.Stage{Code: int(vt.StageCode)}
	if vt.FailReason.String != "" {
		stage.Failed = true
	}
	if domain.OffchainTxStage(vt.StageCode) == domain.OffchainTxFinalizedStage {
		stage.Ended = true
	}
	return &domain.OffchainTx{
		ArkTxid:            vt.Txid,
		ArkTx:              vt.Tx,
		StartingTimestamp:  vt.StartingTimestamp,
		EndingTimestamp:    vt.EndingTimestamp,
		ExpiryTimestamp:    vt.ExpiryTimestamp,
		FailReason:         vt.FailReason.String,
		Stage:              stage,
		CheckpointTxs:      checkpointTxs,
		CommitmentTxids:    commitmentTxids,
		RootCommitmentTxId: rootCommitmentTxId,
	}, nil
}

func (v *offchainTxRepository) GetOffchainTxsByTxids(
	ctx context.Context, txids []string,
) ([]*domain.OffchainTx, error) {
	if len(txids) == 0 {
		return []*domain.OffchainTx{}, nil
	}

	grouped := make(map[string][]queries.OffchainTxVw)
	for start := 0; start < len(txids); start += sqliteMaxBulkTxids {
		end := min(start+sqliteMaxBulkTxids, len(txids))
		rows, err := v.querier.SelectOffchainTxsByTxids(ctx, txids[start:end])
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			grouped[row.OffchainTxVw.Txid] = append(
				grouped[row.OffchainTxVw.Txid],
				row.OffchainTxVw,
			)
		}
	}

	txs := make([]*domain.OffchainTx, 0, len(grouped))
	for _, vws := range grouped {
		vt := vws[0]
		checkpointTxs := make(map[string]string)
		commitmentTxids := make(map[string]string)
		rootCommitmentTxId := ""
		for _, vw := range vws {
			if vw.CheckpointTxid != "" && vw.CheckpointTx != "" {
				checkpointTxs[vw.CheckpointTxid] = vw.CheckpointTx
				commitmentTxids[vw.CheckpointTxid] = vw.CommitmentTxid.String
				if vw.IsRootCommitmentTxid.Bool {
					rootCommitmentTxId = vw.CommitmentTxid.String
				}
			}
		}
		stage := domain.Stage{Code: int(vt.StageCode)}
		if vt.FailReason.String != "" {
			stage.Failed = true
		}
		if domain.OffchainTxStage(vt.StageCode) == domain.OffchainTxFinalizedStage {
			stage.Ended = true
		}
		txs = append(txs, &domain.OffchainTx{
			ArkTxid:            vt.Txid,
			ArkTx:              vt.Tx,
			StartingTimestamp:  vt.StartingTimestamp,
			EndingTimestamp:    vt.EndingTimestamp,
			ExpiryTimestamp:    vt.ExpiryTimestamp,
			FailReason:         vt.FailReason.String,
			Stage:              stage,
			CheckpointTxs:      checkpointTxs,
			CommitmentTxids:    commitmentTxids,
			RootCommitmentTxId: rootCommitmentTxId,
		})
	}

	return txs, nil
}

func (v *offchainTxRepository) Close() {
	_ = v.db.Close()
}
