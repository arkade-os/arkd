package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/infrastructure/db/sqlite/sqlc/queries"
)

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
		if err := querierWithTx.UpsertVirtualTx(ctx, queries.UpsertVirtualTxParams{
			Txid:              offchainTx.VirtualTxid,
			Tx:                offchainTx.VirtualTx,
			StartingTimestamp: offchainTx.StartingTimestamp,
			EndingTimestamp:   offchainTx.EndingTimestamp,
			ExpiryTimestamp:   offchainTx.ExpiryTimestamp,
			FailReason:        sql.NullString{String: offchainTx.FailReason, Valid: offchainTx.FailReason != ""},
			StageCode:         int64(offchainTx.Stage.Code),
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
				Txid:               checkpointTxid,
				Tx:                 checkpointTx,
				CommitmentTxid:     commitmentTxid,
				IsRootCommitmentTx: isRoot,
				VirtualTxid:        offchainTx.VirtualTxid,
			})
			if err != nil {
				return err
			}
		}
		return nil
	}
	return execTx(ctx, v.db, txBody)
}

func (v *offchainTxRepository) GetOffchainTx(ctx context.Context, txid string) (*domain.OffchainTx, error) {
	rows, err := v.querier.SelectVirtualTxWithTxId(ctx, txid)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("offchain tx %s not found", txid)
	}
	vt := rows[0].VirtualTxCheckpointTxVw
	checkpointTxs := make(map[string]string)
	commitmentTxids := make(map[string]string)
	rootCommitmentTxId := ""
	for _, row := range rows {
		vw := row.VirtualTxCheckpointTxVw
		if vw.CheckpointTxid != "" && vw.CheckpointTx != "" {
			checkpointTxs[vw.CheckpointTxid] = vw.CheckpointTx
			commitmentTxids[vw.CheckpointTxid] = vw.CommitmentTxid
			if vw.IsRootCommitmentTx {
				rootCommitmentTxId = vw.CommitmentTxid
			}
		}
	}
	return &domain.OffchainTx{
		VirtualTxid:        vt.Txid,
		VirtualTx:          vt.Tx,
		StartingTimestamp:  vt.StartingTimestamp,
		EndingTimestamp:    vt.EndingTimestamp,
		ExpiryTimestamp:    vt.ExpiryTimestamp,
		FailReason:         vt.FailReason.String,
		Stage:              domain.Stage{Code: int(vt.StageCode)},
		CheckpointTxs:      checkpointTxs,
		CommitmentTxids:    commitmentTxids,
		RootCommitmentTxId: rootCommitmentTxId,
	}, nil
}

func (v *offchainTxRepository) Close() {
	_ = v.db.Close()
}
