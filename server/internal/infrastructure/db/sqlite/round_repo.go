package sqlitedb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ark-network/ark/common/tree"
	"github.com/ark-network/ark/server/internal/core/domain"
	"github.com/ark-network/ark/server/internal/infrastructure/db/sqlite/sqlc/queries"
)

type roundRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewRoundRepository(config ...interface{}) (domain.RoundRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open round repository: invalid config, expected db at 0")
	}

	return &roundRepository{
		db:      db,
		querier: queries.New(db),
	}, nil
}

func (r *roundRepository) Close() {
	_ = r.db.Close()
}

func (r *roundRepository) GetRoundsIds(
	ctx context.Context, startedAfter int64, startedBefore int64,
) ([]string, error) {
	var roundIDs []string
	if startedAfter == 0 && startedBefore == 0 {
		ids, err := r.querier.SelectRoundIds(ctx)
		if err != nil {
			return nil, err
		}

		roundIDs = ids
	} else {
		ids, err := r.querier.SelectRoundIdsInRange(
			ctx,
			queries.SelectRoundIdsInRangeParams{
				StartingTimestamp:   startedAfter,
				StartingTimestamp_2: startedBefore,
			},
		)
		if err != nil {
			return nil, err
		}

		roundIDs = ids
	}

	return roundIDs, nil
}

func (r *roundRepository) AddOrUpdateRound(ctx context.Context, round domain.Round) error {
	txBody := func(querierWithTx *queries.Queries) error {
		if err := querierWithTx.UpsertRound(
			ctx,
			queries.UpsertRoundParams{
				ID:                 round.Id,
				StartingTimestamp:  round.StartingTimestamp,
				EndingTimestamp:    round.EndingTimestamp,
				VtxoTreeExpiration: round.VtxoTreeExpiration,
				Ended:              round.Stage.Ended,
				Failed:             round.Stage.Failed,
				StageCode:          int64(round.Stage.Code),
				Txid:               round.Txid,
				ConnectorAddress:   round.ConnectorAddress,
				Version:            int64(round.Version),
				Swept:              round.Swept,
			},
		); err != nil {
			return fmt.Errorf("failed to upsert round: %w", err)
		}

		if len(round.CommitmentTx) > 0 {
			if err := querierWithTx.UpsertTransaction(
				ctx,
				queries.UpsertTransactionParams{
					Tx:      round.CommitmentTx,
					Txid:    round.Txid,
					RoundID: round.Id,
					Type:    "commitment",
				},
			); err != nil {
				return fmt.Errorf("failed to upsert commitment transaction: %w", err)
			}
		}

		if len(round.ForfeitTxs) > 0 || len(round.Connectors) > 0 || len(round.VtxoTree) > 0 {
			for pos, tx := range round.ForfeitTxs {
				if err := querierWithTx.UpsertTransaction(
					ctx,
					queries.UpsertTransactionParams{
						Txid:     tx.Txid,
						Tx:       tx.Tx,
						RoundID:  round.Id,
						Type:     "forfeit",
						Position: int64(pos),
					},
				); err != nil {
					return fmt.Errorf("failed to upsert forfeit transaction: %w", err)
				}
			}

			for i, chunk := range round.Connectors {
				if err := querierWithTx.UpsertTransaction(
					ctx,
					createUpsertTransactionParams(chunk, round.Id, "connector", int64(i)),
				); err != nil {
					return fmt.Errorf("failed to upsert connector transaction: %w", err)
				}
			}

			for i, chunk := range round.VtxoTree {
				if err := querierWithTx.UpsertTransaction(
					ctx,
					createUpsertTransactionParams(chunk, round.Id, "tree", int64(i)),
				); err != nil {
					return fmt.Errorf("failed to upsert tree transaction: %w", err)
				}
			}
		}

		if len(round.TxRequests) > 0 {
			for _, request := range round.TxRequests {
				if err := querierWithTx.UpsertTxRequest(
					ctx,
					queries.UpsertTxRequestParams{
						ID:      request.Id,
						RoundID: round.Id,
					},
				); err != nil {
					return fmt.Errorf("failed to upsert tx request: %w", err)
				}

				for _, receiver := range request.Receivers {
					if err := querierWithTx.UpsertReceiver(
						ctx,
						queries.UpsertReceiverParams{
							RequestID: request.Id,
							Amount:    int64(receiver.Amount),
							Pubkey: sql.NullString{
								String: receiver.PubKey,
								Valid:  len(receiver.PubKey) > 0,
							},
							OnchainAddress: sql.NullString{
								String: receiver.OnchainAddress,
								Valid:  len(receiver.OnchainAddress) > 0,
							},
						},
					); err != nil {
						return fmt.Errorf("failed to upsert receiver: %w", err)
					}
				}

				for _, input := range request.Inputs {
					if err := querierWithTx.UpdateVtxoRequestId(
						ctx,
						queries.UpdateVtxoRequestIdParams{
							RequestID: sql.NullString{
								String: request.Id,
								Valid:  true,
							},
							Txid: input.Txid,
							Vout: int64(input.VOut),
						},
					); err != nil {
						return fmt.Errorf("failed to update vtxo request id: %w", err)
					}
				}
			}
		}

		return nil
	}

	return execTx(ctx, r.db, txBody)
}

func (r *roundRepository) GetRoundWithId(ctx context.Context, id string) (*domain.Round, error) {
	rows, err := r.querier.SelectRoundWithRoundId(ctx, id)
	if err != nil {
		return nil, err
	}

	rvs := make([]combinedRow, 0, len(rows))
	for _, row := range rows {
		rvs = append(rvs, combinedRow{
			round:    row.Round,
			request:  row.RoundRequestVw,
			tx:       row.RoundTxVw,
			receiver: row.RequestReceiverVw,
			vtxo:     row.RequestVtxoVw,
		})
	}

	rounds, err := rowsToRounds(rvs)
	if err != nil {
		return nil, err
	}

	if len(rounds) > 0 {
		return rounds[0], nil
	}

	return nil, errors.New("round not found")
}

func (r *roundRepository) GetRoundWithTxid(ctx context.Context, txid string) (*domain.Round, error) {
	rows, err := r.querier.SelectRoundWithRoundTxId(ctx, txid)
	if err != nil {
		return nil, err
	}

	rvs := make([]combinedRow, 0, len(rows))
	for _, row := range rows {
		rvs = append(rvs, combinedRow{
			round:    row.Round,
			request:  row.RoundRequestVw,
			tx:       row.RoundTxVw,
			receiver: row.RequestReceiverVw,
			vtxo:     row.RequestVtxoVw,
		})
	}

	rounds, err := rowsToRounds(rvs)
	if err != nil {
		return nil, err
	}

	if len(rounds) > 0 {
		return rounds[0], nil
	}

	return nil, errors.New("round not found")
}

func (r *roundRepository) GetRoundStats(ctx context.Context, id string) (*domain.RoundStats, error) {
	rs, err := r.querier.GetRoundStats(ctx, id)
	if err != nil {
		return nil, err
	}

	var totalForfeitAmount uint64
	if rs.TotalForfeitAmount != nil {
		switch v := rs.TotalForfeitAmount.(type) {
		case int64:
			totalForfeitAmount = uint64(v)
		case int:
			totalForfeitAmount = uint64(v)
		}
	}

	var totalInputVtxo int32
	if rs.TotalInputVtxos != nil {
		switch v := rs.TotalInputVtxos.(type) {
		case int64:
			totalInputVtxo = int32(v)
		case int:
			totalInputVtxo = int32(v)
		}
	}

	var totalBatchAmount uint64
	if rs.TotalBatchAmount != nil {
		switch v := rs.TotalBatchAmount.(type) {
		case int64:
			totalBatchAmount = uint64(v)
		case int:
			totalBatchAmount = uint64(v)
		}
	}

	var expiresAt int64
	if rs.ExpiresAt != nil {
		switch v := rs.ExpiresAt.(type) {
		case int64:
			expiresAt = v
		case int:
			expiresAt = int64(v)
		}
	}

	return &domain.RoundStats{
		Swept:              rs.Swept,
		TotalForfeitAmount: totalForfeitAmount,
		TotalInputVtxos:    totalInputVtxo,
		TotalBatchAmount:   totalBatchAmount,
		TotalOutputVtxos:   int32(rs.TotalOutputVtxos),
		ExpiresAt:          expiresAt,
		Started:            rs.StartingTimestamp,
		Ended:              rs.EndingTimestamp,
	}, nil
}

func (r *roundRepository) GetRoundForfeitTxs(ctx context.Context, roundTxid string) ([]domain.ForfeitTx, error) {
	rows, err := r.querier.GetRoundForfeitTxs(ctx, roundTxid)
	if err != nil {
		return nil, err
	}

	forfeits := make([]domain.ForfeitTx, 0, len(rows))
	for _, row := range rows {
		forfeits = append(forfeits, domain.ForfeitTx{
			Txid: row.Txid.String,
			Tx:   row.Tx.String,
		})
	}

	return forfeits, nil
}

func (r *roundRepository) GetRoundConnectorTree(ctx context.Context, roundTxid string) ([]tree.TxGraphChunk, error) {
	rows, err := r.querier.GetRoundConnectorTreeTxs(ctx, roundTxid)
	if err != nil {
		return nil, err
	}

	chunks := make([]tree.TxGraphChunk, 0, len(rows))

	for _, row := range rows {
		pos := int(row.Position.Int64)
		chunks = extendArray(chunks, pos)
		children := make(map[uint32]string)
		if row.Children.Valid {
			if err := json.Unmarshal([]byte(row.Children.String), &children); err != nil {
				return nil, err
			}
		}
		chunks[pos] = tree.TxGraphChunk{
			Txid:     row.Txid.String,
			Tx:       row.Tx.String,
			Children: children,
		}
	}

	return chunks, nil
}

func (r *roundRepository) GetUnsweptRoundsTxid(ctx context.Context) ([]string, error) {
	return r.querier.SelectUnsweptRoundsTxid(ctx)
}

func (r *roundRepository) GetSweptRoundsConnectorAddress(ctx context.Context) ([]string, error) {
	return r.querier.SelectSweptRoundsConnectorAddress(ctx)
}

func (r *roundRepository) GetVtxoTreeWithTxid(ctx context.Context, txid string) ([]tree.TxGraphChunk, error) {
	rows, err := r.querier.SelectTreeTxsWithRoundTxid(ctx, txid)
	if err != nil {
		return nil, err
	}

	chunks := make([]tree.TxGraphChunk, 0)

	for _, row := range rows {
		pos := int(row.Position.Int64)
		chunks = extendArray(chunks, pos)
		children := make(map[uint32]string)
		if row.Children.Valid {
			if err := json.Unmarshal([]byte(row.Children.String), &children); err != nil {
				return nil, err
			}
		}
		chunks[pos] = tree.TxGraphChunk{
			Txid:     row.Txid.String,
			Tx:       row.Tx.String,
			Children: children,
		}
	}

	return chunks, nil
}

func (r *roundRepository) GetTxsWithTxids(ctx context.Context, txids []string) ([]string, error) {
	rows, err := r.querier.GetTxsByTxid(ctx, queries.GetTxsByTxidParams{
		Ids1: txids,
		Ids2: txids,
	})
	if err != nil {
		return nil, err
	}

	resp := make([]string, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, row.Data)
	}

	return resp, nil
}

func (r *roundRepository) GetExistingRounds(ctx context.Context, txids []string) (map[string]any, error) {
	rows, err := r.querier.GetExistingRounds(ctx, txids)
	if err != nil {
		return nil, err
	}

	resp := make(map[string]any)
	for _, row := range rows {
		resp[row] = nil
	}
	return resp, nil
}

func rowToReceiver(row queries.RequestReceiverVw) domain.Receiver {
	return domain.Receiver{
		Amount:         uint64(row.Amount.Int64),
		PubKey:         row.Pubkey.String,
		OnchainAddress: row.OnchainAddress.String,
	}
}

type combinedRow struct {
	round    queries.Round
	request  queries.RoundRequestVw
	tx       queries.RoundTxVw
	receiver queries.RequestReceiverVw
	vtxo     queries.RequestVtxoVw
}

func rowsToRounds(rows []combinedRow) ([]*domain.Round, error) {
	rounds := make(map[string]*domain.Round)

	for _, v := range rows {
		var round *domain.Round
		var ok bool

		round, ok = rounds[v.round.ID]
		if !ok {
			round = &domain.Round{
				Id:                v.round.ID,
				StartingTimestamp: v.round.StartingTimestamp,
				EndingTimestamp:   v.round.EndingTimestamp,
				Stage: domain.Stage{
					Ended:  v.round.Ended,
					Failed: v.round.Failed,
					Code:   int(v.round.StageCode),
				},
				Txid:               v.round.Txid,
				ConnectorAddress:   v.round.ConnectorAddress,
				Version:            uint(v.round.Version),
				Swept:              v.round.Swept,
				TxRequests:         make(map[string]domain.TxRequest),
				VtxoTreeExpiration: v.round.VtxoTreeExpiration,
			}
		}

		if v.request.ID.Valid {
			request, ok := round.TxRequests[v.request.ID.String]
			if !ok {
				request = domain.TxRequest{
					Id:        v.request.ID.String,
					Inputs:    make([]domain.Vtxo, 0),
					Receivers: make([]domain.Receiver, 0),
				}
				round.TxRequests[v.request.ID.String] = request
			}

			if v.vtxo.RequestID.Valid {
				request, ok = round.TxRequests[v.vtxo.RequestID.String]
				if !ok {
					request = domain.TxRequest{
						Id:        v.vtxo.RequestID.String,
						Inputs:    make([]domain.Vtxo, 0),
						Receivers: make([]domain.Receiver, 0),
					}
				}

				vtxo := combinedRowToVtxo(v.vtxo)
				found := false
				for _, v := range request.Inputs {
					if vtxo.Txid == v.Txid && vtxo.VOut == v.VOut {
						found = true
						break
					}
				}

				if !found {
					request.Inputs = append(request.Inputs, combinedRowToVtxo(v.vtxo))
					round.TxRequests[v.vtxo.RequestID.String] = request
				}
			}

			if v.receiver.RequestID.Valid {
				request, ok = round.TxRequests[v.receiver.RequestID.String]
				if !ok {
					request = domain.TxRequest{
						Id:        v.receiver.RequestID.String,
						Inputs:    make([]domain.Vtxo, 0),
						Receivers: make([]domain.Receiver, 0),
					}
				}

				rcv := rowToReceiver(v.receiver)

				found := false
				for _, rcv := range request.Receivers {
					if (v.receiver.Pubkey.Valid || v.receiver.OnchainAddress.Valid) && v.receiver.Amount.Valid {
						if rcv.PubKey == v.receiver.Pubkey.String && rcv.OnchainAddress == v.receiver.OnchainAddress.String && int64(rcv.Amount) == v.receiver.Amount.Int64 {
							found = true
							break
						}
					}
				}
				if !found {
					request.Receivers = append(request.Receivers, rcv)
					round.TxRequests[v.receiver.RequestID.String] = request
				}
			}
		}

		if v.tx.Tx.Valid && v.tx.Type.Valid && v.tx.Position.Valid {
			position := v.tx.Position
			pos := int(position.Int64)
			switch v.tx.Type.String {
			case "commitment":
				round.CommitmentTx = v.tx.Tx.String
			case "forfeit":
				round.ForfeitTxs = extendArray(round.ForfeitTxs, pos)
				round.ForfeitTxs[pos] = domain.ForfeitTx{
					Txid: v.tx.Txid.String,
					Tx:   v.tx.Tx.String,
				}
			case "connector":
				round.Connectors = extendArray(round.Connectors, pos)

				children := make(map[uint32]string)
				if v.tx.Children.Valid {
					if err := json.Unmarshal([]byte(v.tx.Children.String), &children); err != nil {
						return nil, err
					}
				}

				round.Connectors[pos] = tree.TxGraphChunk{
					Txid:     v.tx.Txid.String,
					Tx:       v.tx.Tx.String,
					Children: children,
				}
			case "tree":
				round.VtxoTree = extendArray(round.VtxoTree, pos)

				children := make(map[uint32]string)
				if v.tx.Children.Valid {
					if err := json.Unmarshal([]byte(v.tx.Children.String), &children); err != nil {
						return nil, err
					}
				}

				round.VtxoTree[pos] = tree.TxGraphChunk{
					Txid:     v.tx.Txid.String,
					Tx:       v.tx.Tx.String,
					Children: children,
				}
			}
		}

		rounds[v.round.ID] = round
	}

	var result []*domain.Round

	for _, round := range rounds {
		result = append(result, round)
	}

	return result, nil
}

func combinedRowToVtxo(row queries.RequestVtxoVw) domain.Vtxo {
	var commitmentTxids []string
	if commitments, ok := row.Commitments.(string); ok && commitments != "" {
		commitmentTxids = strings.Split(commitments, ",")
	}
	return domain.Vtxo{
		VtxoKey: domain.VtxoKey{
			Txid: row.Txid.String,
			VOut: uint32(row.Vout.Int64),
		},
		Amount:             uint64(row.Amount.Int64),
		PubKey:             row.Pubkey.String,
		RootCommitmentTxid: row.RoundTx.String,
		CommitmentTxids:    commitmentTxids,
		SpentBy:            row.SpentBy.String,
		Spent:              row.Spent.Bool,
		Redeemed:           row.Redeemed.Bool,
		Swept:              row.Swept.Bool,
		ExpireAt:           row.ExpireAt.Int64,
	}
}

func createUpsertTransactionParams(graphChunk tree.TxGraphChunk, roundID string, txType string, position int64) queries.UpsertTransactionParams {
	params := queries.UpsertTransactionParams{
		Tx:       graphChunk.Tx,
		RoundID:  roundID,
		Type:     txType,
		Position: position,
		Txid:     graphChunk.Txid,
	}

	if txType == "tree" || txType == "connector" {
		str, _ := json.Marshal(graphChunk.Children)
		params.Children = sql.NullString{
			String: string(str),
			Valid:  true,
		}
	}

	return params
}
