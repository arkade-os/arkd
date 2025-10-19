package pgdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/postgres/sqlc/queries"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/sqlc-dev/pqtype"
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

func (r *roundRepository) GetRoundIds(
	ctx context.Context, startedAfter, startedBefore int64, withFailed, withCompleted bool,
) ([]string, error) {
	var roundIDs []string
	if startedAfter == 0 && startedBefore == 0 {
		// Use filtering query when no time range is specified
		ids, err := r.querier.SelectRoundIdsWithFilters(
			ctx,
			queries.SelectRoundIdsWithFiltersParams{
				WithFailed:    withFailed,
				WithCompleted: withCompleted,
			},
		)
		if err != nil {
			return nil, err
		}

		roundIDs = ids
	} else {
		// Use time range filtering query
		ids, err := r.querier.SelectRoundIdsInTimeRangeWithFilters(
			ctx,
			queries.SelectRoundIdsInTimeRangeWithFiltersParams{
				StartTs:       startedAfter,
				EndTs:         startedBefore,
				WithFailed:    withFailed,
				WithCompleted: withCompleted,
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
				StageCode:          int32(round.Stage.Code),
				ConnectorAddress:   round.ConnectorAddress,
				Version:            int32(round.Version),
				Swept:              round.Swept,
				FailReason: sql.NullString{
					String: round.FailReason, Valid: len(round.FailReason) > 0,
				},
			},
		); err != nil {
			return fmt.Errorf("failed to upsert round: %w", err)
		}

		if len(round.CommitmentTx) > 0 && len(round.CommitmentTxid) > 0 {
			if err := querierWithTx.UpsertTx(
				ctx,
				queries.UpsertTxParams{
					Tx:      round.CommitmentTx,
					Txid:    round.CommitmentTxid,
					RoundID: round.Id,
					Type:    "commitment",
				},
			); err != nil {
				return fmt.Errorf("failed to upsert commitment transaction: %w", err)
			}
		}

		if len(round.ForfeitTxs) > 0 || len(round.Connectors) > 0 ||
			len(round.VtxoTree) > 0 || len(round.SweepTxs) > 0 {
			for pos, tx := range round.ForfeitTxs {
				if err := querierWithTx.UpsertTx(
					ctx,
					queries.UpsertTxParams{
						Txid:     tx.Txid,
						Tx:       tx.Tx,
						RoundID:  round.Id,
						Type:     "forfeit",
						Position: int32(pos),
					},
				); err != nil {
					return fmt.Errorf("failed to upsert forfeit transaction: %w", err)
				}
			}

			for position, node := range round.Connectors {
				if err := querierWithTx.UpsertTx(
					ctx,
					createUpsertTransactionParams(node, round.Id, "connector", int64(position)),
				); err != nil {
					return fmt.Errorf("failed to upsert connector transaction: %w", err)
				}
			}

			for position, node := range round.VtxoTree {
				if err := querierWithTx.UpsertTx(
					ctx,
					createUpsertTransactionParams(node, round.Id, "tree", int64(position)),
				); err != nil {
					return fmt.Errorf("failed to upsert tree transaction: %w", err)
				}
			}

			for txid, tx := range round.SweepTxs {
				if err := querierWithTx.UpsertTx(
					ctx,
					queries.UpsertTxParams{
						Txid:    txid,
						Tx:      tx,
						RoundID: round.Id,
						Type:    "sweep",
					},
				); err != nil {
					return fmt.Errorf("failed to upsert sweep transaction: %w", err)
				}
			}
		}

		if len(round.Intents) > 0 {
			for _, intent := range round.Intents {
				if err := querierWithTx.UpsertIntent(
					ctx,
					queries.UpsertIntentParams{
						ID:      sql.NullString{String: intent.Id, Valid: true},
						RoundID: sql.NullString{String: round.Id, Valid: true},
						Proof:   sql.NullString{String: intent.Proof, Valid: true},
						Message: sql.NullString{String: intent.Message, Valid: true},
					},
				); err != nil {
					return fmt.Errorf("failed to upsert intent: %w", err)
				}

				for _, receiver := range intent.Receivers {
					if err := querierWithTx.UpsertReceiver(
						ctx,
						queries.UpsertReceiverParams{
							IntentID:       intent.Id,
							Amount:         int64(receiver.Amount),
							Pubkey:         receiver.PubKey,
							OnchainAddress: receiver.OnchainAddress,
						},
					); err != nil {
						return fmt.Errorf("failed to upsert receiver: %w", err)
					}
				}

				for _, input := range intent.Inputs {
					if err := querierWithTx.UpdateVtxoIntentId(
						ctx,
						queries.UpdateVtxoIntentIdParams{
							IntentID: sql.NullString{String: intent.Id, Valid: true},
							Txid:     input.Txid,
							Vout:     int32(input.VOut),
						},
					); err != nil {
						return fmt.Errorf("failed to update vtxo intent id: %w", err)
					}
				}
			}
		}

		return nil
	}

	return execTx(ctx, r.db, txBody)
}

func (r *roundRepository) GetRoundWithId(ctx context.Context, id string) (*domain.Round, error) {
	rows, err := r.querier.SelectRoundWithId(ctx, id)
	if err != nil {
		return nil, err
	}

	rvs := make([]combinedRow, 0, len(rows))
	for _, row := range rows {
		rvs = append(rvs, combinedRow{
			round:    row.Round,
			intent:   row.RoundIntentsVw,
			tx:       row.RoundTxsVw,
			receiver: row.IntentWithReceiversVw,
			vtxo:     row.IntentWithInputsVw,
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

func (r *roundRepository) GetRoundWithCommitmentTxid(
	ctx context.Context, txid string,
) (*domain.Round, error) {
	rows, err := r.querier.SelectRoundWithTxid(ctx, txid)
	if err != nil {
		return nil, err
	}

	rvs := make([]combinedRow, 0, len(rows))
	for _, row := range rows {
		rvs = append(rvs, combinedRow{
			round:    row.Round,
			intent:   row.RoundIntentsVw,
			tx:       row.RoundTxsVw,
			receiver: row.IntentWithReceiversVw,
			vtxo:     row.IntentWithInputsVw,
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

func (r *roundRepository) GetRoundStats(
	ctx context.Context, id string,
) (*domain.RoundStats, error) {
	rs, err := r.querier.SelectRoundStats(ctx, id)
	if err != nil {
		return nil, err
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
		TotalForfeitAmount: uint64(rs.TotalForfeitAmount),
		TotalInputVtxos:    int32(rs.TotalInputVtxos),
		TotalBatchAmount:   uint64(rs.TotalBatchAmount),
		TotalOutputVtxos:   int32(rs.TotalOutputVtxos),
		ExpiresAt:          expiresAt,
		Started:            rs.StartingTimestamp,
		Ended:              rs.EndingTimestamp,
	}, nil
}

func (r *roundRepository) GetSweepableRounds(ctx context.Context) ([]string, error) {
	return r.querier.SelectSweepableRounds(ctx)
}

func (r *roundRepository) GetRoundForfeitTxs(
	ctx context.Context, commitmentTxid string,
) ([]domain.ForfeitTx, error) {
	rows, err := r.querier.SelectRoundForfeitTxs(ctx, commitmentTxid)
	if err != nil {
		return nil, err
	}

	forfeits := make([]domain.ForfeitTx, 0, len(rows))
	for _, row := range rows {
		forfeits = append(forfeits, domain.ForfeitTx{
			Txid: row.Txid,
			Tx:   row.Tx,
		})
	}

	return forfeits, nil
}

func (r *roundRepository) GetRoundConnectorTree(
	ctx context.Context, commitmentTxid string,
) (tree.FlatTxTree, error) {
	rows, err := r.querier.SelectRoundConnectors(ctx, commitmentTxid)
	if err != nil {
		return nil, err
	}

	nodes := make(tree.FlatTxTree, 0)

	for _, tx := range rows {
		pos := int(tx.Position)
		nodes = extendArray(nodes, pos)

		nodes[pos] = tree.TxTreeNode{
			Txid: tx.Txid,
			Tx:   tx.Tx,
		}
		if tx.Children.Valid {
			children := make(map[uint32]string)
			if err := json.Unmarshal(tx.Children.RawMessage, &children); err != nil {
				return nil, fmt.Errorf("failed to unmarshal children: %w", err)
			}
			nodes[pos].Children = children
		}
	}

	return nodes, nil
}

func (r *roundRepository) GetSweptRoundsConnectorAddress(ctx context.Context) ([]string, error) {
	return r.querier.SelectSweptRoundsConnectorAddress(ctx)
}

func (r *roundRepository) GetRoundVtxoTree(
	ctx context.Context, txid string,
) (tree.FlatTxTree, error) {
	rows, err := r.querier.SelectRoundVtxoTree(ctx, txid)
	if err != nil {
		return nil, err
	}

	nodes := make(tree.FlatTxTree, 0)

	for _, tx := range rows {
		pos := int(tx.Position)
		nodes = extendArray(nodes, pos)

		nodes[pos] = tree.TxTreeNode{
			Txid: tx.Txid,
			Tx:   tx.Tx,
		}
		if tx.Children.Valid {
			children := make(map[uint32]string)
			if err := json.Unmarshal(tx.Children.RawMessage, &children); err != nil {
				return nil, fmt.Errorf("failed to unmarshal children: %w", err)
			}
			nodes[pos].Children = children
		}

	}

	return nodes, nil
}

func (r *roundRepository) GetTxsWithTxids(ctx context.Context, txids []string) ([]string, error) {
	rows, err := r.querier.SelectTxs(ctx, txids)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	resp := make([]string, 0, len(rows))
	for _, row := range rows {
		resp = append(resp, row.Data)
	}

	return resp, nil
}

func (r *roundRepository) GetRoundsWithCommitmentTxids(
	ctx context.Context, txids []string,
) (map[string]any, error) {
	txids, err := r.querier.SelectRoundsWithTxids(ctx, txids)
	if err != nil {
		return nil, err
	}

	resp := make(map[string]any)
	for _, txid := range txids {
		resp[txid] = nil
	}
	return resp, nil
}

func rowToReceiver(row queries.IntentWithReceiversVw) domain.Receiver {
	return domain.Receiver{
		Amount:         uint64(row.Amount.Int64),
		PubKey:         row.Pubkey.String,
		OnchainAddress: row.OnchainAddress.String,
	}
}

type combinedRow struct {
	round    queries.Round
	intent   queries.RoundIntentsVw
	tx       queries.RoundTxsVw
	receiver queries.IntentWithReceiversVw
	vtxo     queries.IntentWithInputsVw
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
				ConnectorAddress:   v.round.ConnectorAddress,
				Version:            uint(v.round.Version),
				Swept:              v.round.Swept,
				Intents:            make(map[string]domain.Intent),
				VtxoTreeExpiration: v.round.VtxoTreeExpiration,
				FailReason:         v.round.FailReason.String,
			}
		}

		if v.intent.ID.Valid {
			intent, ok := round.Intents[v.intent.ID.String]
			if !ok {
				intent = domain.Intent{
					Id:        v.intent.ID.String,
					Proof:     v.intent.Proof.String,
					Message:   v.intent.Message.String,
					Inputs:    make([]domain.Vtxo, 0),
					Receivers: make([]domain.Receiver, 0),
				}
				round.Intents[v.intent.ID.String] = intent
			}

			if v.vtxo.IntentID.Valid {
				intent, ok = round.Intents[v.vtxo.IntentID.String]
				if !ok {
					intent = domain.Intent{
						Id:        v.vtxo.IntentID.String,
						Proof:     v.vtxo.Proof.String,
						Message:   v.vtxo.Message.String,
						Inputs:    make([]domain.Vtxo, 0),
						Receivers: make([]domain.Receiver, 0),
					}
				}

				vtxo := combinedRowToVtxo(v.vtxo)
				found := false
				for _, v := range intent.Inputs {
					if vtxo.Txid == v.Txid && vtxo.VOut == v.VOut {
						found = true
						break
					}
				}

				if !found {
					intent.Inputs = append(intent.Inputs, combinedRowToVtxo(v.vtxo))
					round.Intents[v.vtxo.IntentID.String] = intent
				}
			}

			if v.receiver.IntentID.Valid {
				intent, ok = round.Intents[v.receiver.IntentID.String]
				if !ok {
					intent = domain.Intent{
						Id:        v.receiver.IntentID.String,
						Proof:     v.receiver.Proof.String,
						Message:   v.receiver.Message.String,
						Inputs:    make([]domain.Vtxo, 0),
						Receivers: make([]domain.Receiver, 0),
					}
				}

				rcv := rowToReceiver(v.receiver)

				found := false
				for _, rcv := range intent.Receivers {
					if (v.receiver.Pubkey.Valid || v.receiver.OnchainAddress.Valid) &&
						v.receiver.Amount.Valid {
						if rcv.PubKey == v.receiver.Pubkey.String &&
							rcv.OnchainAddress == v.receiver.OnchainAddress.String &&
							int64(rcv.Amount) == v.receiver.Amount.Int64 {
							found = true
							break
						}
					}
				}
				if !found {
					intent.Receivers = append(intent.Receivers, rcv)
					round.Intents[v.receiver.IntentID.String] = intent
				}
			}
		}

		if v.tx.Tx.Valid && v.tx.Type.Valid && v.tx.Position.Valid {
			position := v.tx.Position
			switch v.tx.Type.String {
			case "commitment":
				round.CommitmentTxid = v.tx.Txid.String
				round.CommitmentTx = v.tx.Tx.String
			case "forfeit":
				round.ForfeitTxs = extendArray(round.ForfeitTxs, int(position.Int32))
				round.ForfeitTxs[position.Int32] = domain.ForfeitTx{
					Txid: v.tx.Txid.String,
					Tx:   v.tx.Tx.String,
				}
			case "connector":
				round.Connectors = extendArray(round.Connectors, int(position.Int32))

				round.Connectors[int(position.Int32)] = tree.TxTreeNode{
					Txid: v.tx.Txid.String,
					Tx:   v.tx.Tx.String,
				}
				if v.tx.Children.Valid {
					children := make(map[uint32]string)
					if err := json.Unmarshal(v.tx.Children.RawMessage, &children); err != nil {
						return nil, fmt.Errorf("failed to unmarshal children: %w", err)
					}
					round.Connectors[int(position.Int32)].Children = children
				}

			case "tree":
				round.VtxoTree = extendArray(round.VtxoTree, int(position.Int32))

				round.VtxoTree[int(position.Int32)] = tree.TxTreeNode{
					Txid: v.tx.Txid.String,
					Tx:   v.tx.Tx.String,
				}
				if v.tx.Children.Valid {
					children := make(map[uint32]string)
					if err := json.Unmarshal(v.tx.Children.RawMessage, &children); err != nil {
						return nil, fmt.Errorf("failed to unmarshal children: %w", err)
					}
					round.VtxoTree[int(position.Int32)].Children = children
				}
			case "sweep":
				if len(round.SweepTxs) <= 0 {
					round.SweepTxs = make(map[string]string)
				}
				round.SweepTxs[v.tx.Txid.String] = v.tx.Tx.String
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

func combinedRowToVtxo(row queries.IntentWithInputsVw) domain.Vtxo {
	return domain.Vtxo{
		Outpoint: domain.Outpoint{
			Txid: row.Txid.String,
			VOut: uint32(row.Vout.Int32),
		},
		Amount:             uint64(row.Amount.Int64),
		PubKey:             row.Pubkey.String,
		RootCommitmentTxid: row.CommitmentTxid.String,
		CommitmentTxids:    parseCommitments(row.Commitments, []byte(",")),
		SpentBy:            row.SpentBy.String,
		Spent:              row.Spent.Bool,
		Unrolled:           row.Unrolled.Bool,
		Swept:              row.Swept.Bool,
		Preconfirmed:       row.Preconfirmed.Bool,
		ExpiresAt:          row.ExpiresAt.Int64,
		CreatedAt:          row.CreatedAt.Int64,
		ArkTxid:            row.ArkTxid.String,
		SettledBy:          row.SettledBy.String,
	}
}

func createUpsertTransactionParams(
	node tree.TxTreeNode, roundID string, txType string, position int64,
) queries.UpsertTxParams {
	params := queries.UpsertTxParams{
		Tx:       node.Tx,
		RoundID:  roundID,
		Type:     txType,
		Position: int32(position),
	}

	if txType == "connector" || txType == "tree" {
		params.Txid = node.Txid
		if len(node.Children) > 0 {
			// nolint
			children, _ := json.Marshal(node.Children)
			params.Children = pqtype.NullRawMessage{
				RawMessage: children,
				Valid:      true,
			}
		}
	}

	return params
}
