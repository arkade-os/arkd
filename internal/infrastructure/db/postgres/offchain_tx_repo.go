package pgdb

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/postgres/sqlc/queries"
	arkerrors "github.com/arkade-os/arkd/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type offchainTxRepository struct {
	db             *sql.DB
	querier        *queries.Queries
	backfillCancel context.CancelFunc
	backfillDone   chan struct{}
}

func NewOffchainTxRepository(config ...interface{}) (domain.OffchainTxRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("cannot open offchain tx repository: invalid config")
	}

	backfillCtx, cancel := context.WithCancel(context.Background())
	repo := &offchainTxRepository{
		db:             db,
		querier:        queries.New(db),
		backfillCancel: cancel,
		backfillDone:   make(chan struct{}),
	}
	repo.startBackfill(backfillCtx)
	return repo, nil
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
			StageCode:         int32(offchainTx.Stage.Code),
			FailReason: sql.NullString{
				String: offchainTx.FailReason, Valid: offchainTx.FailReason != "",
			},
			Packets: encodePacketsColumn(offchainTx.Packets),
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

func (v *offchainTxRepository) GetOffchainTxs(
	ctx context.Context, filter domain.OffchainTxFilter,
) ([]*domain.OffchainTx, error) {
	if err := filter.Validate(); err != nil {
		return nil, err
	}

	type vwRow struct {
		OffchainTxVw queries.OffchainTxVw
	}

	var rows []vwRow
	if len(filter.WithTxids) > 0 {
		raw, err := v.querier.SelectFilteredOffchainTxsByTxids(
			ctx,
			queries.SelectFilteredOffchainTxsByTxidsParams{
				Txids: filter.WithTxids,
				WithExtension: filter.WithExtension || len(filter.WithPacket) > 0 ||
					len(filter.WithPacketContains) > 0,
				WithAfter:  filter.WithAfterDate > 0,
				AfterTs:    filter.WithAfterDate,
				WithBefore: filter.WithBeforeDate > 0,
				BeforeTs:   filter.WithBeforeDate,
				// A caller-supplied txid list does not bound the result: in
				// withheld/private mode an empty request is backfilled from the
				// auth token's whitelist, which comes from an unbounded vtxo
				// chain walk. No batching is needed here because the txids go
				// over as one array parameter rather than one placeholder each,
				// so a single capped query is both bounded and correctly
				// ordered.
				Lim: int32(domain.OffchainTxsScanLimit),
			},
		)
		if err != nil {
			return nil, err
		}
		rows = make([]vwRow, 0, len(raw))
		for _, r := range raw {
			rows = append(rows, vwRow{OffchainTxVw: r.OffchainTxVw})
		}
	} else {
		raw, err := v.querier.SelectOffchainTxs(ctx, queries.SelectOffchainTxsParams{
			WithExtension: filter.WithExtension || len(filter.WithPacket) > 0 ||
				len(filter.WithPacketContains) > 0,
			WithAfter:  filter.WithAfterDate > 0,
			AfterTs:    filter.WithAfterDate,
			WithBefore: filter.WithBeforeDate > 0,
			BeforeTs:   filter.WithBeforeDate,
			Lim:        int32(domain.OffchainTxsScanLimit),
		})
		if err != nil {
			return nil, err
		}
		rows = make([]vwRow, 0, len(raw))
		for _, r := range raw {
			rows = append(rows, vwRow{OffchainTxVw: r.OffchainTxVw})
		}
	}

	byTxid := make(map[string]*domain.OffchainTx)
	order := make([]string, 0)
	for _, row := range rows {
		vw := row.OffchainTxVw
		off, ok := byTxid[vw.Txid]
		if !ok {
			stage := domain.Stage{Code: int(vw.StageCode)}
			if vw.FailReason.String != "" {
				stage.Failed = true
			}
			if domain.OffchainTxStage(vw.StageCode) == domain.OffchainTxFinalizedStage {
				stage.Ended = true
			}
			off = &domain.OffchainTx{
				ArkTxid:            vw.Txid,
				ArkTx:              vw.Tx,
				StartingTimestamp:  vw.StartingTimestamp,
				EndingTimestamp:    vw.EndingTimestamp,
				ExpiryTimestamp:    vw.ExpiryTimestamp,
				FailReason:         vw.FailReason.String,
				Stage:              stage,
				CheckpointTxs:      make(map[string]string),
				CommitmentTxids:    make(map[string]string),
				RootCommitmentTxId: "",
				Packets:            decodePacketsColumn(vw.Packets),
			}
			byTxid[vw.Txid] = off
			order = append(order, vw.Txid)
		}
		if vw.CheckpointTxid.Valid && vw.CheckpointTx.Valid {
			off.CheckpointTxs[vw.CheckpointTxid.String] = vw.CheckpointTx.String
			off.CommitmentTxids[vw.CheckpointTxid.String] = vw.CommitmentTxid.String
			if vw.IsRootCommitmentTxid.Valid && vw.IsRootCommitmentTxid.Bool {
				off.RootCommitmentTxId = vw.CommitmentTxid.String
			}
		}
	}

	out := make([]*domain.OffchainTx, 0, len(order))
	for _, txid := range order {
		off := byTxid[txid]
		match, err := filter.MatchPackets(off)
		if err != nil {
			return nil, err
		}
		if !match {
			continue
		}
		out = append(out, off)
	}
	return out, nil
}

func (v *offchainTxRepository) GetOffchainTxsByTxids(
	ctx context.Context, txids []string,
) ([]*domain.OffchainTx, error) {
	if len(txids) == 0 {
		return []*domain.OffchainTx{}, nil
	}

	rows, err := v.querier.SelectOffchainTxsByTxids(ctx, txids)
	if err != nil {
		return nil, err
	}

	grouped := make(map[string][]queries.OffchainTxVw)
	for _, row := range rows {
		grouped[row.OffchainTxVw.Txid] = append(grouped[row.OffchainTxVw.Txid], row.OffchainTxVw)
	}

	txs := make([]*domain.OffchainTx, 0, len(grouped))
	for _, vws := range grouped {
		vt := vws[0]
		checkpointTxs := make(map[string]string)
		commitmentTxids := make(map[string]string)
		rootCommitmentTxId := ""
		for _, vw := range vws {
			if vw.CheckpointTxid.Valid && vw.CheckpointTx.Valid {
				checkpointTxs[vw.CheckpointTxid.String] = vw.CheckpointTx.String
				commitmentTxids[vw.CheckpointTxid.String] = vw.CommitmentTxid.String
				if vw.IsRootCommitmentTxid.Valid && vw.IsRootCommitmentTxid.Bool {
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

func (v *offchainTxRepository) GetAnyOffchainTx(
	ctx context.Context, txid string,
) (*domain.OffchainTx, error) {
	rows, err := v.querier.SelectAnyOffchainTx(ctx, txid)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, arkerrors.OFFCHAIN_TX_NOT_FOUND.
			New("offchain tx %s not found", txid).
			WithMetadata(arkerrors.OffchainTxNotFoundMetadata{Txid: txid})
	}
	vws := make([]queries.OffchainTxVw, 0, len(rows))
	for _, row := range rows {
		vws = append(vws, row.OffchainTxVw)
	}
	return rowsToOffchainTx(vws), nil
}

func (v *offchainTxRepository) GetOffchainTxsInRange(
	ctx context.Context, after, before int64, onlyFailed, onlyCompleted bool, limit int64,
) ([]*domain.OffchainTx, error) {
	rows, err := v.querier.SelectOffchainTxsInRange(ctx, queries.SelectOffchainTxsInRangeParams{
		After:          after,
		Before:         before,
		OnlyFailed:     onlyFailed,
		OnlyCompleted:  onlyCompleted,
		FinalizedStage: int32(domain.OffchainTxFinalizedStage),
		MaxResults:     limit,
	})
	if err != nil {
		return nil, err
	}

	// The LIMIT is applied by the ordered subquery, but the outer IN (...) does not
	// preserve its order; callers sort the result.
	grouped := make(map[string][]queries.OffchainTxVw)
	for _, row := range rows {
		grouped[row.OffchainTxVw.Txid] = append(grouped[row.OffchainTxVw.Txid], row.OffchainTxVw)
	}

	txs := make([]*domain.OffchainTx, 0, len(grouped))
	for _, vws := range grouped {
		txs = append(txs, rowsToOffchainTx(vws))
	}
	return txs, nil
}

// rowsToOffchainTx folds the offchain_tx_vw rows of a single offchain tx (one row per
// checkpoint tx) into the domain aggregate.
func rowsToOffchainTx(vws []queries.OffchainTxVw) *domain.OffchainTx {
	vt := vws[0]
	checkpointTxs := make(map[string]string)
	commitmentTxids := make(map[string]string)
	rootCommitmentTxId := ""
	for _, vw := range vws {
		if vw.CheckpointTxid.Valid && vw.CheckpointTx.Valid {
			checkpointTxs[vw.CheckpointTxid.String] = vw.CheckpointTx.String
			commitmentTxids[vw.CheckpointTxid.String] = vw.CommitmentTxid.String
			if vw.IsRootCommitmentTxid.Valid && vw.IsRootCommitmentTxid.Bool {
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
	}
}

func (v *offchainTxRepository) Close() {
	if v.backfillCancel != nil {
		v.backfillCancel()
	}
	if v.backfillDone != nil {
		<-v.backfillDone
	}
	_ = v.db.Close()
}

// backfillBatchSize controls how many rows the background backfill
// reads + updates per loop iteration. Small enough to keep transactions
// short, large enough to amortize the round-trip on a cold cache.
const backfillBatchSize = 500

// startBackfill kicks the offchain_tx.packets backfill off in a
// goroutine so process startup is not blocked. The backfill keyset-
// paginates over rows with NULL packets, decodes each PSBT, and writes
// either the parsed list or the empty string (for rows whose PSBT
// cannot be decoded, so they are not revisited on every restart). The
// goroutine signals completion on backfillDone so Close can wait for
// it before tearing down the DB.
//
// Consistency window: packet filters require a non-empty packets
// column, so while this is still running a filtered GetOffchainTxs can
// omit older rows that do carry packets. We accept that rather than
// blocking startup or falling back to per-row PSBT decoding, because it
// is bounded to the first run against a pre-existing DB and unfiltered
// txid lookups are unaffected. The window is documented on
// GetVirtualTxsRequest.filter for clients.
func (v *offchainTxRepository) startBackfill(ctx context.Context) {
	go func() {
		defer close(v.backfillDone)
		if err := BackfillPackets(ctx, v.db); err != nil {
			log.WithError(err).
				Error("offchain_tx.packets backfill stopped before completion")
		}
	}()
}

// BackfillPackets populates the offchain_tx.packets column for any rows
// where it is still NULL. It is exposed so tests can drive the
// migration synchronously; production callers go through startBackfill.
func BackfillPackets(ctx context.Context, db *sql.DB) error {
	querier := queries.New(db)
	cursor := ""
	totalUpdated := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		rows, err := querier.SelectOffchainTxsWithoutPackets(
			ctx, queries.SelectOffchainTxsWithoutPacketsParams{
				Cursor: cursor,
				Lim:    int32(backfillBatchSize),
			},
		)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			packets, decodeErr := domain.PacketTypesFromPSBT64(row.Tx)
			col := encodePacketsColumn(packets)
			if decodeErr != nil {
				log.WithError(decodeErr).Warnf(
					"failed to decode packets for offchain tx %s during backfill; "+
						"marking row as having no extension to avoid retry",
					row.Txid,
				)
				col = sql.NullString{String: "", Valid: true}
			}
			if err := querier.UpdateOffchainTxPackets(
				ctx, queries.UpdateOffchainTxPacketsParams{
					Txid: row.Txid, Packets: col,
				},
			); err != nil {
				return fmt.Errorf("update packets for offchain tx %s: %w", row.Txid, err)
			}
			cursor = row.Txid
			totalUpdated++
		}
	}
	if totalUpdated > 0 {
		log.Infof("backfilled packets column for %d offchain tx(s)", totalUpdated)
	}
	return nil
}

// encodePacketsColumn formats a packet-type list into the CSV
// representation persisted in offchain_tx.packets. An empty (but
// non-nil) list is persisted as the empty string so that NULL can be
// reserved to mean "not yet backfilled".
func encodePacketsColumn(packets []int) sql.NullString {
	if packets == nil {
		return sql.NullString{}
	}
	parts := make([]string, 0, len(packets))
	for _, p := range packets {
		parts = append(parts, strconv.Itoa(p))
	}
	return sql.NullString{String: strings.Join(parts, ","), Valid: true}
}

// decodePacketsColumn mirrors the nil/empty distinction the domain layer keeps:
// NULL means the row has not been decoded yet and is what the backfill scans
// for, while an empty string means it was decoded and carried no extensions.
// Collapsing both to nil would make a no-extension row read back as
// not-yet-decoded.
func decodePacketsColumn(col sql.NullString) []int {
	if !col.Valid {
		return nil
	}
	if col.String == "" {
		return []int{}
	}
	parts := strings.Split(col.String, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			log.WithError(err).Warnf(
				"offchain_tx.packets contains non-integer entry %q; "+
					"skipping (storage may be corrupt)", p,
			)
			continue
		}
		out = append(out, n)
	}
	return out
}
