package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
	log "github.com/sirupsen/logrus"
)

// sqliteMaxBulkTxids caps the per-query batch for the txid-slice queries
// (GetOffchainTxsByTxids and the WithTxids path of GetOffchainTxs). The SLICE
// expansion in the generated query emits one bound parameter per txid, and
// SQLITE_MAX_VARIABLE_NUMBER bounds how many a single statement may carry:
// 32766 on the bundled modernc.org/sqlite build, 999 on SQLite < 3.32. The cap
// stays at the conservative end so the batching holds on either.
const sqliteMaxBulkTxids = 500

type offchainTxRepository struct {
	db             SQLiteDB
	backfillCancel context.CancelFunc
	backfillDone   chan struct{}
}

func NewOffchainTxRepository(config ...interface{}) (domain.OffchainTxRepository, error) {
	if len(config) != 1 {
		return nil, fmt.Errorf("invalid config")
	}
	db, ok := config[0].(SQLiteDB)
	if !ok {
		return nil, fmt.Errorf("cannot open offchain tx repository: invalid config")
	}

	backfillCtx, cancel := context.WithCancel(context.Background())
	repo := &offchainTxRepository{
		db:             db,
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
			StageCode:         int64(offchainTx.Stage.Code),
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
	return execTx(ctx, v.db.Write(), txBody)
}

func (v *offchainTxRepository) GetOffchainTxs(
	ctx context.Context, filter domain.OffchainTxFilter,
) ([]*domain.OffchainTx, error) {
	if err := filter.Validate(); err != nil {
		return nil, err
	}

	// fold (txid -> offchain tx with checkpoint maps) so that the LEFT JOIN
	// against checkpoint_tx is collapsed correctly.
	byTxid := make(map[string]*domain.OffchainTx)
	order := make([]string, 0)
	// batched is set when the txid slice was split across queries, which
	// breaks the per-query ORDER BY and requires a re-sort after folding.
	batched := false
	if len(filter.WithTxids) > 0 {
		txids := filter.WithTxids
		batched = len(txids) > sqliteMaxBulkTxids
		// The SLICE expansion emits one bound parameter per txid, so batch
		// it the same way GetOffchainTxsByTxids does to stay under
		// SQLITE_MAX_VARIABLE_NUMBER.
		for start := 0; start < len(txids); start += sqliteMaxBulkTxids {
			end := min(start+sqliteMaxBulkTxids, len(txids))
			var raw []queries.SelectFilteredOffchainTxsByTxidsRow
			if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
				var err error
				raw, err = q.SelectFilteredOffchainTxsByTxids(
					ctx,
					queries.SelectFilteredOffchainTxsByTxidsParams{
						Txids: txids[start:end],
						WithExtension: boolToInt64(
							filter.WithExtension || len(filter.WithPacket) > 0 ||
								len(filter.WithPacketContains) > 0,
						),
						WithAfter:  boolToInt64(filter.WithAfterDate > 0),
						AfterTs:    filter.WithAfterDate,
						WithBefore: boolToInt64(filter.WithBeforeDate > 0),
						BeforeTs:   filter.WithBeforeDate,
					},
				)
				return err
			}); err != nil {
				return nil, err
			}
			for _, r := range raw {
				order = foldOffchainTxRow(byTxid, order, r.OffchainTxVw)
			}
			// A caller-supplied txid list does not bound the result: in
			// withheld/private mode an empty request is backfilled from the
			// auth token's whitelist, which comes from an unbounded vtxo chain
			// walk. Trim the running set to the same cap the unfiltered path
			// applies in SQL so the accumulation across batches stays bounded
			// rather than growing with the whitelist.
			order = trimToScanLimit(byTxid, order)
		}
	} else {
		var raw []queries.SelectOffchainTxsRow
		if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
			var err error
			raw, err = q.SelectOffchainTxs(ctx, queries.SelectOffchainTxsParams{
				WithExtension: boolToInt64(
					filter.WithExtension || len(filter.WithPacket) > 0 ||
						len(filter.WithPacketContains) > 0,
				),
				WithAfter:  boolToInt64(filter.WithAfterDate > 0),
				AfterTs:    filter.WithAfterDate,
				WithBefore: boolToInt64(filter.WithBeforeDate > 0),
				BeforeTs:   filter.WithBeforeDate,
				Lim:        int64(domain.OffchainTxsScanLimit),
			})
			return err
		}); err != nil {
			return nil, err
		}
		for _, r := range raw {
			order = foldOffchainTxRow(byTxid, order, r.OffchainTxVw)
		}
	}

	// Each batch is ordered on its own, so restore the query's global
	// ORDER BY starting_timestamp DESC, txid ASC across batch boundaries.
	if batched {
		sortOffchainTxOrder(byTxid, order)
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

	grouped := make(map[string][]queries.OffchainTxVw)
	for start := 0; start < len(txids); start += sqliteMaxBulkTxids {
		end := min(start+sqliteMaxBulkTxids, len(txids))
		var rows []queries.SelectOffchainTxsByTxidsRow
		if err := withReadQuerier(ctx, v.db, func(q *queries.Queries) error {
			var err error
			rows, err = q.SelectOffchainTxsByTxids(ctx, txids[start:end])
			return err
		}); err != nil {
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
		if err := BackfillPackets(ctx, v.db.Write()); err != nil {
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
				Lim:    int64(backfillBatchSize),
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

func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
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

func decodePacketsColumn(col sql.NullString) []int {
	if !col.Valid || col.String == "" {
		return nil
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

// foldOffchainTxRow folds one view row into the txid-keyed accumulator so the
// LEFT JOIN against checkpoint_tx is collapsed correctly, returning the updated
// insertion order.
func foldOffchainTxRow(
	byTxid map[string]*domain.OffchainTx, order []string, vw queries.OffchainTxVw,
) []string {
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
	if vw.CheckpointTxid != "" && vw.CheckpointTx != "" {
		off.CheckpointTxs[vw.CheckpointTxid] = vw.CheckpointTx
		off.CommitmentTxids[vw.CheckpointTxid] = vw.CommitmentTxid.String
		if vw.IsRootCommitmentTxid.Bool {
			off.RootCommitmentTxId = vw.CommitmentTxid.String
		}
	}
	return order
}

// sortOffchainTxOrder restores ORDER BY starting_timestamp DESC, txid ASC.
// SliceStable rather than Slice so rows that tie on timestamp keep the order
// the database returned them in.
func sortOffchainTxOrder(byTxid map[string]*domain.OffchainTx, order []string) {
	sort.SliceStable(order, func(i, j int) bool {
		a, b := byTxid[order[i]], byTxid[order[j]]
		if a.StartingTimestamp != b.StartingTimestamp {
			return a.StartingTimestamp > b.StartingTimestamp
		}
		return a.ArkTxid < b.ArkTxid
	})
}

// trimToScanLimit keeps the highest-ranked OffchainTxsScanLimit txids and drops
// the rest, so batching a large txid list cannot accumulate the whole set in
// memory. Sorting before trimming means the survivors are the global top-N so
// far, not whichever batch happened to arrive first.
func trimToScanLimit(byTxid map[string]*domain.OffchainTx, order []string) []string {
	if len(order) <= domain.OffchainTxsScanLimit {
		return order
	}
	sortOffchainTxOrder(byTxid, order)
	for _, txid := range order[domain.OffchainTxsScanLimit:] {
		delete(byTxid, txid)
	}
	return order[:domain.OffchainTxsScanLimit]
}
