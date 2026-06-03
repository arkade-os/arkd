package sqlitedb

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db/sqlite/sqlc/queries"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
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

	repo := &offchainTxRepository{
		db:      db,
		querier: queries.New(db),
	}
	if err := repo.backfillPackets(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to backfill offchain_tx.packets: %w", err)
	}
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
		raw, err := v.querier.SelectOffchainTxsByTxids(ctx, queries.SelectOffchainTxsByTxidsParams{
			Txids:         filter.WithTxids,
			WithExtension: boolToInt64(filter.WithExtension || len(filter.WithPacket) > 0),
			WithAfter:     boolToInt64(filter.WithAfterDate > 0),
			AfterTs:       filter.WithAfterDate,
			WithBefore:    boolToInt64(filter.WithBeforeDate > 0),
			BeforeTs:      filter.WithBeforeDate,
		})
		if err != nil {
			return nil, err
		}
		rows = make([]vwRow, 0, len(raw))
		for _, r := range raw {
			rows = append(rows, vwRow{OffchainTxVw: r.OffchainTxVw})
		}
	} else {
		raw, err := v.querier.SelectOffchainTxs(ctx, queries.SelectOffchainTxsParams{
			WithExtension: boolToInt64(filter.WithExtension || len(filter.WithPacket) > 0),
			WithAfter:     boolToInt64(filter.WithAfterDate > 0),
			AfterTs:       filter.WithAfterDate,
			WithBefore:    boolToInt64(filter.WithBeforeDate > 0),
			BeforeTs:      filter.WithBeforeDate,
		})
		if err != nil {
			return nil, err
		}
		rows = make([]vwRow, 0, len(raw))
		for _, r := range raw {
			rows = append(rows, vwRow{OffchainTxVw: r.OffchainTxVw})
		}
	}

	// fold (txid -> offchain tx with checkpoint maps) so that the LEFT JOIN
	// against checkpoint_tx is collapsed correctly.
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
		if vw.CheckpointTxid != "" && vw.CheckpointTx != "" {
			off.CheckpointTxs[vw.CheckpointTxid] = vw.CheckpointTx
			off.CommitmentTxids[vw.CheckpointTxid] = vw.CommitmentTxid.String
			if vw.IsRootCommitmentTxid.Bool {
				off.RootCommitmentTxId = vw.CommitmentTxid.String
			}
		}
	}

	out := make([]*domain.OffchainTx, 0, len(order))
	for _, txid := range order {
		off := byTxid[txid]
		if !matchPacketFilter(off, filter.WithPacket) {
			continue
		}
		out = append(out, off)
	}
	return out, nil
}

func (v *offchainTxRepository) Close() {
	_ = v.db.Close()
}

func (v *offchainTxRepository) backfillPackets(ctx context.Context) error {
	rows, err := v.querier.SelectOffchainTxsWithoutPackets(ctx)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}

	updated := 0
	for _, row := range rows {
		packets, decodeErr := decodePacketsFromTx(row.Tx)
		if decodeErr != nil {
			log.WithError(decodeErr).
				Warnf("failed to decode packets for offchain tx %s during backfill", row.Txid)
			continue
		}
		if err := v.querier.UpdateOffchainTxPackets(ctx, queries.UpdateOffchainTxPacketsParams{
			Txid:    row.Txid,
			Packets: encodePacketsColumn(packets),
		}); err != nil {
			return fmt.Errorf("failed to update packets for offchain tx %s: %w", row.Txid, err)
		}
		updated++
	}
	log.Infof("backfilled packets column for %d offchain tx(s)", updated)
	return nil
}

func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// encodePacketsColumn formats a packet-type list into the CSV
// representation persisted in offchain_tx.packets. An empty list (no
// extension) is persisted as the empty string so that a NULL value can be
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

// decodePacketsColumn parses the CSV representation produced by
// encodePacketsColumn back into the in-memory []int form.
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
			continue
		}
		out = append(out, n)
	}
	return out
}

// decodePacketsFromTx parses the ARK extension OP_RETURN in the persisted
// ark tx (base64 PSBT) and returns the list of packet types. Returns nil
// (no error) when the tx carries no extension.
func decodePacketsFromTx(tx string) ([]int, error) {
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return nil, fmt.Errorf("parse psbt: %w", err)
	}
	ext, err := extension.NewExtensionFromTx(ptx.UnsignedTx)
	if err != nil {
		if errors.Is(err, extension.ErrExtensionNotFound) {
			return []int{}, nil
		}
		return nil, fmt.Errorf("parse extension: %w", err)
	}
	out := make([]int, 0, len(ext))
	for _, p := range ext {
		out = append(out, int(p.Type()))
	}
	return out, nil
}

// matchPacketFilter applies the post-SQL portion of an OffchainTxFilter:
// a tx matches when it carries every requested packet type, and (when a
// payload is provided) the persisted ark tx contains the base64-encoded
// payload bytes. An empty filter matches every tx.
func matchPacketFilter(off *domain.OffchainTx, want map[int]string) bool {
	if len(want) == 0 {
		return true
	}
	carried := make(map[int]struct{}, len(off.Packets))
	for _, p := range off.Packets {
		carried[p] = struct{}{}
	}
	for t, data := range want {
		if _, ok := carried[t]; !ok {
			return false
		}
		if data == "" {
			continue
		}
		raw, err := hex.DecodeString(data)
		if err != nil {
			return false
		}
		needle := base64.StdEncoding.EncodeToString(raw)
		if !strings.Contains(off.ArkTx, needle) {
			return false
		}
	}
	return true
}
