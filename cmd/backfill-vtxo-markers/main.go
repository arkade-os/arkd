// backfill-vtxo-markers walks an existing vtxo table and computes proper
// depth + multi-marker assignments for every VTXO, replacing the trivial
// self-marker assignment produced by the 20260210100000_add_depth_and_markers
// migration on master-era data.
//
// Without this backfill, every existing VTXO sits at depth=0 with a single
// self-marker and parent_markers=[]. The marker DAG has no topology, so
// preloadByMarkers can't bulk-fetch anything and falls back to per-VTXO
// reads. With this backfill, VTXOs at boundary depths (0, 100, 200, ...)
// own a real marker linked to the boundary above, and the bulk preload
// path can actually engage.
//
// Trade-off: this also wipes swept_marker. The migration migrated each
// vtxo.swept=true into a per-VTXO swept_marker referencing the soon-to-be-
// deleted self-markers. We don't re-derive sweep status from the new
// marker assignments; vtxo_vw.swept becomes uniformly false after backfill.
// That's intentional — this is a one-shot benchmarking utility, not a
// production data migration. Do not run against a live prod DB.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
)

const markerInterval = 100

type vtxoRow struct {
	txid    string
	vout    uint32
	arkTxid sql.NullString
}

func (v vtxoRow) outpoint() string { return fmt.Sprintf("%s:%d", v.txid, v.vout) }

type markerRow struct {
	id            string
	depth         uint32
	parentMarkers []string
}

func main() {
	dsn := flag.String("dsn",
		"postgresql://replay2826@127.0.0.1:5433/projection?sslmode=disable",
		"DSN for projection DB",
	)
	dryRun := flag.Bool("dry-run", false, "Skip writes, just print stats")
	flag.Parse()

	if err := run(*dsn, *dryRun); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(dsn string, dryRun bool) error {
	ctx := context.Background()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}

	log.Println("loading vtxos...")
	start := time.Now()
	allVtxos, err := loadVtxos(ctx, db)
	if err != nil {
		return err
	}
	log.Printf("loaded %d vtxos in %s", len(allVtxos), time.Since(start))

	// vtxosByTxid: each txid's outputs (multiple VTXOs share txid = the tx)
	// parentsByChildTxid: for txid T, the set of VTXOs that have ark_txid=T
	// (these are the parents of the VTXOs at txid T).
	vtxosByTxid := make(map[string][]vtxoRow)
	parentsByChildTxid := make(map[string][]vtxoRow)
	for _, v := range allVtxos {
		vtxosByTxid[v.txid] = append(vtxosByTxid[v.txid], v)
		if v.arkTxid.Valid && v.arkTxid.String != "" {
			parentsByChildTxid[v.arkTxid.String] = append(
				parentsByChildTxid[v.arkTxid.String], v,
			)
		}
	}
	log.Printf("distinct txids: %d  txids-with-parents: %d",
		len(vtxosByTxid), len(parentsByChildTxid))

	depthByTxid, maxDepth := computeDepths(vtxosByTxid, parentsByChildTxid)
	log.Printf("max depth=%d  assigned %d/%d txids",
		maxDepth, len(depthByTxid), len(vtxosByTxid))
	if len(depthByTxid) < len(vtxosByTxid) {
		log.Printf("WARN: %d txids unreachable (treated as roots in inserts above)",
			len(vtxosByTxid)-len(depthByTxid))
	}

	markersByOutpoint, newMarkers := computeMarkers(
		vtxosByTxid, parentsByChildTxid, depthByTxid,
	)
	log.Printf("computed %d marker rows; %d vtxos got markers",
		len(newMarkers), len(markersByOutpoint))
	printDepthHistogram(depthByTxid)

	if dryRun {
		log.Println("dry-run: skipping writes")
		return nil
	}

	return writeBackfill(ctx, db, allVtxos, depthByTxid, markersByOutpoint, newMarkers)
}

func loadVtxos(ctx context.Context, db *sql.DB) ([]vtxoRow, error) {
	rows, err := db.QueryContext(ctx, `SELECT txid, vout, ark_txid FROM vtxo`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []vtxoRow
	for rows.Next() {
		var v vtxoRow
		if err := rows.Scan(&v.txid, &v.vout, &v.arkTxid); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// computeDepths runs a frontier BFS over the parent-child graph keyed by txid.
// Returns (txid → depth, maxDepth). Unreachable txids are omitted; the caller
// should treat their absence as "leave at default depth=0" (which matches the
// migration's existing behaviour for orphan VTXOs whose parents were pruned).
func computeDepths(
	vtxosByTxid map[string][]vtxoRow, parentsByChildTxid map[string][]vtxoRow,
) (map[string]uint32, uint32) {
	depthByTxid := make(map[string]uint32, len(vtxosByTxid))

	// Build parent → set of distinct children (for traversal in frontier order).
	childrenOf := make(map[string][]string)
	dedupe := make(map[string]map[string]struct{})
	for childTxid, parents := range parentsByChildTxid {
		for _, p := range parents {
			if dedupe[p.txid] == nil {
				dedupe[p.txid] = make(map[string]struct{})
			}
			if _, ok := dedupe[p.txid][childTxid]; !ok {
				dedupe[p.txid][childTxid] = struct{}{}
				childrenOf[p.txid] = append(childrenOf[p.txid], childTxid)
			}
		}
	}

	// Roots: txids with no parents in the DB. Includes both commitment-origin
	// VTXOs and orphans (offchain-origin but parents pruned).
	var frontier []string
	for txid := range vtxosByTxid {
		if _, has := parentsByChildTxid[txid]; !has {
			depthByTxid[txid] = 0
			frontier = append(frontier, txid)
		}
	}

	var maxDepth uint32
	for len(frontier) > 0 {
		var next []string
		for _, parent := range frontier {
			pd := depthByTxid[parent]
			for _, child := range childrenOf[parent] {
				// Only assign once all parents of child have known depths.
				// Otherwise this child will be visited again when its other
				// parents' depths are filled in.
				parents := parentsByChildTxid[child]
				maxPd := uint32(0)
				ready := true
				for _, p := range parents {
					d, ok := depthByTxid[p.txid]
					if !ok {
						ready = false
						break
					}
					if d > maxPd {
						maxPd = d
					}
				}
				if !ready {
					continue
				}
				want := maxPd + 1
				if cur, ok := depthByTxid[child]; ok && cur >= want {
					continue
				}
				depthByTxid[child] = want
				if want > maxDepth {
					maxDepth = want
				}
				next = append(next, child)
				_ = pd
			}
		}
		frontier = next
	}
	return depthByTxid, maxDepth
}

// computeMarkers walks txids in depth-ascending order. For each:
//   - depth 0: each VTXO gets a self-marker (id = outpoint string). Matches
//     application convention from utils.go:292.
//   - depth % 100 == 0 (boundary, >0): new marker id=`{txid}:marker:{depth}`,
//     parent_markers = union of parents' marker IDs.
//   - else: VTXOs inherit parents' marker IDs (no new marker row).
//
// Returns (outpoint → []markerID, []markerRow to insert).
func computeMarkers(
	vtxosByTxid map[string][]vtxoRow,
	parentsByChildTxid map[string][]vtxoRow,
	depthByTxid map[string]uint32,
) (map[string][]string, []markerRow) {
	markersByOutpoint := make(map[string][]string, len(depthByTxid))
	var newMarkers []markerRow

	type entry struct {
		txid  string
		depth uint32
	}
	ordered := make([]entry, 0, len(depthByTxid))
	for t, d := range depthByTxid {
		ordered = append(ordered, entry{t, d})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].depth < ordered[j].depth })

	for _, e := range ordered {
		vtxos := vtxosByTxid[e.txid]

		switch {
		case e.depth == 0:
			for _, v := range vtxos {
				op := v.outpoint()
				markersByOutpoint[op] = []string{op}
				newMarkers = append(newMarkers, markerRow{
					id: op, depth: 0, parentMarkers: nil,
				})
			}

		case e.depth%markerInterval == 0:
			parentMarkers := unionParentMarkers(
				parentsByChildTxid[e.txid], markersByOutpoint,
			)
			id := fmt.Sprintf("%s:marker:%d", e.txid, e.depth)
			newMarkers = append(newMarkers, markerRow{
				id: id, depth: e.depth, parentMarkers: parentMarkers,
			})
			for _, v := range vtxos {
				markersByOutpoint[v.outpoint()] = []string{id}
			}

		default:
			parentMarkers := unionParentMarkers(
				parentsByChildTxid[e.txid], markersByOutpoint,
			)
			for _, v := range vtxos {
				markersByOutpoint[v.outpoint()] = parentMarkers
			}
		}
	}
	return markersByOutpoint, newMarkers
}

func unionParentMarkers(
	parents []vtxoRow, markersByOutpoint map[string][]string,
) []string {
	set := make(map[string]struct{})
	for _, p := range parents {
		for _, m := range markersByOutpoint[p.outpoint()] {
			set[m] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func printDepthHistogram(depthByTxid map[string]uint32) {
	buckets := make(map[uint32]int)
	for _, d := range depthByTxid {
		bucket := d / markerInterval * markerInterval
		buckets[bucket]++
	}
	var keys []uint32
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	log.Println("depth histogram (per 100):")
	for _, k := range keys {
		log.Printf("  [%4d-%4d]  %d", k, k+99, buckets[k])
	}
}

func writeBackfill(
	ctx context.Context, db *sql.DB,
	allVtxos []vtxoRow,
	depthByTxid map[string]uint32,
	markersByOutpoint map[string][]string,
	newMarkers []markerRow,
) error {
	log.Println("writing backfill...")
	start := time.Now()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.ExecContext(ctx, `DELETE FROM swept_marker`); err != nil {
		return fmt.Errorf("clear swept_marker: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM marker`); err != nil {
		return fmt.Errorf("clear marker: %w", err)
	}
	log.Println("  cleared marker + swept_marker")

	stmt, err := tx.PrepareContext(ctx,
		pq.CopyIn("marker", "id", "depth", "parent_markers"),
	)
	if err != nil {
		return fmt.Errorf("prepare copy: %w", err)
	}
	for _, m := range newMarkers {
		if _, err := stmt.ExecContext(
			ctx,
			m.id,
			m.depth,
			jsonStringArray(m.parentMarkers),
		); err != nil {
			return fmt.Errorf("copy marker row: %w", err)
		}
	}
	if _, err := stmt.ExecContext(ctx); err != nil {
		return fmt.Errorf("copy flush: %w", err)
	}
	if err := stmt.Close(); err != nil {
		return fmt.Errorf("copy close: %w", err)
	}
	log.Printf("  inserted %d marker rows", len(newMarkers))

	// Bulk UPDATE vtxos via batched UPDATE ... FROM (VALUES ...).
	type update struct {
		txid    string
		vout    uint32
		depth   uint32
		markers []string
	}
	updates := make([]update, 0, len(allVtxos))
	for _, v := range allVtxos {
		d, ok := depthByTxid[v.txid]
		if !ok {
			continue // unreachable, leave defaults
		}
		updates = append(updates, update{
			txid:    v.txid,
			vout:    v.vout,
			depth:   d,
			markers: markersByOutpoint[v.outpoint()],
		})
	}

	const batchSize = 1000
	for i := 0; i < len(updates); i += batchSize {
		end := i + batchSize
		if end > len(updates) {
			end = len(updates)
		}
		batch := updates[i:end]

		var sb strings.Builder
		sb.WriteString(`UPDATE vtxo SET depth = v.depth, markers = v.markers::jsonb FROM (VALUES `)
		args := make([]any, 0, len(batch)*4)
		for j, u := range batch {
			if j > 0 {
				sb.WriteByte(',')
			}
			b := j*4 + 1
			fmt.Fprintf(&sb, "($%d::text,$%d::integer,$%d::integer,$%d::text)",
				b, b+1, b+2, b+3)
			args = append(args,
				u.txid, int32(u.vout), int32(u.depth), jsonStringArray(u.markers),
			)
		}
		sb.WriteString(
			`) AS v(txid, vout, depth, markers) WHERE vtxo.txid = v.txid AND vtxo.vout = v.vout`,
		)
		if _, err := tx.ExecContext(ctx, sb.String(), args...); err != nil {
			return fmt.Errorf("update batch %d: %w", i, err)
		}
		if (i/batchSize)%20 == 0 {
			log.Printf("  updated %d/%d vtxos", end, len(updates))
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	tx = nil
	log.Printf("backfill complete in %s", time.Since(start))
	return nil
}

func jsonStringArray(xs []string) string {
	if len(xs) == 0 {
		return "[]"
	}
	var sb strings.Builder
	sb.WriteByte('[')
	for i, x := range xs {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('"')
		sb.WriteString(x)
		sb.WriteByte('"')
	}
	sb.WriteByte(']')
	return sb.String()
}
