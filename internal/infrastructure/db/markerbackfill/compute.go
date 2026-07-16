package markerbackfill

import (
	"fmt"
	"sort"
	"strings"
)

// MarkerInterval is the depth interval at which a new boundary marker is
// created. Must match internal/core/domain/marker.go MarkerInterval.
const MarkerInterval = 100

// VtxoRow is one (txid, vout, ark_txid) tuple loaded from the vtxo table.
// ArkTxidValid mirrors sql.NullString.Valid; when false ArkTxid is ignored.
type VtxoRow struct {
	Txid         string
	Vout         uint32
	ArkTxid      string
	ArkTxidValid bool
}

// Outpoint returns the canonical "txid:vout" outpoint string used as a
// self-marker id and as the map key throughout the algorithm.
func (v VtxoRow) Outpoint() string { return fmt.Sprintf("%s:%d", v.Txid, v.Vout) }

// MarkerRow is a marker to insert: id, its BFS depth, and the sorted union of
// its parents' marker ids (empty for self-markers / roots).
type MarkerRow struct {
	ID            string
	Depth         uint32
	ParentMarkers []string
}

// BuildIndexes groups vtxos by their own txid and by the txid of the tx they
// spend (their parent linkage), the two inputs ComputeDepths/ComputeMarkers need.
func BuildIndexes(all []VtxoRow) (vtxosByTxid, parentsByChildTxid map[string][]VtxoRow) {
	vtxosByTxid = make(map[string][]VtxoRow)
	parentsByChildTxid = make(map[string][]VtxoRow)
	for _, v := range all {
		vtxosByTxid[v.Txid] = append(vtxosByTxid[v.Txid], v)
		if v.ArkTxidValid && v.ArkTxid != "" {
			parentsByChildTxid[v.ArkTxid] = append(parentsByChildTxid[v.ArkTxid], v)
		}
	}
	return vtxosByTxid, parentsByChildTxid
}

// ComputeDepths runs a frontier BFS over the parent->child graph keyed by txid.
// Returns (txid -> depth, maxDepth). Unreachable txids are omitted; callers
// treat their absence as "leave at default depth=0".
func ComputeDepths(
	vtxosByTxid map[string][]VtxoRow, parentsByChildTxid map[string][]VtxoRow,
) (map[string]uint32, uint32) {
	depthByTxid := make(map[string]uint32, len(vtxosByTxid))

	childrenOf := make(map[string][]string)
	dedupe := make(map[string]map[string]struct{})
	for childTxid, parents := range parentsByChildTxid {
		for _, p := range parents {
			if dedupe[p.Txid] == nil {
				dedupe[p.Txid] = make(map[string]struct{})
			}
			if _, ok := dedupe[p.Txid][childTxid]; !ok {
				dedupe[p.Txid][childTxid] = struct{}{}
				childrenOf[p.Txid] = append(childrenOf[p.Txid], childTxid)
			}
		}
	}

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
			for _, child := range childrenOf[parent] {
				parents := parentsByChildTxid[child]
				maxPd := uint32(0)
				ready := true
				for _, p := range parents {
					d, ok := depthByTxid[p.Txid]
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
			}
		}
		frontier = next
	}
	return depthByTxid, maxDepth
}

// ComputeMarkers walks txids in depth-ascending order and assigns markers:
//   - depth 0: each vtxo gets a self-marker (id = outpoint).
//   - depth % MarkerInterval == 0 (>0): one boundary marker per txid,
//     id = "{txid}:marker:{depth}", parent_markers = union of parents' markers.
//   - else: vtxos inherit the sorted union of their parents' marker ids.
//
// Returns (outpoint -> []markerID, []MarkerRow to insert).
func ComputeMarkers(
	vtxosByTxid map[string][]VtxoRow,
	parentsByChildTxid map[string][]VtxoRow,
	depthByTxid map[string]uint32,
) (map[string][]string, []MarkerRow) {
	markersByOutpoint := make(map[string][]string, len(depthByTxid))
	var newMarkers []MarkerRow

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
		// Depths can include phantom txids that have no vtxo rows (an ark_txid
		// pointing at a pruned tx). Skip them: minting a boundary marker for a
		// phantom would leave a dangling marker row nothing references.
		if len(vtxos) == 0 {
			continue
		}
		switch {
		case e.depth == 0:
			for _, v := range vtxos {
				op := v.Outpoint()
				markersByOutpoint[op] = []string{op}
				newMarkers = append(newMarkers, MarkerRow{ID: op, Depth: 0, ParentMarkers: nil})
			}
		case e.depth%MarkerInterval == 0:
			parentMarkers := UnionParentMarkers(parentsByChildTxid[e.txid], markersByOutpoint)
			id := fmt.Sprintf("%s:marker:%d", e.txid, e.depth)
			newMarkers = append(
				newMarkers,
				MarkerRow{ID: id, Depth: e.depth, ParentMarkers: parentMarkers},
			)
			for _, v := range vtxos {
				markersByOutpoint[v.Outpoint()] = []string{id}
			}
		default:
			parentMarkers := UnionParentMarkers(parentsByChildTxid[e.txid], markersByOutpoint)
			for _, v := range vtxos {
				markersByOutpoint[v.Outpoint()] = parentMarkers
			}
		}
	}
	return markersByOutpoint, newMarkers
}

// UnionParentMarkers returns the sorted, deduplicated union of the marker ids
// currently assigned to the given parent vtxos.
func UnionParentMarkers(parents []VtxoRow, markersByOutpoint map[string][]string) []string {
	set := make(map[string]struct{})
	for _, p := range parents {
		for _, m := range markersByOutpoint[p.Outpoint()] {
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

// JSONStringArray serializes a []string to a compact JSON array literal.
// Empty/nil -> "[]". Marker ids never contain quotes so no escaping is needed.
func JSONStringArray(xs []string) string {
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
