package markerbackfill_test

import (
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/internal/infrastructure/db/markerbackfill"
	"github.com/stretchr/testify/require"
)

func TestComputeDepths(t *testing.T) {
	t.Run("linear chain", func(t *testing.T) {
		const n = 205
		rows, txids := linearChain(n)
		vtxosByTxid, parentsByChildTxid := markerbackfill.BuildIndexes(rows)
		depthByTxid, maxDepth := markerbackfill.ComputeDepths(vtxosByTxid, parentsByChildTxid)

		require.Equal(t, uint32(n), maxDepth)
		for k := 0; k <= n; k++ {
			require.Equal(t, uint32(k), depthByTxid[txids[k]], "depth at index %d", k)
		}
	})

	t.Run("diamond", func(t *testing.T) {
		// root(A) -> B and C; B and C both -> D. D depth = max(B,C)+1 = 2.
		// A is the parent of B and C (two outputs, each spent): rows at txid A
		// with ArkTxid=B and ArkTxid=C. B and C are each parents of D.
		rows := []markerbackfill.VtxoRow{
			{Txid: "A", Vout: 0, ArkTxid: "B", ArkTxidValid: true},
			{Txid: "A", Vout: 1, ArkTxid: "C", ArkTxidValid: true},
			{Txid: "B", Vout: 0, ArkTxid: "D", ArkTxidValid: true},
			{Txid: "C", Vout: 0, ArkTxid: "D", ArkTxidValid: true},
			{Txid: "D", Vout: 0},
		}
		vtxosByTxid, parentsByChildTxid := markerbackfill.BuildIndexes(rows)
		depthByTxid, maxDepth := markerbackfill.ComputeDepths(vtxosByTxid, parentsByChildTxid)

		require.Equal(t, uint32(0), depthByTxid["A"])
		require.Equal(t, uint32(1), depthByTxid["B"])
		require.Equal(t, uint32(1), depthByTxid["C"])
		require.Equal(t, uint32(2), depthByTxid["D"])
		require.Equal(t, uint32(2), maxDepth)
	})

	t.Run("orphan omitted", func(t *testing.T) {
		// C is a child of P (row at txid P points ArkTxid=C), but P is itself a
		// child of a pruned txid: parentsByChildTxid lists P as having a parent
		// "GONE" that is never present in vtxosByTxid, so P never gets a depth and
		// C, whose readiness depends on P, stays unreachable.
		rows := []markerbackfill.VtxoRow{
			// A parent-of-P row whose txid GONE only exists as this row's ArkTxid
			// target P; GONE itself has no vtxo rows (pruned), so P is not a root
			// (it has a parent) yet its parent never resolves.
			{Txid: "P", Vout: 0, ArkTxid: "C", ArkTxidValid: true},
			{Txid: "C", Vout: 0},
		}
		// Manually inject P as a child of a pruned tx so P is not treated as a root.
		vtxosByTxid, parentsByChildTxid := markerbackfill.BuildIndexes(rows)
		parentsByChildTxid["P"] = []markerbackfill.VtxoRow{
			{Txid: "GONE", Vout: 0, ArkTxid: "P", ArkTxidValid: true},
		}
		depthByTxid, _ := markerbackfill.ComputeDepths(vtxosByTxid, parentsByChildTxid)

		// P has a parent (GONE) that never resolves, so P is unreachable, and C
		// (whose only parent is P) is unreachable too.
		_, okP := depthByTxid["P"]
		require.False(t, okP, "P must be absent (parent pruned)")
		_, okC := depthByTxid["C"]
		require.False(t, okC, "orphan child C must be absent from depthByTxid")
	})
}

func TestComputeMarkers(t *testing.T) {
	t.Run("linear chain boundaries", func(t *testing.T) {
		const n = 205
		rows, txids := linearChain(n)
		vtxosByTxid, parentsByChildTxid := markerbackfill.BuildIndexes(rows)
		depthByTxid, _ := markerbackfill.ComputeDepths(vtxosByTxid, parentsByChildTxid)
		markersByOutpoint, newMarkers := markerbackfill.ComputeMarkers(
			vtxosByTxid, parentsByChildTxid, depthByTxid,
		)

		byID := make(map[string]markerbackfill.MarkerRow, len(newMarkers))
		for _, m := range newMarkers {
			byID[m.ID] = m
		}

		// depth-0 self-marker for the root.
		rootOp := txids[0] + ":0"
		require.Equal(t, []string{rootOp}, markersByOutpoint[rootOp])
		require.Contains(t, byID, rootOp)
		require.Empty(t, byID[rootOp].ParentMarkers)

		// boundary markers at 100 and 200 with correct parent linkage.
		m100 := fmt.Sprintf("%s:marker:100", txids[100])
		m200 := fmt.Sprintf("%s:marker:200", txids[200])
		require.Contains(t, byID, m100)
		require.Contains(t, byID, m200)
		require.Equal(t, uint32(100), byID[m100].Depth)
		require.Equal(t, uint32(200), byID[m200].Depth)
		require.Equal(t, []string{rootOp}, byID[m100].ParentMarkers)
		require.Equal(t, []string{m100}, byID[m200].ParentMarkers)

		// inheritance: depth 47 -> root self-marker; depth 150 -> 100 boundary.
		require.Equal(t, []string{rootOp}, markersByOutpoint[txids[47]+":0"])
		require.Equal(t, []string{m100}, markersByOutpoint[txids[150]+":0"])
	})

	t.Run("diamond union", func(t *testing.T) {
		// Two boundary parents at depth 100 merging into a child at depth 101
		// which then reaches a boundary at 200; assert unioned parent markers.
		// Build: rootB (0) -> ...100 chain... reaching a boundary Bm; same for C;
		// then a merge. To keep it simple, directly craft depths.
		depthByTxid := map[string]uint32{
			"P1": 100, "P2": 100, "M": 200,
		}
		vtxosByTxid := map[string][]markerbackfill.VtxoRow{
			"P1": {{Txid: "P1", Vout: 0}},
			"P2": {{Txid: "P2", Vout: 0}},
			"M":  {{Txid: "M", Vout: 0}},
		}
		parentsByChildTxid := map[string][]markerbackfill.VtxoRow{
			"M": {{Txid: "P1", Vout: 0}, {Txid: "P2", Vout: 0}},
		}
		markersByOutpoint, newMarkers := markerbackfill.ComputeMarkers(
			vtxosByTxid, parentsByChildTxid, depthByTxid,
		)
		byID := make(map[string]markerbackfill.MarkerRow)
		for _, m := range newMarkers {
			byID[m.ID] = m
		}
		mMerge := "M:marker:200"
		require.Contains(t, byID, mMerge)
		require.Equal(t, []string{"P1:marker:100", "P2:marker:100"}, byID[mMerge].ParentMarkers)
		require.Equal(t, []string{mMerge}, markersByOutpoint["M:0"])
	})

	t.Run("phantom txid skipped", func(t *testing.T) {
		// A phantom txid (present in depthByTxid because some vtxo's ark_txid
		// points at it, but with no vtxo rows of its own) must not mint a marker,
		// even when it lands exactly on a boundary depth — that would leave a
		// dangling marker row nothing references.
		rows := []markerbackfill.VtxoRow{
			{Txid: "real", Vout: 0, ArkTxid: "phantom", ArkTxidValid: true},
		}
		vtxosByTxid, parentsByChildTxid := markerbackfill.BuildIndexes(rows)
		depthByTxid := map[string]uint32{
			"real":    markerbackfill.MarkerInterval - 1,
			"phantom": markerbackfill.MarkerInterval, // boundary depth
		}
		markersByOutpoint, newMarkers := markerbackfill.ComputeMarkers(
			vtxosByTxid, parentsByChildTxid, depthByTxid,
		)

		for _, m := range newMarkers {
			require.NotContains(t, m.ID, "phantom", "phantom must not mint marker %s", m.ID)
		}
		_, ok := markersByOutpoint["phantom:0"]
		require.False(t, ok, "phantom outpoint must not receive markers")
	})
}

func TestJSONStringArray(t *testing.T) {
	require.Equal(t, "[]", markerbackfill.JSONStringArray(nil))
	require.Equal(t, "[]", markerbackfill.JSONStringArray([]string{}))
	require.Equal(t, `["a"]`, markerbackfill.JSONStringArray([]string{"a"}))
	require.Equal(t, `["a","b","c"]`, markerbackfill.JSONStringArray([]string{"a", "b", "c"}))
}

// linearChain builds a chain tx0(root) -> tx1 -> ... -> txN(leaf). A row whose
// ark_txid = T is a PARENT of the tx at T (matching parentsByChildTxid in the
// backfill: parentsByChildTxid[v.ArkTxid] gets v). So tx_k (the parent of
// tx_{k+1}) carries ArkTxid = txids[k+1]. txids[0] is the root (no ark_txid).
// Returns the rows and the per-index txid (index == chain depth).
func linearChain(n int) ([]markerbackfill.VtxoRow, []string) {
	txids := make([]string, n+1)
	for k := 0; k <= n; k++ {
		txids[k] = fmt.Sprintf("tx%03d", k)
	}
	rows := make([]markerbackfill.VtxoRow, 0, n+1)
	for k := 0; k <= n; k++ {
		v := markerbackfill.VtxoRow{Txid: txids[k], Vout: 0}
		if k < n {
			v.ArkTxid = txids[k+1]
			v.ArkTxidValid = true
		}
		rows = append(rows, v)
	}
	return rows, txids
}
