package application

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// Lightweight fake repos for benchmarks — no testify/mock overhead.
// Unused interface methods are satisfied by the embedded nil interface
// and will panic if called unexpectedly.

type benchVtxoRepo struct {
	domain.VtxoRepository
	vtxos map[string]domain.Vtxo
}

func (r *benchVtxoRepo) GetVtxos(
	_ context.Context, outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	result := make([]domain.Vtxo, 0, len(outpoints))
	for _, op := range outpoints {
		if v, ok := r.vtxos[op.String()]; ok {
			result = append(result, v)
		}
	}
	return result, nil
}

func (r *benchVtxoRepo) Close() {}

type benchMarkerRepo struct {
	domain.MarkerRepository
	markers       map[string]domain.Marker
	vtxosByMarker map[string][]domain.Vtxo
}

func (r *benchMarkerRepo) GetVtxoChainByMarkers(
	_ context.Context, markerIDs []string,
) ([]domain.Vtxo, error) {
	seen := make(map[string]bool)
	var result []domain.Vtxo
	for _, mid := range markerIDs {
		for _, v := range r.vtxosByMarker[mid] {
			key := v.Outpoint.String()
			if !seen[key] {
				seen[key] = true
				result = append(result, v)
			}
		}
	}
	return result, nil
}

func (r *benchMarkerRepo) GetMarkersByIds(
	_ context.Context, ids []string,
) ([]domain.Marker, error) {
	result := make([]domain.Marker, 0, len(ids))
	for _, id := range ids {
		if m, ok := r.markers[id]; ok {
			result = append(result, m)
		}
	}
	return result, nil
}

func (r *benchMarkerRepo) GetVtxosByMarker(
	_ context.Context, markerID string,
) ([]domain.Vtxo, error) {
	return r.vtxosByMarker[markerID], nil
}

func (r *benchMarkerRepo) Close() {}

type benchOffchainTxRepo struct {
	domain.OffchainTxRepository
	txs map[string]*domain.OffchainTx
}

func (r *benchOffchainTxRepo) GetOffchainTx(
	_ context.Context, txid string,
) (*domain.OffchainTx, error) {
	if tx, ok := r.txs[txid]; ok {
		return tx, nil
	}
	return &domain.OffchainTx{CheckpointTxs: map[string]string{}}, nil
}

func (r *benchOffchainTxRepo) GetOffchainTxsByTxids(
	_ context.Context, txids []string,
) ([]*domain.OffchainTx, error) {
	result := make([]*domain.OffchainTx, 0, len(txids))
	for _, txid := range txids {
		if tx, ok := r.txs[txid]; ok {
			result = append(result, tx)
		}
	}
	return result, nil
}

func (r *benchOffchainTxRepo) Close() {}

type benchRepoManager struct {
	vtxoRepo     *benchVtxoRepo
	markerRepo   *benchMarkerRepo
	offchainRepo domain.OffchainTxRepository
}

func (m *benchRepoManager) Events() domain.EventRepository   { return nil }
func (m *benchRepoManager) Rounds() domain.RoundRepository   { return nil }
func (m *benchRepoManager) Vtxos() domain.VtxoRepository     { return m.vtxoRepo }
func (m *benchRepoManager) Markers() domain.MarkerRepository {
	if m.markerRepo == nil {
		return nil
	}
	return m.markerRepo
}
func (m *benchRepoManager) ScheduledSession() domain.ScheduledSessionRepo { return nil }
func (m *benchRepoManager) OffchainTxs() domain.OffchainTxRepository {
	if m.offchainRepo == nil {
		return nil
	}
	return m.offchainRepo
}
func (m *benchRepoManager) Convictions() domain.ConvictionRepository              { return nil }
func (m *benchRepoManager) Assets() domain.AssetRepository                        { return nil }
func (m *benchRepoManager) Fees() domain.FeeRepository                            { return nil }
func (m *benchRepoManager) RegisterBatchUpdateHandler(func(data domain.Round))    {}
func (m *benchRepoManager) RegisterOffchainTxUpdateHandler(func(domain.OffchainTx)) {}
func (m *benchRepoManager) Close()                                                {}

// benchTxid returns a deterministic 64-char hex txid for index i.
func benchTxid(i int) string {
	return fmt.Sprintf("%064x", i)
}

// benchCheckpointPSBT creates a base64-encoded PSBT with a single input.
func benchCheckpointPSBT(inputTxid string, inputVout uint32) string {
	prevHash, err := chainhash.NewHashFromStr(inputTxid)
	if err != nil {
		panic(fmt.Sprintf("benchCheckpointPSBT: bad txid %q: %v", inputTxid, err))
	}
	p, err := psbt.New(
		[]*wire.OutPoint{wire.NewOutPoint(prevHash, inputVout)},
		[]*wire.TxOut{wire.NewTxOut(1000, []byte{0x51})},
		2, 0,
		[]uint32{wire.MaxTxInSequenceNum},
	)
	if err != nil {
		panic(err)
	}
	b64, err := p.B64Encode()
	if err != nil {
		panic(err)
	}
	return b64
}

// buildLinearChain creates a linear preconfirmed chain:
//
//	V0 -> cp0 -> V1 -> cp1 -> V2 -> ... -> V{n-1} (terminal)
func buildLinearChain(n int, withMarkers bool) (*indexerService, domain.Outpoint) {
	vtxoRepo := &benchVtxoRepo{vtxos: make(map[string]domain.Vtxo, n)}
	offchainRepo := &benchOffchainTxRepo{txs: make(map[string]*domain.OffchainTx, n)}

	vtxos := make([]domain.Vtxo, n)
	for i := 0; i < n; i++ {
		tid := benchTxid(i)
		var markerIDs []string
		if withMarkers {
			markerIDs = []string{fmt.Sprintf("m-%d", i/int(domain.MarkerInterval))}
		}
		vtxos[i] = domain.Vtxo{
			Outpoint:     domain.Outpoint{Txid: tid, VOut: 0},
			Preconfirmed: true,
			ExpiresAt:    int64(1000 + i),
			MarkerIDs:    markerIDs,
		}
		vtxoRepo.vtxos[vtxos[i].Outpoint.String()] = vtxos[i]

		if i < n-1 {
			offchainRepo.txs[tid] = &domain.OffchainTx{
				ArkTxid: tid,
				CheckpointTxs: map[string]string{
					fmt.Sprintf("cp-%d", i): benchCheckpointPSBT(benchTxid(i+1), 0),
				},
			}
		} else {
			offchainRepo.txs[tid] = &domain.OffchainTx{
				ArkTxid:       tid,
				CheckpointTxs: map[string]string{},
			}
		}
	}

	var markerRepo *benchMarkerRepo
	if withMarkers {
		markerRepo = &benchMarkerRepo{
			markers:       make(map[string]domain.Marker),
			vtxosByMarker: make(map[string][]domain.Vtxo),
		}
		interval := int(domain.MarkerInterval)
		markersCount := (n + interval - 1) / interval
		for m := 0; m < markersCount; m++ {
			mid := fmt.Sprintf("m-%d", m)
			start := m * interval
			end := start + interval
			if end > n {
				end = n
			}
			markerRepo.vtxosByMarker[mid] = vtxos[start:end]

			var parentIDs []string
			if m+1 < markersCount {
				parentIDs = []string{fmt.Sprintf("m-%d", m+1)}
			}
			markerRepo.markers[mid] = domain.Marker{
				ID:              mid,
				Depth:           uint32(m * interval),
				ParentMarkerIDs: parentIDs,
			}
		}
	}

	svc := &indexerService{repoManager: &benchRepoManager{
		vtxoRepo: vtxoRepo, markerRepo: markerRepo, offchainRepo: offchainRepo,
	}}
	return svc, domain.Outpoint{Txid: benchTxid(0), VOut: 0}
}

// buildFanoutTree creates a binary-tree shaped chain where each VTXO has
// 2 checkpoints pointing to 2 children. Depth d produces 2^(d+1)-1 VTXOs.
//
//	         V0
//	        / \
//	      V1   V2
//	     / \   / \
//	   V3  V4 V5  V6
//	   ...
func buildFanoutTree(depth int) (*indexerService, domain.Outpoint, int) {
	n := (1 << (depth + 1)) - 1
	vtxoRepo := &benchVtxoRepo{vtxos: make(map[string]domain.Vtxo, n)}
	offchainRepo := &benchOffchainTxRepo{txs: make(map[string]*domain.OffchainTx, n)}

	for i := 0; i < n; i++ {
		tid := benchTxid(i)
		vtxoRepo.vtxos[fmt.Sprintf("%s:0", tid)] = domain.Vtxo{
			Outpoint:     domain.Outpoint{Txid: tid, VOut: 0},
			Preconfirmed: true,
			ExpiresAt:    int64(1000 + i),
		}

		left := 2*i + 1
		right := 2*i + 2
		if left < n && right < n {
			offchainRepo.txs[tid] = &domain.OffchainTx{
				CheckpointTxs: map[string]string{
					fmt.Sprintf("cp-l-%d", i): benchCheckpointPSBT(benchTxid(left), 0),
					fmt.Sprintf("cp-r-%d", i): benchCheckpointPSBT(benchTxid(right), 0),
				},
			}
		} else {
			offchainRepo.txs[tid] = &domain.OffchainTx{CheckpointTxs: map[string]string{}}
		}
	}

	svc := &indexerService{repoManager: &benchRepoManager{
		vtxoRepo: vtxoRepo, offchainRepo: offchainRepo,
	}}
	return svc, domain.Outpoint{Txid: benchTxid(0), VOut: 0}, n
}

// buildDiamondChain creates a chain of diamond patterns where paths diverge
// and reconverge, stressing the visited-set deduplication:
//
//	V0 --(2 checkpoints)--> V1, V2
//	V1 --(1 checkpoint)---> V3
//	V2 --(1 checkpoint)---> V3  (same V3 = convergence)
//	V3 --(2 checkpoints)--> V4, V5
//	V4 --(1 checkpoint)---> V6
//	V5 --(1 checkpoint)---> V6
//	...
//
// Each diamond uses 3 node indices; the convergence node is the next diamond's
// fan-out. Total unique VTXOs = 3*diamonds + 1.
func buildDiamondChain(diamonds int) (*indexerService, domain.Outpoint, int) {
	n := 3*diamonds + 1
	vtxoRepo := &benchVtxoRepo{vtxos: make(map[string]domain.Vtxo, n)}
	offchainRepo := &benchOffchainTxRepo{txs: make(map[string]*domain.OffchainTx, n)}

	for i := 0; i < n; i++ {
		tid := benchTxid(i)
		vtxoRepo.vtxos[fmt.Sprintf("%s:0", tid)] = domain.Vtxo{
			Outpoint:     domain.Outpoint{Txid: tid, VOut: 0},
			Preconfirmed: true,
			ExpiresAt:    int64(1000 + i),
		}
	}

	for d := 0; d < diamonds; d++ {
		fanOut := 3 * d
		midA := 3*d + 1
		midB := 3*d + 2
		converge := 3 * (d + 1)

		// Fan-out: 2 checkpoints -> midA, midB
		offchainRepo.txs[benchTxid(fanOut)] = &domain.OffchainTx{
			CheckpointTxs: map[string]string{
				fmt.Sprintf("cp-a-%d", d): benchCheckpointPSBT(benchTxid(midA), 0),
				fmt.Sprintf("cp-b-%d", d): benchCheckpointPSBT(benchTxid(midB), 0),
			},
		}
		// Mid A -> converge
		offchainRepo.txs[benchTxid(midA)] = &domain.OffchainTx{
			CheckpointTxs: map[string]string{
				fmt.Sprintf("cp-ca-%d", d): benchCheckpointPSBT(benchTxid(converge), 0),
			},
		}
		// Mid B -> converge (same target)
		offchainRepo.txs[benchTxid(midB)] = &domain.OffchainTx{
			CheckpointTxs: map[string]string{
				fmt.Sprintf("cp-cb-%d", d): benchCheckpointPSBT(benchTxid(converge), 0),
			},
		}
	}
	// Terminal
	offchainRepo.txs[benchTxid(3*diamonds)] = &domain.OffchainTx{
		CheckpointTxs: map[string]string{},
	}

	svc := &indexerService{repoManager: &benchRepoManager{
		vtxoRepo: vtxoRepo, offchainRepo: offchainRepo,
	}}
	return svc, domain.Outpoint{Txid: benchTxid(0), VOut: 0}, n
}

func BenchmarkGetVtxoChain(b *testing.B) {
	ctx := context.Background()

	for _, size := range []int{1000, 5000} {
		b.Run(fmt.Sprintf("linear/%d/with_markers", size), func(b *testing.B) {
			svc, start := buildLinearChain(size, true)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resp, err := svc.GetVtxoChain(ctx, "", start, nil, "")
				if err != nil {
					b.Fatal(err)
				}
				// Sanity: (n-1)*2 + 1 = 2n-1 items (ark + checkpoint per non-terminal, ark for terminal).
				if len(resp.Chain) != 2*size-1 {
					b.Fatalf("expected %d chain items, got %d", 2*size-1, len(resp.Chain))
				}
			}
		})

		b.Run(fmt.Sprintf("linear/%d/without_markers", size), func(b *testing.B) {
			svc, start := buildLinearChain(size, false)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resp, err := svc.GetVtxoChain(ctx, "", start, nil, "")
				if err != nil {
					b.Fatal(err)
				}
				if len(resp.Chain) != 2*size-1 {
					b.Fatalf("expected %d chain items, got %d", 2*size-1, len(resp.Chain))
				}
			}
		})
	}

	b.Run("fanout/depth10_2047_vtxos", func(b *testing.B) {
		svc, start, n := buildFanoutTree(10)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resp, err := svc.GetVtxoChain(ctx, "", start, nil, "")
			if err != nil {
				b.Fatal(err)
			}
			// Internal nodes: 2^depth - 1 = 1023, each emits ark + 2 checkpoints = 3 items.
			// Leaves: 2^depth = 1024, each emits 1 ark item.
			// Total: 1023*3 + 1024 = 4093.
			internalNodes := (1 << 10) - 1
			leaves := 1 << 10
			expected := internalNodes*3 + leaves
			if len(resp.Chain) != expected {
				b.Fatalf("expected %d chain items, got %d (n=%d)", expected, len(resp.Chain), n)
			}
		}
	})

	b.Run("diamond/500_pairs", func(b *testing.B) {
		svc, start, _ := buildDiamondChain(500)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resp, err := svc.GetVtxoChain(ctx, "", start, nil, "")
			if err != nil {
				b.Fatal(err)
			}
			// Each diamond's fan-out: ark + 2 checkpoints = 3 items.
			// Each mid node: ark + 1 checkpoint = 2 items.
			// Terminal: 1 ark item.
			// Per diamond: 3 + 2 + 2 = 7 items.
			// Total: 7*diamonds + 1.
			expected := 7*500 + 1
			if len(resp.Chain) != expected {
				b.Fatalf("expected %d chain items, got %d", expected, len(resp.Chain))
			}
		}
	})
}

// BenchmarkCheckpointPSBTParse measures the raw cost of PSBT base64
// decode + parse, which dominates GetVtxoChain runtime.
func BenchmarkCheckpointPSBTParse(b *testing.B) {
	encoded := benchCheckpointPSBT(benchTxid(1), 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := psbt.NewFromRawBytes(strings.NewReader(encoded), true)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// countingOffchainTxRepo wraps benchOffchainTxRepo and counts calls.
type countingOffchainTxRepo struct {
	inner          *benchOffchainTxRepo
	singleCalls    atomic.Int64
	bulkCalls      atomic.Int64
	latencyPerCall time.Duration
}

func (r *countingOffchainTxRepo) GetOffchainTx(
	ctx context.Context, txid string,
) (*domain.OffchainTx, error) {
	r.singleCalls.Add(1)
	if r.latencyPerCall > 0 {
		time.Sleep(r.latencyPerCall)
	}
	return r.inner.GetOffchainTx(ctx, txid)
}

func (r *countingOffchainTxRepo) GetOffchainTxsByTxids(
	ctx context.Context, txids []string,
) ([]*domain.OffchainTx, error) {
	r.bulkCalls.Add(1)
	if r.latencyPerCall > 0 {
		time.Sleep(r.latencyPerCall) // one round-trip regardless of batch size
	}
	return r.inner.GetOffchainTxsByTxids(ctx, txids)
}

func (r *countingOffchainTxRepo) AddOrUpdateOffchainTx(
	_ context.Context, _ *domain.OffchainTx,
) error {
	return nil
}

func (r *countingOffchainTxRepo) Close() {}

func (r *countingOffchainTxRepo) reset() {
	r.singleCalls.Store(0)
	r.bulkCalls.Store(0)
}

// noBulkOffchainTxRepo is like benchOffchainTxRepo but GetOffchainTxsByTxids
// always returns empty, forcing the fallback to individual GetOffchainTx calls.
// This simulates the pre-optimization behavior.
type noBulkOffchainTxRepo struct {
	countingOffchainTxRepo
}

func (r *noBulkOffchainTxRepo) GetOffchainTxsByTxids(
	_ context.Context, _ []string,
) ([]*domain.OffchainTx, error) {
	r.bulkCalls.Add(1)
	return []*domain.OffchainTx{}, nil
}

// TestBulkOffchainTxReducesDBCalls verifies that the bulk prefetch reduces the
// number of DB round-trips. Uses a fanout tree where each iteration processes
// multiple VTXOs — bulk fetches all offchain txs in one call per iteration
// instead of one call per VTXO.
func TestBulkOffchainTxReducesDBCalls(t *testing.T) {
	const depth = 8 // 2^9 - 1 = 511 VTXOs
	ctx := context.Background()

	// Build fanout tree data (reuse the helper's repo setup).
	n := (1 << (depth + 1)) - 1
	vtxoRepo := &benchVtxoRepo{vtxos: make(map[string]domain.Vtxo, n)}
	innerRepo := &benchOffchainTxRepo{txs: make(map[string]*domain.OffchainTx, n)}

	for i := 0; i < n; i++ {
		tid := benchTxid(i)
		vtxoRepo.vtxos[fmt.Sprintf("%s:0", tid)] = domain.Vtxo{
			Outpoint:     domain.Outpoint{Txid: tid, VOut: 0},
			Preconfirmed: true,
			ExpiresAt:    int64(1000 + i),
		}
		left := 2*i + 1
		right := 2*i + 2
		if left < n && right < n {
			innerRepo.txs[tid] = &domain.OffchainTx{
				ArkTxid: tid,
				CheckpointTxs: map[string]string{
					fmt.Sprintf("cp-l-%d", i): benchCheckpointPSBT(benchTxid(left), 0),
					fmt.Sprintf("cp-r-%d", i): benchCheckpointPSBT(benchTxid(right), 0),
				},
			}
		} else {
			innerRepo.txs[tid] = &domain.OffchainTx{
				ArkTxid:       tid,
				CheckpointTxs: map[string]string{},
			}
		}
	}

	start := Outpoint{Txid: benchTxid(0), VOut: 0}

	// With bulk fetch (current behavior).
	bulkRepo := &countingOffchainTxRepo{inner: innerRepo}
	svc := &indexerService{repoManager: &benchRepoManager{
		vtxoRepo: vtxoRepo, offchainRepo: bulkRepo,
	}}
	resp, err := svc.GetVtxoChain(ctx, "", start, nil, "")
	require.NoError(t, err)

	bulkSingle := bulkRepo.singleCalls.Load()
	bulkBulk := bulkRepo.bulkCalls.Load()

	// Without bulk fetch (simulated pre-optimization: bulk returns empty).
	noBulkRepo := &noBulkOffchainTxRepo{countingOffchainTxRepo{inner: innerRepo}}
	svc2 := &indexerService{repoManager: &benchRepoManager{
		vtxoRepo: vtxoRepo, offchainRepo: noBulkRepo,
	}}
	resp2, err := svc2.GetVtxoChain(ctx, "", start, nil, "")
	require.NoError(t, err)
	require.Equal(t, len(resp.Chain), len(resp2.Chain))

	noBulkSingle := noBulkRepo.singleCalls.Load()

	t.Logf("fanout tree: depth=%d, %d VTXOs", depth, n)
	t.Logf("WITH bulk:    %d bulk calls, %d individual calls (total round-trips: %d)",
		bulkBulk, bulkSingle, bulkBulk+bulkSingle)
	t.Logf("WITHOUT bulk: %d individual calls (total round-trips: %d)",
		noBulkSingle, noBulkSingle)

	// With bulk fetch, individual calls should be 0 (all served from cache).
	require.Zero(t, bulkSingle, "bulk prefetch should eliminate individual GetOffchainTx calls")
	// Bulk calls = depth+1 iterations (one per tree level), much fewer than N VTXOs.
	require.LessOrEqual(t, bulkBulk, int64(depth+1),
		"bulk calls should equal tree depth (one per iteration)")
	// Without bulk, individual calls == N (one per preconfirmed VTXO).
	require.Equal(t, int64(n), noBulkSingle,
		"without bulk, every VTXO triggers an individual call")
}

// BenchmarkOffchainTxBulkVsSingle compares chain traversal with and without
// the bulk offchain tx prefetch, using simulated DB latency to make the
// round-trip reduction visible in wall-clock time. Uses a fanout tree
// (depth 8, 511 VTXOs) where each iteration processes an exponentially
// growing number of VTXOs — the bulk path does 9 round-trips vs 511
// individual calls without it.
func BenchmarkOffchainTxBulkVsSingle(b *testing.B) {
	const depth = 8
	const simulatedLatency = 50 * time.Microsecond

	n := (1 << (depth + 1)) - 1
	vtxoRepo := &benchVtxoRepo{vtxos: make(map[string]domain.Vtxo, n)}
	innerRepo := &benchOffchainTxRepo{txs: make(map[string]*domain.OffchainTx, n)}

	for i := 0; i < n; i++ {
		tid := benchTxid(i)
		vtxoRepo.vtxos[fmt.Sprintf("%s:0", tid)] = domain.Vtxo{
			Outpoint:     domain.Outpoint{Txid: tid, VOut: 0},
			Preconfirmed: true,
			ExpiresAt:    int64(1000 + i),
		}
		left := 2*i + 1
		right := 2*i + 2
		if left < n && right < n {
			innerRepo.txs[tid] = &domain.OffchainTx{
				ArkTxid: tid,
				CheckpointTxs: map[string]string{
					fmt.Sprintf("cp-l-%d", i): benchCheckpointPSBT(benchTxid(left), 0),
					fmt.Sprintf("cp-r-%d", i): benchCheckpointPSBT(benchTxid(right), 0),
				},
			}
		} else {
			innerRepo.txs[tid] = &domain.OffchainTx{
				ArkTxid:       tid,
				CheckpointTxs: map[string]string{},
			}
		}
	}

	start := Outpoint{Txid: benchTxid(0), VOut: 0}
	ctx := context.Background()

	b.Run(fmt.Sprintf("bulk_prefetch/%d_vtxos", n), func(b *testing.B) {
		repo := &countingOffchainTxRepo{inner: innerRepo, latencyPerCall: simulatedLatency}
		svc := &indexerService{repoManager: &benchRepoManager{
			vtxoRepo: vtxoRepo, offchainRepo: repo,
		}}
		b.ReportAllocs()
		repo.reset()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := svc.GetVtxoChain(ctx, "", start, nil, "")
			if err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		b.ReportMetric(float64(repo.bulkCalls.Load())/float64(b.N), "bulk_calls/op")
		b.ReportMetric(float64(repo.singleCalls.Load())/float64(b.N), "single_calls/op")
	})

	b.Run(fmt.Sprintf("no_bulk_fallback/%d_vtxos", n), func(b *testing.B) {
		repo := &noBulkOffchainTxRepo{countingOffchainTxRepo{inner: innerRepo, latencyPerCall: simulatedLatency}}
		svc := &indexerService{repoManager: &benchRepoManager{
			vtxoRepo: vtxoRepo, offchainRepo: repo,
		}}
		b.ReportAllocs()
		repo.reset()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := svc.GetVtxoChain(ctx, "", start, nil, "")
			if err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		b.ReportMetric(float64(repo.bulkCalls.Load())/float64(b.N), "bulk_calls/op")
		b.ReportMetric(float64(repo.singleCalls.Load())/float64(b.N), "single_calls/op")
	})
}

// phaseTimings accumulates per-phase wall-clock time and call counts across
// the wrapped repo methods. Safe for concurrent recording.
type phaseTimings struct {
	mu     sync.Mutex
	totals map[string]time.Duration
	counts map[string]int
}

func newPhaseTimings() *phaseTimings {
	return &phaseTimings{
		totals: make(map[string]time.Duration),
		counts: make(map[string]int),
	}
}

func (p *phaseTimings) record(phase string, d time.Duration) {
	p.mu.Lock()
	p.totals[phase] += d
	p.counts[phase]++
	p.mu.Unlock()
}

func (p *phaseTimings) log(t *testing.T, header string, wall time.Duration) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()

	phases := make([]string, 0, len(p.totals))
	var repoTotal time.Duration
	for name, d := range p.totals {
		phases = append(phases, name)
		repoTotal += d
	}
	sort.Strings(phases)

	t.Logf("%s", header)
	t.Logf("  %-32s %12s", "wall clock (GetVtxoChain)", wall)
	for _, name := range phases {
		t.Logf("  %-32s %12s  (%d calls)", name, p.totals[name], p.counts[name])
	}
	t.Logf("  %-32s %12s", "sum of repo phases", repoTotal)
	t.Logf("  %-32s %12s", "other (psbt parse + overhead)", wall-repoTotal)
}

// timingVtxoRepo wraps a VtxoRepository and records per-call latency into a
// shared phaseTimings. An optional per-call latency simulates DB round-trip
// cost so the relative phase times are visible when running against fakes.
type timingVtxoRepo struct {
	domain.VtxoRepository
	inner          domain.VtxoRepository
	t              *phaseTimings
	latencyPerCall time.Duration
}

func (r *timingVtxoRepo) GetVtxos(
	ctx context.Context, outpoints []domain.Outpoint,
) ([]domain.Vtxo, error) {
	start := time.Now()
	defer func() { r.t.record("Vtxos.GetVtxos", time.Since(start)) }()
	if r.latencyPerCall > 0 {
		time.Sleep(r.latencyPerCall)
	}
	return r.inner.GetVtxos(ctx, outpoints)
}

func (r *timingVtxoRepo) Close() {}

type timingMarkerRepo struct {
	domain.MarkerRepository
	inner          domain.MarkerRepository
	t              *phaseTimings
	latencyPerCall time.Duration
}

func (r *timingMarkerRepo) GetVtxoChainByMarkers(
	ctx context.Context, markerIDs []string,
) ([]domain.Vtxo, error) {
	start := time.Now()
	defer func() { r.t.record("Markers.GetVtxoChainByMarkers", time.Since(start)) }()
	if r.latencyPerCall > 0 {
		time.Sleep(r.latencyPerCall)
	}
	return r.inner.GetVtxoChainByMarkers(ctx, markerIDs)
}

func (r *timingMarkerRepo) GetMarkersByIds(
	ctx context.Context, ids []string,
) ([]domain.Marker, error) {
	start := time.Now()
	defer func() { r.t.record("Markers.GetMarkersByIds", time.Since(start)) }()
	if r.latencyPerCall > 0 {
		time.Sleep(r.latencyPerCall)
	}
	return r.inner.GetMarkersByIds(ctx, ids)
}

func (r *timingMarkerRepo) GetVtxosByMarker(
	ctx context.Context, markerID string,
) ([]domain.Vtxo, error) {
	start := time.Now()
	defer func() { r.t.record("Markers.GetVtxosByMarker", time.Since(start)) }()
	if r.latencyPerCall > 0 {
		time.Sleep(r.latencyPerCall)
	}
	return r.inner.GetVtxosByMarker(ctx, markerID)
}

func (r *timingMarkerRepo) Close() {}

type timingOffchainTxRepo struct {
	domain.OffchainTxRepository
	inner          domain.OffchainTxRepository
	t              *phaseTimings
	latencyPerCall time.Duration
}

func (r *timingOffchainTxRepo) GetOffchainTx(
	ctx context.Context, txid string,
) (*domain.OffchainTx, error) {
	start := time.Now()
	defer func() { r.t.record("OffchainTxs.GetOffchainTx", time.Since(start)) }()
	if r.latencyPerCall > 0 {
		time.Sleep(r.latencyPerCall)
	}
	return r.inner.GetOffchainTx(ctx, txid)
}

func (r *timingOffchainTxRepo) GetOffchainTxsByTxids(
	ctx context.Context, txids []string,
) ([]*domain.OffchainTx, error) {
	start := time.Now()
	defer func() { r.t.record("OffchainTxs.GetOffchainTxsByTxids", time.Since(start)) }()
	if r.latencyPerCall > 0 {
		time.Sleep(r.latencyPerCall)
	}
	return r.inner.GetOffchainTxsByTxids(ctx, txids)
}

func (r *timingOffchainTxRepo) AddOrUpdateOffchainTx(
	_ context.Context, _ *domain.OffchainTx,
) error {
	return nil
}

func (r *timingOffchainTxRepo) Close() {}

// TestVtxoChainTimingBreakdown builds a deep linear chain and runs
// GetVtxoChain against it with timing-decorated repos, logging a per-phase
// wall-clock breakdown. This is the in-process replacement for the server-side
// timing log that previously lived in walkVtxoChain.
//
// The repos use an in-memory backing store and inject a fixed per-call
// simulatedLatency via time.Sleep, so the absolute numbers in the breakdown
// do NOT reflect real DB cost — they are only meaningful as relative phase
// proportions under a uniform latency assumption.
//
// Run with:
//
//	go test -v -run TestVtxoChainTimingBreakdown ./internal/core/application/...
func TestVtxoChainTimingBreakdown(t *testing.T) {
	const (
		chainLen         = 10000
		simulatedLatency = 50 * time.Microsecond
	)

	ctx := context.Background()

	// Reuse buildLinearChain to get the same data layout the perf test produces,
	// then swap its repo manager for a timing-decorated one.
	svc, start := buildLinearChain(chainLen, true)
	inner := svc.repoManager.(*benchRepoManager)

	timings := newPhaseTimings()
	svc.repoManager = &wrappedRepoManager{
		vtxos: &timingVtxoRepo{
			inner: inner.vtxoRepo, t: timings, latencyPerCall: simulatedLatency,
		},
		markers: &timingMarkerRepo{
			inner: inner.markerRepo, t: timings, latencyPerCall: simulatedLatency,
		},
		offchainTxs: &timingOffchainTxRepo{
			inner: inner.offchainRepo, t: timings, latencyPerCall: simulatedLatency,
		},
	}

	wallStart := time.Now()
	resp, err := svc.GetVtxoChain(ctx, "", start, nil, "")
	wall := time.Since(wallStart)
	require.NoError(t, err)
	require.Equal(t, 2*chainLen-1, len(resp.Chain))

	timings.log(t, fmt.Sprintf(
		"GetVtxoChain timing breakdown: linear chain n=%d, simulated repo latency=%s",
		chainLen, simulatedLatency,
	), wall)
}

// wrappedRepoManager is a minimal RepoManager that exposes only the repos
// walkVtxoChain touches. Unwired accessors panic with a descriptive message
// instead of returning nil, so an accidental dependency on one of them
// surfaces as a clear failure rather than a nil-pointer dereference.
type wrappedRepoManager struct {
	vtxos       domain.VtxoRepository
	markers     domain.MarkerRepository
	offchainTxs domain.OffchainTxRepository
}

func (m *wrappedRepoManager) Events() domain.EventRepository { panic("Events: not wired") }
func (m *wrappedRepoManager) Rounds() domain.RoundRepository { panic("Rounds: not wired") }
func (m *wrappedRepoManager) Vtxos() domain.VtxoRepository   { return m.vtxos }
func (m *wrappedRepoManager) Markers() domain.MarkerRepository {
	return m.markers
}
func (m *wrappedRepoManager) ScheduledSession() domain.ScheduledSessionRepo {
	panic("ScheduledSession: not wired")
}
func (m *wrappedRepoManager) OffchainTxs() domain.OffchainTxRepository { return m.offchainTxs }
func (m *wrappedRepoManager) Convictions() domain.ConvictionRepository {
	panic("Convictions: not wired")
}
func (m *wrappedRepoManager) Assets() domain.AssetRepository                        { panic("Assets: not wired") }
func (m *wrappedRepoManager) Fees() domain.FeeRepository                            { panic("Fees: not wired") }
func (m *wrappedRepoManager) RegisterBatchUpdateHandler(func(data domain.Round))    {}
func (m *wrappedRepoManager) RegisterOffchainTxUpdateHandler(func(domain.OffchainTx)) {}
func (m *wrappedRepoManager) Close()                                                {}
