package application

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
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

func (r *benchOffchainTxRepo) Close() {}

type benchRepoManager struct {
	vtxoRepo     *benchVtxoRepo
	markerRepo   *benchMarkerRepo
	offchainRepo *benchOffchainTxRepo
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
func (m *benchRepoManager) Convictions() domain.ConvictionRepository { return nil }
func (m *benchRepoManager) Assets() domain.AssetRepository           { return nil }
func (m *benchRepoManager) Fees() domain.FeeRepository               { return nil }
func (m *benchRepoManager) Close()                                   {}

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
				CheckpointTxs: map[string]string{
					fmt.Sprintf("cp-%d", i): benchCheckpointPSBT(benchTxid(i+1), 0),
				},
			}
		} else {
			offchainRepo.txs[tid] = &domain.OffchainTx{CheckpointTxs: map[string]string{}}
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
