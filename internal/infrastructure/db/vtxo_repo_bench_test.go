package db_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/internal/infrastructure/db"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/google/uuid"
)

// Benchmark sizes for the vtxo-pubkey lookup. The per-txid variant (the
// pre-fix N+1 pattern) is intentionally capped lower than the bulk
// variant because a single iteration of the per-txid loop fans out into
// one DB call per round, so 10 000 rounds takes several minutes per
// iteration. The bulk variant collapses that to two calls and can
// comfortably handle the larger sizes.
var (
	perTxidSizes = []int{10, 100, 1000}
	bulkSizes    = []int{10, 100, 1000, 5000}
)

// vtxosPerRound is the per-round vtxo fan-out we seed. Total scripts in
// the seeded DB is N * vtxosPerRound.
const vtxosPerRound = 10

// newBenchService spins up a fresh sqlite+badger RepoManager rooted at a
// throwaway temp dir. Each benchmark sub-run gets its own DB so iteration
// counts are not biased by warm caches across sizes.
func newBenchService(tb testing.TB) ports.RepoManager {
	tb.Helper()
	dir := tb.TempDir()
	svc, err := db.NewService(db.ServiceConfig{
		EventStoreType:   "badger",
		DataStoreType:    "sqlite",
		EventStoreConfig: []interface{}{"", nil},
		DataStoreConfig:  []interface{}{dir},
	}, nil)
	if err != nil {
		tb.Fatalf("open db: %s", err)
	}
	tb.Cleanup(svc.Close)
	return svc
}

// seedSweepableRounds inserts numRounds sweepable Round records and
// numRounds*vtxosPerRound vtxo rows. Returns the list of commitment txids
// that GetSweepableRounds will subsequently return so callers do not have
// to re-query for them on the hot path.
func seedSweepableRounds(tb testing.TB, svc ports.RepoManager, numRounds int) []string {
	tb.Helper()
	ctx := context.Background()
	commitmentTxids := make([]string, 0, numRounds)
	now := time.Now().Unix()

	for r := 0; r < numRounds; r++ {
		commitmentTxid := randomHex(tb, 32)
		round := domain.Round{
			Id:                 uuid.New().String(),
			StartingTimestamp:  now - 60,
			EndingTimestamp:    now,
			Stage:              domain.Stage{Code: int(domain.RoundFinalizationStage), Ended: true},
			Intents:            map[string]domain.Intent{},
			CommitmentTxid:     commitmentTxid,
			CommitmentTx:       "bench-commitment-tx",
			Version:            1,
			VtxoTreeExpiration: 100,
			// One synthetic 'tree' tx is enough to satisfy the EXISTS
			// clause in SelectSweepableRounds.
			VtxoTree: tree.FlatTxTree{
				tree.TxTreeNode{Txid: randomHex(tb, 32), Tx: "bench-tree-tx"},
			},
		}
		if err := svc.Rounds().AddOrUpdateRound(ctx, round); err != nil {
			tb.Fatalf("AddOrUpdateRound[%d]: %s", r, err)
		}

		vtxos := make([]domain.Vtxo, 0, vtxosPerRound)
		for v := 0; v < vtxosPerRound; v++ {
			vtxos = append(vtxos, domain.Vtxo{
				Outpoint:           domain.Outpoint{Txid: randomHex(tb, 32), VOut: uint32(v)},
				Amount:             1000,
				PubKey:             randomXOnlyPubKey(tb),
				CommitmentTxids:    []string{commitmentTxid},
				RootCommitmentTxid: commitmentTxid,
				CreatedAt:          now,
				ExpiresAt:          now + 3600,
			})
		}
		if err := svc.Vtxos().AddVtxos(ctx, vtxos); err != nil {
			tb.Fatalf("AddVtxos[%d]: %s", r, err)
		}
		commitmentTxids = append(commitmentTxids, commitmentTxid)
	}

	return commitmentTxids
}

// BenchmarkGetVtxoPubKeysByCommitmentTxid_PerTxidLoop reproduces the
// pre-fix code path: for each sweepable round, issue a singular
// per-commitment-txid query and union the results. This is what
// restoreWatchingVtxos used to do.
func BenchmarkGetVtxoPubKeysByCommitmentTxid_PerTxidLoop(b *testing.B) {
	for _, n := range perTxidSizes {
		b.Run(fmt.Sprintf("rounds=%d", n), func(b *testing.B) {
			svc := newBenchService(b)
			txids := seedSweepableRounds(b, svc, n)
			ctx := context.Background()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				total := 0
				for _, t := range txids {
					keys, err := svc.Vtxos().
						GetVtxoPubKeysByCommitmentTxid(ctx, t, 0)
					if err != nil {
						b.Fatalf("singular: %s", err)
					}
					total += len(keys)
				}
				if total == 0 {
					b.Fatalf("expected non-zero keys at rounds=%d", n)
				}
			}
		})
	}
}

// BenchmarkGetVtxoPubKeysByCommitmentTxids_Bulk exercises the bulk
// variant that replaces the loop above. The bulk method runs one SQL
// query regardless of how many commitment txids it is given.
func BenchmarkGetVtxoPubKeysByCommitmentTxids_Bulk(b *testing.B) {
	for _, n := range bulkSizes {
		b.Run(fmt.Sprintf("rounds=%d", n), func(b *testing.B) {
			svc := newBenchService(b)
			txids := seedSweepableRounds(b, svc, n)
			ctx := context.Background()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				keys, err := svc.Vtxos().
					GetVtxoPubKeysByCommitmentTxids(ctx, txids, 0)
				if err != nil {
					b.Fatalf("bulk: %s", err)
				}
				if len(keys) == 0 {
					b.Fatalf("expected non-zero keys at rounds=%d", n)
				}
			}
		})
	}
}

// TestVtxoPubKeysBulkMatchesLoop asserts that the bulk query returns the
// same deduplicated pubkey set as the singular per-txid loop, so the
// benchmark comparison is apples to apples. Uses a modest size since it
// is part of the standard test suite and runs on every CI cycle.
func TestVtxoPubKeysBulkMatchesLoop(t *testing.T) {
	svc := newBenchService(t)
	txids := seedSweepableRounds(t, svc, 50)

	ctx := context.Background()
	loopUnion := make(map[string]struct{})
	for _, txid := range txids {
		keys, err := svc.Vtxos().GetVtxoPubKeysByCommitmentTxid(ctx, txid, 0)
		if err != nil {
			t.Fatalf("singular: %s", err)
		}
		for _, k := range keys {
			loopUnion[k] = struct{}{}
		}
	}

	bulk, err := svc.Vtxos().GetVtxoPubKeysByCommitmentTxids(ctx, txids, 0)
	if err != nil {
		t.Fatalf("bulk: %s", err)
	}
	bulkSet := make(map[string]struct{}, len(bulk))
	for _, k := range bulk {
		bulkSet[k] = struct{}{}
	}

	if len(bulkSet) != len(loopUnion) {
		t.Fatalf("bulk set size=%d loop union size=%d", len(bulkSet), len(loopUnion))
	}
	for k := range loopUnion {
		if _, ok := bulkSet[k]; !ok {
			t.Fatalf("bulk missing pubkey %s", k)
		}
	}
}

// randomHex returns 2*n hex characters.
func randomHex(tb testing.TB, n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		tb.Fatalf("rand: %s", err)
	}
	return hex.EncodeToString(buf)
}

// randomXOnlyPubKey returns a fresh schnorr x-only pubkey as a 64-char
// hex string. Each vtxo gets a unique pubkey so the bulk DISTINCT path
// is exercised non-trivially.
func randomXOnlyPubKey(tb testing.TB) string {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		tb.Fatalf("priv: %s", err)
	}
	return hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey()))
}
