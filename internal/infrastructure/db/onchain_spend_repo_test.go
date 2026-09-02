package db_test

import (
	"context"
	"os"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db"
	badgerdb "github.com/arkade-os/arkd/internal/infrastructure/db/badger"
	pgdb "github.com/arkade-os/arkd/internal/infrastructure/db/postgres"
	"github.com/stretchr/testify/require"
)

func TestOnchainSpendRepository(t *testing.T) {
	ctx := context.Background()

	for name, repo := range newOnchainSpendRepos(t) {
		t.Run(name, func(t *testing.T) {
			t.Run("marks, re-points and retracts an unrolled vtxo", func(t *testing.T) {
				vtxo := onchainSpendVtxo(randomString(32))
				require.NoError(t, repo.AddVtxos(ctx, []domain.Vtxo{vtxo}))
				require.NoError(t, repo.UnrollVtxos(ctx, []domain.Outpoint{vtxo.Outpoint}))

				require.NoError(t, repo.MarkVtxosOnchainSpent(
					ctx, map[domain.Outpoint]string{vtxo.Outpoint: "spendingtxid"},
				))

				got := getOnchainSpendVtxo(t, repo, vtxo.Outpoint)
				require.True(t, got.Spent)
				require.Equal(t, "spendingtxid", got.SpentBy)
				require.Empty(t, got.ArkTxid, "an onchain spend must leave ark_txid unset")
				require.True(t, got.IsOnchainSpent())

				// RBF: the spender is replaced, so spent_by must follow it even
				// though the vtxo is already marked spent.
				require.NoError(t, repo.MarkVtxosOnchainSpent(
					ctx, map[domain.Outpoint]string{vtxo.Outpoint: "replacementtxid"},
				))
				got = getOnchainSpendVtxo(t, repo, vtxo.Outpoint)
				require.True(t, got.Spent)
				require.Equal(t, "replacementtxid", got.SpentBy)

				// The replacement never confirms and drops out of the mempool.
				require.NoError(t, repo.UnmarkVtxosOnchainSpent(
					ctx, []domain.Outpoint{vtxo.Outpoint},
				))
				got = getOnchainSpendVtxo(t, repo, vtxo.Outpoint)
				require.False(t, got.Spent, "a retracted spend must leave the vtxo spendable")
				require.Empty(t, got.SpentBy)
				require.True(t, got.Unrolled, "retracting a spend must not un-unroll the vtxo")
			})

			// The guard that makes reusing spent/spent_by safe. If an offchain
			// spend lands first, the onchain writer must not overwrite it: doing
			// so would clear ark_txid and hide a real fraud case from the sweeper.
			t.Run("never clobbers a vtxo spent offchain", func(t *testing.T) {
				vtxo := onchainSpendVtxo(randomString(32))
				require.NoError(t, repo.AddVtxos(ctx, []domain.Vtxo{vtxo}))
				require.NoError(t, repo.UnrollVtxos(ctx, []domain.Outpoint{vtxo.Outpoint}))
				require.NoError(t, repo.SpendVtxos(
					ctx, map[domain.Outpoint]string{vtxo.Outpoint: "checkpointtxid"}, "arktxid",
				))

				require.NoError(t, repo.MarkVtxosOnchainSpent(
					ctx, map[domain.Outpoint]string{vtxo.Outpoint: "spendingtxid"},
				))

				got := getOnchainSpendVtxo(t, repo, vtxo.Outpoint)
				require.Equal(t, "checkpointtxid", got.SpentBy)
				require.Equal(t, "arktxid", got.ArkTxid)
				require.False(t, got.IsOnchainSpent())

				// Retraction is scoped the same way: an offchain spend can never
				// be undone by the onchain reconciler.
				require.NoError(t, repo.UnmarkVtxosOnchainSpent(
					ctx, []domain.Outpoint{vtxo.Outpoint},
				))
				got = getOnchainSpendVtxo(t, repo, vtxo.Outpoint)
				require.True(t, got.Spent)
				require.Equal(t, "checkpointtxid", got.SpentBy)
			})

			// Only an unrolled vtxo has an onchain output to spend.
			t.Run("ignores a vtxo that was never unrolled", func(t *testing.T) {
				vtxo := onchainSpendVtxo(randomString(32))
				require.NoError(t, repo.AddVtxos(ctx, []domain.Vtxo{vtxo}))

				require.NoError(t, repo.MarkVtxosOnchainSpent(
					ctx, map[domain.Outpoint]string{vtxo.Outpoint: "spendingtxid"},
				))

				got := getOnchainSpendVtxo(t, repo, vtxo.Outpoint)
				require.False(t, got.Spent)
				require.Empty(t, got.SpentBy)
			})

			// The sweeper resolves SpentBy as a checkpoint tx, so an onchain
			// spend must stay out of its candidate set while an in-Ark spend that
			// was later unrolled must stay in it.
			t.Run("sweepable set excludes onchain spends only", func(t *testing.T) {
				onchain := onchainSpendVtxo(randomString(32))
				offchain := onchainSpendVtxo(randomString(32))
				require.NoError(t, repo.AddVtxos(ctx, []domain.Vtxo{onchain, offchain}))
				require.NoError(t, repo.UnrollVtxos(ctx, []domain.Outpoint{
					onchain.Outpoint, offchain.Outpoint,
				}))
				require.NoError(t, repo.SpendVtxos(
					ctx,
					map[domain.Outpoint]string{offchain.Outpoint: "checkpointtxid"},
					"arktxid",
				))
				require.NoError(t, repo.MarkVtxosOnchainSpent(
					ctx, map[domain.Outpoint]string{onchain.Outpoint: "spendingtxid"},
				))

				sweepable, err := repo.GetAllSweepableUnrolledVtxos(ctx)
				require.NoError(t, err)

				require.True(t, containsOutpoint(sweepable, offchain.Outpoint),
					"an in-Ark spend that was unrolled is still the sweeper's job")
				require.False(t, containsOutpoint(sweepable, onchain.Outpoint),
					"an onchain spend has no checkpoint tx for the sweeper to resolve")
			})

			t.Run("candidate selectors partition by onchain spend state", func(t *testing.T) {
				unspent := onchainSpendVtxo(randomString(32))
				spent := onchainSpendVtxo(randomString(32))
				require.NoError(t, repo.AddVtxos(ctx, []domain.Vtxo{unspent, spent}))
				require.NoError(t, repo.UnrollVtxos(ctx, []domain.Outpoint{
					unspent.Outpoint, spent.Outpoint,
				}))
				require.NoError(t, repo.MarkVtxosOnchainSpent(
					ctx, map[domain.Outpoint]string{spent.Outpoint: "spendingtxid"},
				))

				candidates, err := repo.GetUnrolledUnspentVtxos(ctx)
				require.NoError(t, err)
				require.True(t, containsOutpoint(candidates, unspent.Outpoint))
				require.False(t, containsOutpoint(candidates, spent.Outpoint))

				recorded, err := repo.GetOnchainSpentVtxos(ctx)
				require.NoError(t, err)
				require.True(t, containsOutpoint(recorded, spent.Outpoint))
				require.False(t, containsOutpoint(recorded, unspent.Outpoint))
			})

			// A rejoined unrolled vtxo is spent onchain by the commitment tx
			// itself, and that spend can be noticed before the round is
			// projected. The settlement is the authoritative record and must
			// override the onchain-spend mark rather than be skipped by it.
			t.Run("settlement overrides an earlier onchain spend mark", func(t *testing.T) {
				vtxo := onchainSpendVtxo(randomString(32))
				require.NoError(t, repo.AddVtxos(ctx, []domain.Vtxo{vtxo}))
				require.NoError(t, repo.UnrollVtxos(ctx, []domain.Outpoint{vtxo.Outpoint}))
				require.NoError(t, repo.MarkVtxosOnchainSpent(
					ctx, map[domain.Outpoint]string{vtxo.Outpoint: "commitmenttxid"},
				))

				require.NoError(t, repo.SettleVtxos(
					ctx, map[domain.Outpoint]string{vtxo.Outpoint: "commitmenttxid"},
					"commitmenttxid",
				))

				got := getOnchainSpendVtxo(t, repo, vtxo.Outpoint)
				require.True(t, got.Spent)
				require.Equal(t, "commitmenttxid", got.SettledBy)
				require.False(t, got.IsOnchainSpent())

				// Once settled, the reconciler can no longer touch it.
				require.NoError(t, repo.UnmarkVtxosOnchainSpent(
					ctx, []domain.Outpoint{vtxo.Outpoint},
				))
				got = getOnchainSpendVtxo(t, repo, vtxo.Outpoint)
				require.True(t, got.Spent)
				require.Equal(t, "commitmenttxid", got.SettledBy)
			})

			// Exercises a batch larger than the badger
			// transaction chunk size. badger rejects an oversized transaction with
			// ErrTxnTooBig and Discard then drops every buffered write, so an unbounded
			// batch would lose the whole set rather than part of it. The reconciler's first
			// pass after a restart is unwindowed by design and can carry exactly this kind
			// of backlog.
			t.Run("records and retracts a batch larger than a badger chunk", func(t *testing.T) {
				const count = 450 // spans more than two chunks of 200
				vtxos := make([]domain.Vtxo, 0, count)
				spentBy := make(map[domain.Outpoint]string, count)
				outpoints := make([]domain.Outpoint, 0, count)
				for i := 0; i < count; i++ {
					vtxo := onchainSpendVtxo(randomString(32))
					vtxos = append(vtxos, vtxo)
					outpoints = append(outpoints, vtxo.Outpoint)
					spentBy[vtxo.Outpoint] = "spendingtxid"
				}

				require.NoError(t, repo.AddVtxos(ctx, vtxos))
				require.NoError(t, repo.UnrollVtxos(ctx, outpoints))
				require.NoError(t, repo.MarkVtxosOnchainSpent(ctx, spentBy))

				recorded, err := repo.GetOnchainSpentVtxos(ctx)
				require.NoError(t, err)
				for _, outpoint := range outpoints {
					require.True(t, containsOutpoint(recorded, outpoint),
						"every vtxo in an oversized batch must be recorded")
				}

				require.NoError(t, repo.UnmarkVtxosOnchainSpent(ctx, outpoints))
				for _, outpoint := range outpoints {
					require.False(t, getOnchainSpendVtxo(t, repo, outpoint).Spent)
				}
			})
		})
	}
}

// --- fixtures ---

// newOnchainSpendRepos builds one VtxoRepository per supported backend. The
// onchain-spend statements are guarded by predicates that each backend expresses
// differently (SQL WHERE clauses in sqlite/postgres, badgerhold query terms and
// a read-modify-write in badger), so they have to be pinned on all three rather
// than on whichever one is convenient.
func newOnchainSpendRepos(t *testing.T) map[string]domain.VtxoRepository {
	t.Helper()

	configs := map[string]db.ServiceConfig{
		"sqlite": {
			EventStoreType:   "badger",
			DataStoreType:    "sqlite",
			EventStoreConfig: []interface{}{"", nil},
			DataStoreConfig:  []interface{}{t.TempDir()},
			Settings:         validSettings(),
		},
		// Dedicated databases, auto-created on first run. TestService seeds and
		// then mutates the settings row of the shared projection database, so
		// sharing it here would make the two tests fail depending on which ran
		// first.
		"postgres": {
			EventStoreType: "postgres",
			DataStoreType:  "postgres",
			EventStoreConfig: []interface{}{
				"postgresql://root:secret@127.0.0.1:5432/event_onchain_spend?sslmode=disable",
				true, pgdb.ConnectionConfig{},
			},
			DataStoreConfig: []interface{}{
				"postgresql://root:secret@127.0.0.1:5432/projection_onchain_spend?sslmode=disable",
				true, pgdb.ConnectionConfig{},
			},
			Settings: validSettings(),
		},
	}

	repos := make(map[string]domain.VtxoRepository, len(configs)+1)
	for name, config := range configs {
		svc, err := db.NewService(config, nil)
		require.NoError(t, err, "failed to open %s repo manager", name)
		t.Cleanup(svc.Close)
		repos[name] = svc.Vtxos()
	}

	// badger is built from the repository constructor rather than a full
	// RepoManager. Opening a second badger data store in one process after the
	// first is closed fails with "DB Closed" — reproducible on the base commit
	// with `go test -count=2 -run TestRoundSummariesBadger`, so it predates this
	// change. Standing up a RepoManager here would make that latent bug fail an
	// unrelated test in this package, and nothing here needs one.
	badgerRepo, err := badgerdb.NewVtxoRepository(badgerTempDir(t), nil)
	require.NoError(t, err, "failed to open badger vtxo repository")
	t.Cleanup(badgerRepo.Close)
	repos["badger"] = badgerRepo

	return repos
}

// badgerTempDir is t.TempDir with best-effort removal. badger keeps its value
// log mapped for a moment after Close, and on Windows t.TempDir's cleanup fails
// the test when the unlink loses that race. The failure says nothing about the
// code under test, so the directory is removed on a best-effort basis instead.
func badgerTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "onchain-spend-badger-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		//nolint:errcheck
		_ = os.RemoveAll(dir)
	})
	return dir
}

func onchainSpendVtxo(txid string) domain.Vtxo {
	return domain.Vtxo{
		Outpoint:           domain.Outpoint{Txid: txid, VOut: 0},
		PubKey:             "187396153c4cf84a4a9d32cba6a8a64f6869ba986d85c4e6c763f3564ed781af",
		Amount:             187592,
		CommitmentTxids:    []string{"9246e57242e458015cefe06511b841f1b9bf6431194b4af371e3528af67554ae"},
		RootCommitmentTxid: "9246e57242e458015cefe06511b841f1b9bf6431194b4af371e3528af67554ae",
		ExpiresAt:          1785690467,
		CreatedAt:          1783098211,
	}
}

func getOnchainSpendVtxo(
	t *testing.T, repo domain.VtxoRepository, outpoint domain.Outpoint,
) domain.Vtxo {
	t.Helper()
	vtxos, err := repo.GetVtxos(context.Background(), []domain.Outpoint{outpoint})
	require.NoError(t, err)
	require.Len(t, vtxos, 1)
	return vtxos[0]
}

func containsOutpoint(vtxos []domain.Vtxo, outpoint domain.Outpoint) bool {
	for _, vtxo := range vtxos {
		if vtxo.Outpoint == outpoint {
			return true
		}
	}
	return false
}
