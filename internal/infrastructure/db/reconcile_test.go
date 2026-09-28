package db

import (
	"context"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/stretchr/testify/require"
)

func TestReconcileProjections(t *testing.T) {
	ctx := context.Background()

	// Recording a batch sweep is two writes, the round then the vtxo outpoints,
	// and they are not one transaction. Each case seeds the state a shutdown
	// between them would leave, reopens the service, and checks what startup
	// made of it.
	t.Run("ensureSweptVtxos", func(t *testing.T) {
		t.Run("marks the vtxos a swept batch left behind", func(t *testing.T) {
			dir := t.TempDir()
			svc := newProjectionTestService(t, dir)

			commitmentTxid, outpoints := seedBatch(t, svc, true)
			requireSwept(t, svc, outpoints, false)
			svc.Close()

			// Reopening runs the reconciliation.
			healed := newProjectionTestService(t, dir)
			requireSwept(t, healed, outpoints, true)

			round, err := healed.Rounds().GetRoundWithCommitmentTxid(ctx, commitmentTxid)
			require.NoError(t, err)
			require.True(t, round.Swept, "reconciliation must not disturb the batch itself")
		})

		t.Run("leaves the vtxos of an unswept batch alone", func(t *testing.T) {
			dir := t.TempDir()
			svc := newProjectionTestService(t, dir)

			_, outpoints := seedBatch(t, svc, false)
			svc.Close()

			reopened := newProjectionTestService(t, dir)
			requireSwept(
				t, reopened, outpoints, false,
				"a batch that is not fully swept has vtxos that are legitimately unswept",
			)
		})

		t.Run("is a no-op on a projection that is already consistent", func(t *testing.T) {
			dir := t.TempDir()
			svc := newProjectionTestService(t, dir)

			_, outpoints := seedBatch(t, svc, true)
			require.NoError(t, svc.Markers().SweepVtxoOutpoints(ctx, outpoints, sweptAtFixture))
			requireSwept(t, svc, outpoints, true)
			svc.Close()

			// The swept insert ignores duplicates, so a second pass over an
			// already consistent batch must neither fail nor rewrite anything.
			reopened := newProjectionTestService(t, dir)
			requireSwept(t, reopened, outpoints, true)
		})
	})

	t.Run("GetExpiredButNotSweptRounds", func(t *testing.T) {
		for _, dataStoreType := range []string{"sqlite", "badger"} {
			t.Run(dataStoreType, func(t *testing.T) {
				svc := newTestRepoManager(t, dataStoreType)

				expired, _ := seedBatch(t, svc, false)
				seedBatch(t, svc, true)

				_, sweptOutpoints := seedBatch(t, svc, false)
				require.NoError(t, svc.Markers().SweepVtxoOutpoints(
					ctx, sweptOutpoints, sweptAtFixture,
				))

				_, unrolledOutpoints := seedBatch(t, svc, false)
				require.NoError(t, svc.Vtxos().UnrollVtxos(ctx, unrolledOutpoints[:1]))

				seedBatchExpiringAt(t, svc, false, time.Now().Add(time.Hour).Unix())

				spentBatch, spentOutpoints := seedBatch(t, svc, false)
				spentVtxos := make(map[domain.Outpoint]string, len(spentOutpoints))
				for _, outpoint := range spentOutpoints {
					spentVtxos[outpoint] = randomString(t, 32)
				}
				require.NoError(t, svc.Vtxos().SettleVtxos(ctx, spentVtxos, spentBatch))

				commitmentTxids, err := svc.Rounds().GetExpiredButNotSweptRounds(ctx)
				require.NoError(t, err)
				require.Equal(
					t, []string{expired}, commitmentTxids,
					"swept batches, batches with any unrolled vtxo, and batches with only "+
						"swept, not expired or spent vtxos must be left out",
				)
			})
		}
	})
}

const sweptAtFixture = int64(1767225600)

// seedBatch writes an ended batch carrying two vtxos, with none of them marked
// swept. swept sets the batch's own flag, which is what tells reconciliation
// whether those vtxos should have been marked.
func seedBatch(t *testing.T, svc ports.RepoManager, swept bool) (string, []domain.Outpoint) {
	t.Helper()
	return seedBatchExpiringAt(t, svc, swept, sweptAtFixture)
}

// seedBatchExpiringAt is seedBatch with vtxos that expire at expiresAt.
func seedBatchExpiringAt(
	t *testing.T, svc ports.RepoManager, swept bool, expiresAt int64,
) (string, []domain.Outpoint) {
	t.Helper()
	ctx := context.Background()

	commitmentTxid := randomString(t, 32)
	round := domain.Round{
		Id:                randomString(t, 32),
		StartingTimestamp: sweptAtFixture,
		EndingTimestamp:   sweptAtFixture,
		Stage:             domain.Stage{Code: int(domain.RoundFinalizationStage), Ended: true},
		CommitmentTxid:    commitmentTxid,
		CommitmentTx:      randomTx(t),
		// The batch has to carry a tree: a batch with nothing to sweep is not a
		// batch reconciliation has anything to say about.
		VtxoTree: tree.FlatTxTree{
			{Txid: randomString(t, 32), Tx: randomTx(t)},
		},
		Swept: swept,
	}
	require.NoError(t, svc.Rounds().AddOrUpdateRound(ctx, round))

	vtxos := []domain.Vtxo{
		newBatchVtxo(t, commitmentTxid),
		newBatchVtxo(t, commitmentTxid),
	}
	for i := range vtxos {
		vtxos[i].ExpiresAt = expiresAt
	}
	require.NoError(t, svc.Vtxos().AddVtxos(ctx, vtxos))

	outpoints := make([]domain.Outpoint, 0, len(vtxos))
	for _, v := range vtxos {
		outpoints = append(outpoints, v.Outpoint)
	}
	return commitmentTxid, outpoints
}

func newBatchVtxo(t *testing.T, commitmentTxid string) domain.Vtxo {
	t.Helper()

	return domain.Vtxo{
		Outpoint:           domain.Outpoint{Txid: randomString(t, 32), VOut: 0},
		PubKey:             randomString(t, 32),
		Amount:             1000,
		RootCommitmentTxid: commitmentTxid,
		CommitmentTxids:    []string{commitmentTxid},
		CreatedAt:          sweptAtFixture,
		ExpiresAt:          sweptAtFixture,
	}
}

func requireSwept(
	t *testing.T, svc ports.RepoManager, outpoints []domain.Outpoint, swept bool, msg ...string,
) {
	t.Helper()

	vtxos, err := svc.Vtxos().GetVtxos(context.Background(), outpoints)
	require.NoError(t, err)
	require.Len(t, vtxos, len(outpoints))
	for _, v := range vtxos {
		if len(msg) > 0 {
			require.Equal(t, swept, v.Swept, msg[0])
			continue
		}
		require.Equal(t, swept, v.Swept, "vtxo %s", v.Outpoint)
	}
}

// newTestRepoManager opens a service over a fresh dir with the given data store.
func newTestRepoManager(t *testing.T, dataStoreType string) ports.RepoManager {
	t.Helper()
	dataStoreConfig := []interface{}{t.TempDir()}
	if dataStoreType == "badger" {
		dataStoreConfig = append(dataStoreConfig, nil)
	}
	svc, err := NewService(ServiceConfig{
		EventStoreType:   "badger",
		DataStoreType:    dataStoreType,
		EventStoreConfig: []interface{}{"", nil},
		DataStoreConfig:  dataStoreConfig,
		Settings:         validSettings(t),
	}, nil)
	require.NoError(t, err)
	t.Cleanup(svc.Close)
	return svc
}
