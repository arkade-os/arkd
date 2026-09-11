package db_test

import (
	"context"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/infrastructure/db"
	badgerdb "github.com/arkade-os/arkd/internal/infrastructure/db/badger"
	"github.com/stretchr/testify/require"
)

// RecordCosignedTx is the durable write behind an on-chain cosign. The inputs
// are marked spent with no ark txid, which is what tells an onchain spend from
// an in-Ark one, and the outputs are recorded as pending because nothing arkd
// has only cosigned is spendable yet.
func TestRecordCosignedTx(t *testing.T) {
	for name, repo := range cosignedTxRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			t.Run("marks the inputs spent onchain and adds the outputs pending", func(t *testing.T) {
				in := cosignInput(randomString(32))
				require.NoError(t, repo.AddVtxos(ctx, []domain.Vtxo{in}))

				spendTxid := randomString(32)
				out := cosignOutput(spendTxid, 0)
				require.NoError(t, repo.RecordCosignedTx(
					ctx, spendTxid, []domain.Outpoint{in.Outpoint}, []domain.Vtxo{out},
				))

				got, err := repo.GetVtxos(ctx, []domain.Outpoint{in.Outpoint})
				require.NoError(t, err)
				require.Len(t, got, 1)
				require.True(t, got[0].Spent)
				require.Equal(t, spendTxid, got[0].SpentBy)
				// The discriminator. An in-Ark spend would carry one of these.
				require.Empty(t, got[0].ArkTxid)
				require.Empty(t, got[0].SettledBy)

				got, err = repo.GetVtxos(ctx, []domain.Outpoint{out.Outpoint})
				require.NoError(t, err)
				require.Len(t, got, 1)
				require.Equal(t, domain.VtxoKindOnchainPending, got[0].Kind)
				require.True(t, got[0].IsOnchainKind())
				require.False(t, got[0].HasBatchExpiry())
			})

			// The caller cannot register something as already confirmed, since
			// only the per-transaction lifecycle may promote a pending output.
			t.Run("forces the pending kind whatever the caller asked for", func(t *testing.T) {
				spendTxid := randomString(32)
				out := cosignOutput(spendTxid, 1)
				out.Kind = domain.VtxoKindOnchain

				require.NoError(t, repo.RecordCosignedTx(ctx, spendTxid, nil, []domain.Vtxo{out}))

				got, err := repo.GetVtxos(ctx, []domain.Outpoint{out.Outpoint})
				require.NoError(t, err)
				require.Len(t, got, 1)
				require.Equal(t, domain.VtxoKindOnchainPending, got[0].Kind)
			})

			t.Run("an unknown input does not block the outputs", func(t *testing.T) {
				spendTxid := randomString(32)
				out := cosignOutput(spendTxid, 2)
				missing := domain.Outpoint{Txid: randomString(32), VOut: 7}

				require.NoError(t, repo.RecordCosignedTx(
					ctx, spendTxid, []domain.Outpoint{missing}, []domain.Vtxo{out},
				))

				got, err := repo.GetVtxos(ctx, []domain.Outpoint{out.Outpoint})
				require.NoError(t, err)
				require.Len(t, got, 1)
			})
		})
	}
}

func cosignedTxRepos(t *testing.T) map[string]domain.VtxoRepository {
	t.Helper()

	svc, err := db.NewService(db.ServiceConfig{
		EventStoreType:   "badger",
		DataStoreType:    "sqlite",
		EventStoreConfig: []interface{}{"", nil},
		DataStoreConfig:  []interface{}{t.TempDir()},
		Settings:         validSettings(),
	}, nil)
	require.NoError(t, err)
	t.Cleanup(svc.Close)

	badgerRepo, err := badgerdb.NewVtxoRepository(t.TempDir(), nil)
	require.NoError(t, err)
	t.Cleanup(badgerRepo.Close)

	return map[string]domain.VtxoRepository{
		"sqlite": svc.Vtxos(),
		"badger": badgerRepo,
	}
}

func cosignInput(txid string) domain.Vtxo {
	return domain.Vtxo{
		Outpoint:           domain.Outpoint{Txid: txid, VOut: 0},
		PubKey:             randomString(32),
		Amount:             10_000,
		RootCommitmentTxid: randomString(32),
		CreatedAt:          1_700_000_000,
		ExpiresAt:          2_000_000_000,
	}
}

func cosignOutput(txid string, vout uint32) domain.Vtxo {
	return domain.Vtxo{
		Outpoint:  domain.Outpoint{Txid: txid, VOut: vout},
		PubKey:    randomString(32),
		Amount:    9_000,
		CreatedAt: 1_700_000_000,
	}
}
