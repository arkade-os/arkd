package badgerdb

import (
	"context"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

// The filter and paging contract is covered by the shared suite in the db
// package. These pin the two things only badger does in Go: it indexes a slice
// with the page, so a bad page must not panic, and it sorts in memory, so the
// ordering must be total or two pages can overlap.
func TestVtxoPage(t *testing.T) {
	ctx := context.Background()

	t.Run("nonsensical page does not panic", func(t *testing.T) {
		repo := seedPageVtxos(t, "pagepubkey", time.Now().Unix())
		filter := domain.VtxoFilter{Pubkeys: []string{"pagepubkey"}}

		t.Run("offset past the end is empty", func(t *testing.T) {
			for _, page := range []domain.Page{
				{Limit: 10, Offset: 1_000_000},
				{Limit: 100, Offset: 2147483647},
			} {
				got, total, err := repo.GetVtxosWithPubKeys(ctx, filter, page)
				require.NoError(t, err)
				require.Empty(t, got)
				require.Greater(t, total, int32(0), "the total is still reported")
			}
		})

		t.Run("non positive limit reads the whole set", func(t *testing.T) {
			all, total, err := repo.GetVtxosWithPubKeys(ctx, filter, domain.Page{Limit: 100})
			require.NoError(t, err)
			for _, page := range []domain.Page{
				{Limit: 0, Offset: 0},
				{Limit: -1, Offset: 0},
			} {
				got, gotTotal, err := repo.GetVtxosWithPubKeys(ctx, filter, page)
				require.NoError(t, err)
				require.Equal(t, total, gotTotal)
				require.Equal(t, outpointsOfVtxos(all), outpointsOfVtxos(got))
			}
		})

		t.Run("negative offset reads the first page", func(t *testing.T) {
			got, total, err := repo.GetVtxosWithPubKeys(
				ctx, filter, domain.Page{Limit: 2, Offset: -5},
			)
			require.NoError(t, err)
			require.Len(t, got, 2)
			require.Greater(t, total, int32(0))

			first, _, err := repo.GetVtxosWithPubKeys(
				ctx, filter, domain.Page{Limit: 2, Offset: 0},
			)
			require.NoError(t, err)
			require.Equal(t, outpointsOfVtxos(first), outpointsOfVtxos(got))
		})
	})

	t.Run("sortByCreatedAt", func(t *testing.T) {
		t.Run("orders newest first", func(t *testing.T) {
			vtxos := []domain.Vtxo{
				{Outpoint: domain.Outpoint{Txid: "a", VOut: 0}, CreatedAt: 10},
				{Outpoint: domain.Outpoint{Txid: "b", VOut: 0}, CreatedAt: 30},
				{Outpoint: domain.Outpoint{Txid: "c", VOut: 0}, CreatedAt: 20},
			}
			sortByCreatedAt(vtxos)

			require.Equal(t, []int64{30, 20, 10}, []int64{
				vtxos[0].CreatedAt, vtxos[1].CreatedAt, vtxos[2].CreatedAt,
			})
		})

		// Ties must break on the outpoint, otherwise two pages of the same set
		// can overlap or skip a vtxo.
		t.Run("breaks ties by outpoint", func(t *testing.T) {
			vtxos := []domain.Vtxo{
				{Outpoint: domain.Outpoint{Txid: "b", VOut: 1}, CreatedAt: 10},
				{Outpoint: domain.Outpoint{Txid: "b", VOut: 0}, CreatedAt: 10},
				{Outpoint: domain.Outpoint{Txid: "a", VOut: 9}, CreatedAt: 10},
			}
			sortByCreatedAt(vtxos)

			require.Equal(t, "a:9", vtxos[0].Outpoint.String())
			require.Equal(t, "b:0", vtxos[1].Outpoint.String())
			require.Equal(t, "b:1", vtxos[2].Outpoint.String())
		})
	})
}

// seedPageVtxos writes three vtxos under pubkey so a page of two has a
// remainder to fall off.
func seedPageVtxos(t *testing.T, pubkey string, now int64) *VtxoRepository {
	t.Helper()
	ctx := context.Background()

	repo, err := NewVtxoRepository(t.TempDir(), nil)
	require.NoError(t, err)
	t.Cleanup(repo.Close)

	vtxos := make([]domain.Vtxo, 0, 3)
	for i, txid := range []string{"page0000", "page0001", "page0002"} {
		vtxos = append(vtxos, domain.Vtxo{
			Outpoint:           domain.Outpoint{Txid: txid, VOut: 0},
			PubKey:             pubkey,
			Amount:             1000,
			ExpiresAt:          now + 3600,
			CreatedAt:          now - int64(10*i),
			RootCommitmentTxid: "commitment",
			CommitmentTxids:    []string{"commitment"},
		})
	}
	require.NoError(t, repo.AddVtxos(ctx, vtxos))

	return repo.(*VtxoRepository)
}

func outpointsOfVtxos(vtxos []domain.Vtxo) []domain.Outpoint {
	outpoints := make([]domain.Outpoint, 0, len(vtxos))
	for _, vtxo := range vtxos {
		outpoints = append(outpoints, vtxo.Outpoint)
	}
	return outpoints
}
