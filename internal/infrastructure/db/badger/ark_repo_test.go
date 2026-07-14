package badgerdb

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/timshannon/badgerhold/v4"
)

func TestArkRepositoryPatchForfeitTxs(t *testing.T) {
	repo, err := NewArkRepository(t.TempDir(), nil)
	require.NoError(t, err)

	r, ok := repo.(*arkRepository)
	require.True(t, ok)
	t.Cleanup(r.Close)

	ctx := context.Background()
	const (
		txid    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		missing = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	// Seed an existing forfeit tx.
	require.NoError(t, r.store.Upsert(txid, Tx{Txid: txid, Tx: "old"}))

	// Patching an existing txid updates it in place.
	require.NoError(t, repo.PatchForfeitTxs(ctx, map[string]string{txid: "new"}))
	var got Tx
	require.NoError(t, r.store.Get(txid, &got))
	require.Equal(t, "new", got.Tx)

	// Patching an unknown txid fails loudly instead of inserting a stray record,
	// matching the SQL backends' "UPDATE ... WHERE txid = ?" no-match behavior.
	err = repo.PatchForfeitTxs(ctx, map[string]string{missing: "new"})
	require.ErrorContains(t, err, "not found")
	require.ErrorIs(t, r.store.Get(missing, &got), badgerhold.ErrNotFound)
}
