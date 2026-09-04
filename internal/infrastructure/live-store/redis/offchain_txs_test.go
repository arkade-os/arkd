package redislivestore

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestOffChainTxStore(t *testing.T) {
	ctx := context.Background()
	rdb := newRebuildTestRedis(t)

	t.Run("re-registers the inputs of stored tx bodies", func(t *testing.T) {
		require.NoError(t, rdb.FlushDB(ctx).Err())
		// A body without an owner entry is what the version before the
		// owner-tagged hash leaves behind for an in-flight tx.
		tx, spent := rebuildFixtureTx(t, "arktx-aa", 1)
		storeBody(t, rdb, tx)

		store := newStore(t, rdb, 3)

		exists, err := store.Includes(ctx, spent)
		require.NoError(t, err)
		require.True(t, exists)

		// The rebuilt entry carries the tx's own id as owner, so a different
		// owner conflicts and the tx itself is idempotent.
		status, conflict, err := store.ClaimOutpoints(
			ctx, "other-owner", []domain.Outpoint{spent},
		)
		require.NoError(t, err)
		require.Equal(t, ports.ClaimConflict, status)
		require.NotNil(t, conflict)
		require.Equal(t, spent.String(), conflict.String())

		status, _, err = store.ClaimOutpoints(ctx, tx.ArkTxid, []domain.Outpoint{spent})
		require.NoError(t, err)
		require.Equal(t, ports.ClaimAlreadyOwned, status)
	})

	t.Run("never overwrites an existing owner", func(t *testing.T) {
		require.NoError(t, rdb.FlushDB(ctx).Err())
		tx, spent := rebuildFixtureTx(t, "arktx-bb", 2)
		storeBody(t, rdb, tx)
		require.NoError(t,
			rdb.HSet(ctx, offChainInputsHashKey, spent.String(), "someone-else").Err(),
		)

		newStore(t, rdb, 3)

		owner, err := rdb.HGet(ctx, offChainInputsHashKey, spent.String()).Result()
		require.NoError(t, err)
		require.Equal(t, "someone-else", owner)
	})

	t.Run("skips a malformed body and rebuilds the rest", func(t *testing.T) {
		require.NoError(t, rdb.FlushDB(ctx).Err())
		require.NoError(t, rdb.HSet(ctx, offChainTxsHashKey, "garbage", "{not json").Err())
		tx, spent := rebuildFixtureTx(t, "arktx-cc", 3)
		storeBody(t, rdb, tx)

		store := newStore(t, rdb, 3)

		exists, err := store.Includes(ctx, spent)
		require.NoError(t, err)
		require.True(t, exists)
	})

	t.Run("is a no-op with nothing stored", func(t *testing.T) {
		require.NoError(t, rdb.FlushDB(ctx).Err())

		newStore(t, rdb, 3)

		n, err := rdb.HLen(ctx, offChainInputsHashKey).Result()
		require.NoError(t, err)
		require.Zero(t, n)
	})

	t.Run("does not re-register the inputs of a body removed meanwhile", func(t *testing.T) {
		require.NoError(t, rdb.FlushDB(ctx).Err())
		tx, spent := rebuildFixtureTx(t, "arktx-dd", 4)
		storeBody(t, rdb, tx)
		store := newStore(t, rdb, 3)
		inputs, err := checkpointInputs(tx)
		require.NoError(t, err)

		// Another instance projects the tx and removes it between the body
		// listing and the re-registration. Nothing could clear an input
		// re-registered after that, since Remove needs the body to find it.
		require.NoError(t, store.Remove(ctx, tx.ArkTxid))

		added, err := store.reregisterInputs(ctx, tx.ArkTxid, inputs)
		require.NoError(t, err)
		require.Zero(t, added)
		exists, err := store.Includes(ctx, spent)
		require.NoError(t, err)
		require.False(t, exists, "an input must not be registered for a body that is gone")
	})

	t.Run("skips a stored tx with a malformed checkpoint tx as a whole", func(t *testing.T) {
		require.NoError(t, rdb.FlushDB(ctx).Err())
		tx, spent := rebuildFixtureTx(t, "arktx-ff", 6)
		// One parseable checkpoint tx and one that is not. Registering only the
		// parseable half would leave claims that Remove, failing on the same
		// parse error, could never clear.
		tx.CheckpointTxs["bad"] = "not a psbt"
		storeBody(t, rdb, tx)

		store := newStore(t, rdb, 3)

		exists, err := store.Includes(ctx, spent)
		require.NoError(t, err)
		require.False(t, exists, "no input of a partially parseable tx may be registered")
	})

	t.Run("fails to construct when the rebuild cannot run", func(t *testing.T) {
		// A store that served after a failed rebuild would answer ClaimFresh
		// for every in-flight input it did not reach.
		unreachable := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
		t.Cleanup(func() { _ = unreachable.Close() })

		store, err := NewOffChainTxStore(unreachable, 1)

		require.Error(t, err)
		require.Nil(t, store)
	})

	t.Run("runs a script at least once with zero retries", func(t *testing.T) {
		require.NoError(t, rdb.FlushDB(ctx).Err())
		store := newStore(t, rdb, 0)
		_, spent := rebuildFixtureTx(t, "arktx-ee", 5)

		status, _, err := store.ClaimOutpoints(ctx, "owner", []domain.Outpoint{spent})
		require.NoError(t, err)
		require.Equal(t, ports.ClaimFresh, status)

		require.NoError(t, store.ReleaseOutpoints(ctx, "owner", []domain.Outpoint{spent}))
		exists, err := store.Includes(ctx, spent)
		require.NoError(t, err)
		require.False(t, exists)
	})
}

// --- helpers ---

// newStore builds the store against the given redis, failing the test if the
// startup rebuild does.
func newStore(t *testing.T, rdb *redis.Client, retries int) *offChainTxStore {
	t.Helper()
	store, err := NewOffChainTxStore(rdb, retries)
	require.NoError(t, err)
	return store.(*offChainTxStore)
}

// newRebuildTestRedis connects to a redis db index of its own and flushes it
// when the test ends.
func newRebuildTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	opts, err := redis.ParseURL("redis://localhost:6379/3")
	require.NoError(t, err)
	rdb := redis.NewClient(opts)
	t.Cleanup(func() {
		_ = rdb.FlushDB(context.Background()).Err()
		_ = rdb.Close()
	})
	return rdb
}

// rebuildFixtureTx builds an offchain tx with one checkpoint tx spending a
// single outpoint, and returns that outpoint.
func rebuildFixtureTx(
	t *testing.T, arkTxid string, seed byte,
) (domain.OffchainTx, domain.Outpoint) {
	t.Helper()
	var hash chainhash.Hash
	hash[0] = seed
	msgTx := wire.NewMsgTx(2)
	msgTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: hash, Index: 1}, nil, nil))
	msgTx.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))
	p, err := psbt.NewFromUnsignedTx(msgTx)
	require.NoError(t, err)
	b64, err := p.B64Encode()
	require.NoError(t, err)

	tx := domain.OffchainTx{
		ArkTxid:       arkTxid,
		CheckpointTxs: map[string]string{msgTx.TxID(): b64},
	}
	return tx, domain.Outpoint{Txid: hash.String(), VOut: 1}
}

// storeBody writes only the tx body, leaving the inputs hash untouched.
func storeBody(t *testing.T, rdb *redis.Client, tx domain.OffchainTx) {
	t.Helper()
	body, err := json.Marshal(tx)
	require.NoError(t, err)
	require.NoError(t,
		rdb.HSet(context.Background(), offChainTxsHashKey, tx.ArkTxid, body).Err(),
	)
}
