package redislivestore

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestOffchainTxLockFinalization(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379", DB: 3})
	waiterRdb := redis.NewClient(&redis.Options{Addr: "localhost:6379", DB: 3})
	t.Cleanup(func() {
		_ = rdb.Close()
		_ = waiterRdb.Close()
	})
	store := NewOffChainTxStore(rdb, 1)
	waiter := NewOffChainTxStore(waiterRdb, 1)

	t.Run("waits until unlock", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		txid := uuid.NewString()
		t.Cleanup(func() { _ = store.UnlockFinalization(context.Background(), txid) })

		require.NoError(t, store.LockFinalization(ctx, txid, 5*time.Minute))

		acquired := make(chan error, 1)
		go func() {
			acquired <- waiter.LockFinalization(ctx, txid, 5*time.Minute)
		}()

		// Contention must wait beyond the store's retry budget.
		select {
		case err := <-acquired:
			t.Fatalf("lock returned before unlock: %v", err)
		case <-time.After(50 * time.Millisecond):
		}

		require.NoError(t, store.UnlockFinalization(ctx, txid))
		select {
		case err := <-acquired:
			require.NoError(t, err)
		case <-ctx.Done():
			t.Fatal("waiter did not acquire the released lock")
		}
		require.NoError(t, waiter.UnlockFinalization(ctx, txid))
	})

	t.Run("locks are scoped by txid", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		txid := uuid.NewString()
		otherTxid := uuid.NewString()
		t.Cleanup(func() {
			_ = store.UnlockFinalization(context.Background(), txid)
			_ = store.UnlockFinalization(context.Background(), otherTxid)
		})

		require.NoError(t, store.LockFinalization(ctx, txid, 5*time.Minute))
		require.NoError(t, waiter.LockFinalization(ctx, otherTxid, 5*time.Minute))
		require.NoError(t, waiter.UnlockFinalization(ctx, otherTxid))

		waitCtx, cancelWait := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancelWait()
		require.ErrorIs(
			t, waiter.LockFinalization(waitCtx, txid, 5*time.Minute), context.DeadlineExceeded,
		)
	})

	t.Run("waiting can be canceled", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		txid := uuid.NewString()
		t.Cleanup(func() { _ = store.UnlockFinalization(context.Background(), txid) })

		require.NoError(t, store.LockFinalization(ctx, txid, 5*time.Minute))

		waitCtx, cancelWait := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancelWait()
		require.ErrorIs(
			t, waiter.LockFinalization(waitCtx, txid, 5*time.Minute), context.DeadlineExceeded,
		)
	})

	t.Run("unlock is idempotent", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		txid := uuid.NewString()
		t.Cleanup(func() { _ = store.UnlockFinalization(context.Background(), txid) })

		require.NoError(t, store.LockFinalization(ctx, txid, 5*time.Minute))
		require.NoError(t, store.UnlockFinalization(ctx, txid))
		require.NoError(t, store.UnlockFinalization(ctx, txid))
	})

	t.Run("canceled caller cannot acquire an available lock", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		txid := uuid.NewString()
		t.Cleanup(func() { _ = store.UnlockFinalization(context.Background(), txid) })

		canceledCtx, cancelNow := context.WithCancel(ctx)
		cancelNow()
		require.ErrorIs(t, store.LockFinalization(canceledCtx, txid, 5*time.Minute), context.Canceled)
		require.NoError(t, store.LockFinalization(ctx, txid, 5*time.Minute))
		require.NoError(t, store.UnlockFinalization(ctx, txid))
	})

	t.Run("expiry", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379", DB: 3})
		t.Cleanup(func() { _ = rdb.Close() })
		store := NewLiveStore(rdb, nil, 1).OffchainTxs()
		waiter := NewLiveStore(rdb, nil, 1).OffchainTxs()
		txid := uuid.NewString()
		t.Cleanup(func() { _ = store.UnlockFinalization(context.Background(), txid) })

		require.NoError(t, store.LockFinalization(ctx, txid, 200*time.Millisecond))
		ttl, err := rdb.PTTL(ctx, offChainFinalizationLockKey+txid).Result()
		require.NoError(t, err)
		require.Positive(t, ttl)
		require.LessOrEqual(t, ttl, 200*time.Millisecond)

		// An abandoned lock expires without an explicit unlock. The waiter gets its own TTL.
		require.NoError(t, waiter.LockFinalization(ctx, txid, 2*time.Minute))
		ttl, err = rdb.PTTL(ctx, offChainFinalizationLockKey+txid).Result()
		require.NoError(t, err)
		require.Greater(t, ttl, time.Minute)
		require.LessOrEqual(t, ttl, 2*time.Minute)
	})

	t.Run("redis error", func(t *testing.T) {
		rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
		require.NoError(t, rdb.Close())
		store := NewOffChainTxStore(rdb, 1)

		require.ErrorIs(t, store.LockFinalization(t.Context(), "txid", 5*time.Minute), redis.ErrClosed)
		require.ErrorIs(t, store.UnlockFinalization(t.Context(), "txid"), redis.ErrClosed)
	})

	t.Run("rejects invalid TTL", func(t *testing.T) {
		store := NewOffChainTxStore(nil, 1)
		for _, ttl := range []time.Duration{0, -time.Second} {
			require.EqualError(t, store.LockFinalization(t.Context(), "txid", ttl),
				"finalization lock TTL must be positive")
		}
	})
}
