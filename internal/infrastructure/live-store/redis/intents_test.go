package redislivestore

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// TestPopNilIntent ensures Pop doesn't panic when intent:ids contains an id whose intent:<id> body is "nil"
func TestPopNilIntent(t *testing.T) {
	ctx := t.Context()

	// use /1 to isolate from TestLiveStoreImplementations which uses /0
	// it avoids race condition where DeleteAll clean the intent list before the end of the test
	redisOpts, err := redis.ParseURL("redis://localhost:6379/1")
	require.NoError(t, err)
	rdb := redis.NewClient(redisOpts)

	store := NewIntentStore(rdb, 5)

	// delete all to not make the other tests won't fail
	err = store.DeleteAll(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.DeleteAll(ctx) })

	// push an intent with "nil" body
	orphanId := "nilvalueintent-" + uuid.New().String()
	redisCmd := rdb.SAdd(ctx, intentStoreIdsKey, orphanId)
	require.NoError(t, redisCmd.Err())

	// try to pop the intent, verify it doesn't panic
	require.NotPanics(t, func() {
		popped, err := store.Pop(ctx, 10)
		require.NoError(t, err)
		require.Empty(t, popped)
	})
}

// TestPopAndDeleteWatchIntentBody verifies that Pop() and Delete() add the
// per-intent body key (`intent:<id>`) to their WATCH set, so a concurrent
// Update() on the same intent aborts the transaction with TxFailedErr rather
// than committing stale outpoints to intent:vtxos / intent:vtxosToRemove.
func TestPopAndDeleteWatchIntentBody(t *testing.T) {
	ctx := t.Context()

	redisOpts, err := redis.ParseURL("redis://localhost:6379/2")
	require.NoError(t, err)
	rdb := redis.NewClient(redisOpts)
	t.Cleanup(func() { _ = rdb.Close() })

	hook := &watchHook{}
	rdb.AddHook(hook)

	s, ok := NewIntentStore(rdb, 3).(*intentStore)
	require.True(t, ok)
	t.Cleanup(func() { _ = s.DeleteAll(ctx) })
	require.NoError(t, s.DeleteAll(ctx))

	// seed a minimal intent body without going through Push (which would
	// pollute the hook with its own WATCH calls)
	id := "raceintent-" + uuid.New().String()
	body, err := json.Marshal(ports.TimedIntent{
		Intent: domain.Intent{
			Id: id,
			Inputs: []domain.Vtxo{
				{Outpoint: domain.Outpoint{Txid: "aa", VOut: 0}},
			},
			Receivers: []domain.Receiver{{Amount: 1, PubKey: "pk"}},
		},
		Timestamp: time.Now(),
	})
	require.NoError(t, err)
	bodyKey := s.intents.Key(id)
	require.NoError(t, rdb.Set(ctx, bodyKey, body, 0).Err())
	require.NoError(t, rdb.SAdd(ctx, intentStoreIdsKey, id).Err())

	t.Run("pop watches intent body", func(t *testing.T) {
		hook.mu.Lock()
		hook.sets = nil
		hook.mu.Unlock()

		_, err := s.Pop(ctx, 1)
		require.NoError(t, err)

		watched := hook.watchedKeys()
		require.Contains(t, watched, bodyKey)
	})

	// re-seed for the Delete subtest (Pop consumes the intent)
	require.NoError(t, rdb.Set(ctx, bodyKey, body, 0).Err())
	require.NoError(t, rdb.SAdd(ctx, intentStoreIdsKey, id).Err())

	t.Run("delete watches intent body", func(t *testing.T) {
		hook.mu.Lock()
		hook.sets = nil
		hook.mu.Unlock()

		require.NoError(t, s.Delete(ctx, []string{id}))

		watched := hook.watchedKeys()
		require.Contains(t, watched, bodyKey)
	})

	// And: end-to-end — a concurrent body overwrite between WATCH and EXEC
	// must abort the transaction with TxFailedErr, proving WATCH is active.
	t.Run("watch detects concurrent body update", func(t *testing.T) {
		require.NoError(t, rdb.Set(ctx, bodyKey, body, 0).Err())
		require.NoError(t, rdb.SAdd(ctx, intentStoreIdsKey, id).Err())

		err := rdb.Watch(ctx, func(tx *redis.Tx) error {
			// overwrite the body from an unrelated connection
			require.NoError(t, rdb.Set(ctx, bodyKey, body, 0).Err())
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.SRem(ctx, intentStoreIdsKey, id)
				return nil
			})
			return err
		}, intentStoreIdsKey, bodyKey)

		require.True(t, errors.Is(err, redis.TxFailedErr))
	})
}

// watchHook records the key sets passed to every WATCH command issued on the
// connection it is attached to, so tests can assert what a caller watched.
type watchHook struct {
	mu   sync.Mutex
	sets [][]string
}

func (h *watchHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *watchHook) ProcessPipelineHook(
	next redis.ProcessPipelineHook,
) redis.ProcessPipelineHook {
	return next
}

func (h *watchHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		args := cmd.Args()
		if len(args) > 0 {
			if name, ok := args[0].(string); ok && strings.EqualFold(name, "watch") {
				keys := make([]string, 0, len(args)-1)
				for _, a := range args[1:] {
					if s, ok := a.(string); ok {
						keys = append(keys, s)
					}
				}
				h.mu.Lock()
				h.sets = append(h.sets, keys)
				h.mu.Unlock()
			}
		}
		return next(ctx, cmd)
	}
}

func (h *watchHook) watchedKeys() map[string]struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]struct{}{}
	for _, set := range h.sets {
		for _, k := range set {
			out[k] = struct{}{}
		}
	}
	return out
}
