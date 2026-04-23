package redislivestore

import (
	"testing"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// TestPopNilIntent ensures Pop doesn't panic when intent:ids contains an id whose intent:<id> body is "nil"
func TestPopNilIntent(t *testing.T) {
	ctx := t.Context()
	
	redisOpts, err := redis.ParseURL("redis://localhost:6379/0")
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
