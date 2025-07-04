package redislivestore

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/redis/go-redis/v9"
)

// KVStore is a generic key-value store for storing JSON-encoded structs in Redis.
type KVStore[T any] struct {
	rdb    *redis.Client
	prefix string // e.g., "intent:"
}

func NewRedisKVStore[T any](rdb *redis.Client, prefix string) *KVStore[T] {
	return &KVStore[T]{rdb: rdb, prefix: prefix}
}

// NewIntentKVStore returns a KVStore for TimedIntent with the proper prefix.
func NewIntentKVStore(rdb *redis.Client) *KVStore[ports.TimedIntent] {
	return &KVStore[ports.TimedIntent]{rdb: rdb, prefix: "intent:"}
}

func (s *KVStore[T]) key(id string) string {
	return s.prefix + id
}

func (s *KVStore[T]) Get(ctx context.Context, id string) (*T, error) {
	val, err := s.rdb.Get(ctx, s.key(id)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var result T
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *KVStore[T]) Set(ctx context.Context, id string, value *T) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.key(id), data, 0).Err()
}

func (s *KVStore[T]) Delete(ctx context.Context, id string) error {
	return s.rdb.Del(ctx, s.key(id)).Err()
}

func (s *KVStore[T]) GetMulti(ctx context.Context, ids []string) ([]*T, error) {
	if len(ids) == 0 {
		return []*T{}, nil
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = s.key(id)
	}
	vals, err := s.rdb.MGet(ctx, keys...).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}
	results := make([]*T, 0, len(ids))
	for _, v := range vals {
		if v == nil {
			results = append(results, nil)
			continue
		}
		var item T
		if err := json.Unmarshal([]byte(v.(string)), &item); err != nil {
			return nil, err
		}
		results = append(results, &item)
	}
	return results, nil
}

// SetPipe is a helper to use KVStore Set with a pipeliner.
func (s *KVStore[T]) SetPipe(
	ctx context.Context, pipe redis.Pipeliner, key string, value *T,
) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	pipe.Set(ctx, s.prefix+key, b, 0)
	return nil
}
