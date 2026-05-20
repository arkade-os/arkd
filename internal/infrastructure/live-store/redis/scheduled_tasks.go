package redislivestore

import (
	"context"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/redis/go-redis/v9"
)


type scheduledTasksStore struct {
	rdb *redis.Client
}

func NewScheduledTasksStore(rdb *redis.Client) ports.ScheduledTasksStore {
	return &scheduledTasksStore{rdb: rdb}
}

func (s *scheduledTasksStore) AddIfAbsent(ctx context.Context, id string) (bool, error) {
	// SETNX is atomic on the Redis server: returns true iff this call set
	// the key. Multiple arkd processes racing to claim the same task id
	// will see exactly one true and the rest false.
	return s.rdb.SetNX(ctx, scheduledTaskKey(id), "1", 0).Result()
}

func (s *scheduledTasksStore) Remove(ctx context.Context, id string) error {
	// Del returns the number of keys removed; we don't care if it was 0
	// (Remove is idempotent per the interface contract).
	return s.rdb.Del(ctx, scheduledTaskKey(id)).Err()
}

func (s *scheduledTasksStore) Has(ctx context.Context, id string) (bool, error) {
	n, err := s.rdb.Exists(ctx, scheduledTaskKey(id)).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func scheduledTaskKey(id string) string {
	return fmt.Sprintf("%s:%s", scheduledTaskKeyPrefix, id)
}
