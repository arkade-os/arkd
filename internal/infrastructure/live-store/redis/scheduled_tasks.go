package redislivestore

import (
	"context"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/redis/go-redis/v9"
)

const scheduledTaskTTL = 30 * 24 * time.Hour

type scheduledTasksStore struct {
	rdb *redis.Client
}

func NewScheduledTasksStore(rdb *redis.Client) ports.ScheduledTasksStore {
	return &scheduledTasksStore{rdb: rdb}
}

func (s *scheduledTasksStore) AddIfAbsent(ctx context.Context, id string) (bool, error) {
	return s.rdb.SetNX(ctx, scheduledTaskKey(id), "1", scheduledTaskTTL).Result()
}

func (s *scheduledTasksStore) Remove(ctx context.Context, id string) error {
	// Safe to call when the key isn't there — Del returns 0, not an error.
	return s.rdb.Del(ctx, scheduledTaskKey(id)).Err()
}

func (s *scheduledTasksStore) Has(ctx context.Context, id string) (bool, error) {
	n, err := s.rdb.Exists(ctx, scheduledTaskKey(id)).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *scheduledTasksStore) Clear(ctx context.Context) error {
	pattern := scheduledTaskKeyPrefix + ":*"
	iter := s.rdb.Scan(ctx, 0, pattern, 100).Iterator()
	var batch []string
	for iter.Next(ctx) {
		batch = append(batch, iter.Val())
		if len(batch) >= 100 {
			if err := s.rdb.Del(ctx, batch...).Err(); err != nil {
				return err
			}
			batch = batch[:0]
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	if len(batch) > 0 {
		return s.rdb.Del(ctx, batch...).Err()
	}
	return nil
}

func scheduledTaskKey(id string) string {
	return fmt.Sprintf("%s:%s", scheduledTaskKeyPrefix, id)
}
