package inmemorylivestore

import (
	"context"
	"sync"

	"github.com/arkade-os/arkd/internal/core/ports"
)

type scheduledTasksStore struct {
	lock sync.Mutex
	ids  map[string]struct{}
}

func NewScheduledTasksStore() ports.ScheduledTasksStore {
	return &scheduledTasksStore{
		ids: make(map[string]struct{}),
	}
}

func (s *scheduledTasksStore) AddIfAbsent(_ context.Context, id string) (bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if _, ok := s.ids[id]; ok {
		return false, nil
	}
	s.ids[id] = struct{}{}
	return true, nil
}

func (s *scheduledTasksStore) Remove(_ context.Context, id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.ids, id)
	return nil
}

func (s *scheduledTasksStore) Has(_ context.Context, id string) (bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	_, ok := s.ids[id]
	return ok, nil
}
