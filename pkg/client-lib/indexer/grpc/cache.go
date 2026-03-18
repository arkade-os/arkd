package indexer

import (
	"maps"
	"slices"
	"sync"
)

// TODO: drop me in https://github.com/arkade-os/arkd/pull/951
type scriptsCache struct {
	lock    *sync.Mutex
	scripts map[string]struct{}
}

func newScriptsCache() *scriptsCache {
	return &scriptsCache{
		lock:    &sync.Mutex{},
		scripts: make(map[string]struct{}),
	}
}

func (s *scriptsCache) get() []string {
	s.lock.Lock()
	defer s.lock.Unlock()

	return slices.Collect((maps.Keys(s.scripts)))
}

func (s *scriptsCache) add(scripts []string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, script := range scripts {
		s.scripts[script] = struct{}{}
	}
}

func (s *scriptsCache) remove(scripts []string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, script := range scripts {
		delete(s.scripts, script)
	}
}
