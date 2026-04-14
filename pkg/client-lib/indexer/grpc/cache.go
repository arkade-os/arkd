package indexer

import (
	"maps"
	"slices"
	"sync"
)

// TODO: drop me in https://github.com/arkade-os/arkd/pull/951
type scriptsCache struct {
	lock           *sync.Mutex
	scriptsBySubId map[string]map[string]struct{}
	replacements   map[string]string
}

func newScriptsCache() *scriptsCache {
	return &scriptsCache{
		lock:           &sync.Mutex{},
		scriptsBySubId: make(map[string]map[string]struct{}),
		replacements:   make(map[string]string),
	}
}

func (s *scriptsCache) get(id string) []string {
	s.lock.Lock()
	defer s.lock.Unlock()

	subId := s.resolveId(id)
	scripts, ok := s.scriptsBySubId[subId]
	if !ok {
		return nil
	}
	return slices.Collect((maps.Keys(scripts)))
}

func (s *scriptsCache) add(id string, scripts []string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	subId := s.resolveId(id)
	if _, ok := s.scriptsBySubId[subId]; !ok {
		s.scriptsBySubId[subId] = make(map[string]struct{})
	}
	for _, script := range scripts {
		s.scriptsBySubId[subId][script] = struct{}{}
	}
}

func (s *scriptsCache) removeScripts(id string, scripts []string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	subId := s.resolveId(id)
	if _, ok := s.scriptsBySubId[subId]; !ok {
		return
	}
	for _, script := range scripts {
		delete(s.scriptsBySubId[subId], script)
	}
}

func (s *scriptsCache) removeSubscription(id string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	subId := s.resolveId(id)
	if _, ok := s.scriptsBySubId[subId]; !ok {
		return
	}
	delete(s.scriptsBySubId, subId)
}

func (s *scriptsCache) replace(oldId, newId string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Prevent replacing the oldId with itself in the replacement chain to avoid infinite loops
	if oldId == newId {
		return
	}
	// Prevent replacing the oldId with a new one already existing in the replacement chain to
	// avoid infinite loops
	if _, exists := s.replacements[newId]; exists {
		return
	}
	// Prevent replacing the oldId with a newId that already has scripts to avoid data loss
	if _, exists := s.scriptsBySubId[newId]; exists {
		return
	}

	subId := s.resolveId(oldId)
	scripts, ok := s.scriptsBySubId[subId]
	if !ok {
		return
	}
	delete(s.scriptsBySubId, subId)
	s.scriptsBySubId[newId] = scripts
	s.replacements[subId] = newId
}

func (s *scriptsCache) resolveId(id string) string {
	subId := id
	for {
		if _, ok := s.replacements[subId]; !ok {
			break
		}
		subId = s.replacements[subId]
	}
	return subId
}
