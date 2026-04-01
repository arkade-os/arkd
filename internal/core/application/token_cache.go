package application

import (
	"sync"
	"time"
)

type tokenCache struct {
	mu                   *sync.RWMutex
	outpointsByHash      map[string]map[Outpoint]struct{}
	invalidationDuration time.Duration
}

func newTokenCache(invalidationDuration time.Duration) *tokenCache {
	return &tokenCache{
		mu:                   &sync.RWMutex{},
		outpointsByHash:      make(map[string]map[Outpoint]struct{}),
		invalidationDuration: invalidationDuration,
	}
}

func (c *tokenCache) add(hash string, outpoints []Outpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.outpointsByHash[hash]; ok {
		return
	}

	if c.outpointsByHash[hash] == nil {
		c.outpointsByHash[hash] = make(map[Outpoint]struct{})
	}
	for _, outpoint := range outpoints {
		c.outpointsByHash[hash][outpoint] = struct{}{}
	}

	go func() {
		<-time.After(c.invalidationDuration)
		c.delete(hash)
	}()
}

func (c *tokenCache) delete(hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.outpointsByHash, hash)
}

func (c *tokenCache) getOutpoints(hash string) (map[string]struct{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	outpoints, ok := c.outpointsByHash[hash]
	if !ok {
		return nil, false
	}

	res := make(map[string]struct{}, 0)
	for outpoint := range outpoints {
		res[outpoint.String()] = struct{}{}
	}
	return res, true
}

func (c *tokenCache) getTxids(hash string) (map[string]struct{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	outpoints, ok := c.outpointsByHash[hash]
	if !ok {
		return nil, false
	}

	res := make(map[string]struct{}, 0)
	for outpoint := range outpoints {
		res[outpoint.Txid] = struct{}{}
	}
	return res, true
}
