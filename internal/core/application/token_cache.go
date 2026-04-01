package application

import (
	"sync"
	"time"
)

type tokenCache struct {
	mu                   sync.RWMutex
	outpointsByHash      map[string]map[Outpoint]time.Time
	invalidationDuration time.Duration
	stop                 chan struct{}
}

func newTokenCache(invalidationDuration time.Duration) *tokenCache {
	c := &tokenCache{
		outpointsByHash:      make(map[string]map[Outpoint]time.Time),
		invalidationDuration: invalidationDuration,
		stop:                 make(chan struct{}),
	}
	go c.sweep()
	return c
}

// sweep removes expired entries on a fixed interval. Correctness does not
// depend on this — reads already do a lazy expiry check — but it bounds
// memory growth under high token volume.
func (c *tokenCache) sweep() {
	ticker := time.NewTicker(c.invalidationDuration / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			c.mu.Lock()
			for hash, outpoints := range c.outpointsByHash {
				for _, expiresAt := range outpoints {
					if now.After(expiresAt) {
						delete(c.outpointsByHash, hash)
					}
					break // all entries share the same expiresAt
				}
			}
			c.mu.Unlock()
		case <-c.stop:
			return
		}
	}
}

// nolint
func (c *tokenCache) close() {
	close(c.stop)
}

func (c *tokenCache) add(hash string, outpoints []Outpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.outpointsByHash[hash]; ok {
		return
	}

	expiresAt := time.Now().Add(c.invalidationDuration)
	if c.outpointsByHash[hash] == nil {
		c.outpointsByHash[hash] = make(map[Outpoint]time.Time)
	}
	for _, outpoint := range outpoints {
		c.outpointsByHash[hash][outpoint] = expiresAt
	}
}

func (c *tokenCache) getOutpoints(hash string) (map[string]struct{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	outpoints, ok := c.outpointsByHash[hash]
	if !ok {
		return nil, false
	}
	for _, expiresAt := range outpoints {
		if time.Now().After(expiresAt) {
			return nil, false
		}
		break
	}

	res := make(map[string]struct{})
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
	for _, expiresAt := range outpoints {
		if time.Now().After(expiresAt) {
			return nil, false
		}
		break
	}

	res := make(map[string]struct{})
	for outpoint := range outpoints {
		res[outpoint.Txid] = struct{}{}
	}
	return res, true
}
