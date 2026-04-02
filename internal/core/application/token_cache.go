package application

import (
	"sync"
	"time"
)

type tokenCache struct {
	mu sync.RWMutex
	// Stores outpoints by hash (hash of outpoints), with a shared expiration time for all
	// outpoints of the same hash
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

func (c *tokenCache) add(hash string, outpoints []Outpoint, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.outpointsByHash[hash]; ok {
		return
	}

	expiry := now.Add(c.invalidationDuration)
	if c.outpointsByHash[hash] == nil {
		c.outpointsByHash[hash] = make(map[Outpoint]time.Time)
	}
	for _, outpoint := range outpoints {
		c.outpointsByHash[hash][outpoint] = expiry
	}
}

func (c *tokenCache) getOutpoints(hash string) (map[string]struct{}, *time.Time, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	outpoints, ok := c.outpointsByHash[hash]
	if !ok {
		return nil, nil, false
	}
	for _, expiresAt := range outpoints {
		if time.Now().After(expiresAt) {
			return nil, nil, false
		}
		break
	}

	res := make(map[string]struct{})
	expiry := time.Time{}
	for outpoint := range outpoints {
		if expiry.IsZero() {
			expiry = outpoints[outpoint]
		}
		res[outpoint.String()] = struct{}{}
	}
	return res, &expiry, true
}

func (c *tokenCache) getTxids(hash string) (map[string]struct{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	outpoints, ok := c.outpointsByHash[hash]
	if !ok {
		return nil, false
	}
	for _, expiry := range outpoints {
		if time.Now().After(expiry) {
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
