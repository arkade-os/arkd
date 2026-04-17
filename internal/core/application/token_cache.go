package application

import (
	"sync"
	"time"
)

type TokenEntry struct {
	Hash      string
	Outpoints []string
	ExpiresAt time.Time
}

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

// touch extends the expiry of an existing cache entry by invalidationDuration
// from now. Auth tokens embed a signed timestamp that expires after authTokenTTL
// (5 min), but paginating a long VTXO chain can span many requests over a longer
// period. Each successful GetVtxoChain page calls touch so the cache entry stays
// live; validateChainAuth then accepts expired-timestamp tokens as long as the
// cache entry is still active, proving the session was recently used.
func (c *tokenCache) touch(hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	outpoints, ok := c.outpointsByHash[hash]
	if !ok {
		return
	}
	newExpiry := time.Now().Add(c.invalidationDuration)
	for op := range outpoints {
		outpoints[op] = newExpiry
	}
}

// isActive returns true if the hash has any non-expired cache entry. In
// practice touch/add set every outpoint under a hash to the same expiry, so
// any single entry would answer the question; scanning all entries removes
// reliance on that invariant and on Go's non-deterministic map iteration.
func (c *tokenCache) isActive(hash string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	outpoints, ok := c.outpointsByHash[hash]
	if !ok {
		return false
	}
	now := time.Now()
	for _, expiresAt := range outpoints {
		if now.Before(expiresAt) {
			return true
		}
	}
	return false
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

// list returns non-expired token entries matching the given filters.
func (c *tokenCache) list(hash, outpointStr, txid string) []TokenEntry {
	// Fast path: hash is known, do a direct lookup.
	if hash != "" {
		return c.listByHash(hash)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	var result []TokenEntry

	for h, outpoints := range c.outpointsByHash {
		// Check expiry.
		var expiresAt time.Time
		for _, exp := range outpoints {
			expiresAt = exp
			break
		}
		if now.After(expiresAt) {
			continue
		}

		// Filter by outpoint.
		if outpointStr != "" {
			found := false
			for op := range outpoints {
				if op.String() == outpointStr {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Filter by txid.
		if txid != "" {
			found := false
			for op := range outpoints {
				if op.Txid == txid {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		entry := TokenEntry{
			Hash:      h,
			ExpiresAt: expiresAt,
		}
		for op := range outpoints {
			entry.Outpoints = append(entry.Outpoints, op.String())
		}

		result = append(result, entry)
	}

	return result
}

func (c *tokenCache) listByHash(hash string) []TokenEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	outpoints, ok := c.outpointsByHash[hash]
	if !ok {
		return nil
	}
	var expiresAt time.Time
	for _, exp := range outpoints {
		expiresAt = exp
		break
	}
	if time.Now().After(expiresAt) {
		return nil
	}

	entry := TokenEntry{
		Hash:      hash,
		ExpiresAt: expiresAt,
	}
	for op := range outpoints {
		entry.Outpoints = append(entry.Outpoints, op.String())
	}
	return []TokenEntry{entry}
}

// revoke deletes non-expired token entries matching the given filters
// and returns the number of entries removed.
func (c *tokenCache) revoke(hash, outpointStr, txid string) int {
	// Fast path: hash is known, do a direct delete.
	if hash != "" {
		return c.revokeByHash(hash)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	count := 0

	for h, outpoints := range c.outpointsByHash {
		// Check expiry.
		var expiresAt time.Time
		for _, exp := range outpoints {
			expiresAt = exp
			break
		}
		if now.After(expiresAt) {
			continue
		}

		// Filter by outpoint.
		if outpointStr != "" {
			found := false
			for op := range outpoints {
				if op.String() == outpointStr {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Filter by txid.
		if txid != "" {
			found := false
			for op := range outpoints {
				if op.Txid == txid {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		delete(c.outpointsByHash, h)
		count++
	}

	return count
}

func (c *tokenCache) revokeByHash(hash string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	outpoints, ok := c.outpointsByHash[hash]
	if !ok {
		return 0
	}
	for _, expiry := range outpoints {
		if time.Now().After(expiry) {
			return 0
		}
		break
	}
	delete(c.outpointsByHash, hash)
	return 1
}
