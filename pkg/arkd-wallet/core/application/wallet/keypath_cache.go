package wallet

import "sync"

// keyPathEntry records the derivation scheme and relative key path a script
// belongs to.
type keyPathEntry struct {
	derivationScheme string
	keyPath          string
}

// keyPathCache caches the script -> (derivation scheme, key path) mapping.
//
// The mapping is immutable: a given script always derives from the same key
// path under the same account, so cached entries never need invalidation. The
// cache lets the wallet skip the per-input NBXplorer script lookups when signing
// inputs it has already seen as UTXOs.
type keyPathCache struct {
	mu    sync.RWMutex
	cache map[string]keyPathEntry
}

func newKeyPathCache() *keyPathCache {
	return &keyPathCache{cache: make(map[string]keyPathEntry)}
}

// get returns the cached entry for the given script, if any.
func (c *keyPathCache) get(script string) (keyPathEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.cache[script]
	return entry, ok
}

// set caches the derivation scheme and key path for the given script. Entries
// with an empty script or key path are ignored, as they cannot be used to derive
// a key later.
func (c *keyPathCache) set(script, derivationScheme, keyPath string) {
	if script == "" || keyPath == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[script] = keyPathEntry{derivationScheme: derivationScheme, keyPath: keyPath}
}
