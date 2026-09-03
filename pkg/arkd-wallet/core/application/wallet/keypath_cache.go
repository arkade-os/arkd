package wallet

import lru "github.com/hashicorp/golang-lru/v2"

// keyPathCacheSize bounds the number of cached script -> key path entries.
//
// A signing operation only needs the scripts of the inputs being signed, which
// are the most recently listed UTXOs, so evicting older entries is always safe:
// a miss simply falls back to the NBXplorer lookup. The bound keeps memory flat
// on a long-running server whose wallet churns through many addresses (e.g. the
// connector account across many rounds).
const keyPathCacheSize = 50_000

// keyPathEntry records the derivation scheme and relative key path a script
// belongs to.
type keyPathEntry struct {
	derivationScheme string
	keyPath          string
}

// keyPathCache is a bounded, concurrency-safe cache of the script ->
// (derivation scheme, key path) mapping.
//
// The mapping is immutable: a given script always derives from the same key
// path under the same account, so cached entries are never stale. The cache lets
// the wallet skip the per-input NBXplorer script lookups when signing inputs it
// has already seen as UTXOs.
type keyPathCache struct {
	cache *lru.Cache[string, keyPathEntry]
}

func newKeyPathCache() *keyPathCache {
	// lru.New only errors on a non-positive size, which is a positive constant
	// here, so the error cannot occur.
	cache, _ := lru.New[string, keyPathEntry](keyPathCacheSize)
	return &keyPathCache{cache: cache}
}

// get returns the cached entry for the given script, if any.
func (c *keyPathCache) get(script string) (keyPathEntry, bool) {
	return c.cache.Get(script)
}

// set caches the derivation scheme and key path for the given script, evicting
// the least-recently-used entry if the cache is full. Entries with an empty
// script or key path are ignored, as they cannot be used to derive a key later.
func (c *keyPathCache) set(script, derivationScheme, keyPath string) {
	if script == "" || keyPath == "" {
		return
	}
	c.cache.Add(script, keyPathEntry{derivationScheme: derivationScheme, keyPath: keyPath})
}
