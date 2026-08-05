package wallet

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyPathCache(t *testing.T) {
	t.Run("set and get", func(t *testing.T) {
		c := newKeyPathCache()

		c.set("script-a", "scheme-main", "0/0")
		entry, ok := c.get("script-a")
		require.True(t, ok)
		require.Equal(t, "scheme-main", entry.derivationScheme)
		require.Equal(t, "0/0", entry.keyPath)
	})

	t.Run("get miss", func(t *testing.T) {
		c := newKeyPathCache()

		_, ok := c.get("missing")
		require.False(t, ok)
	})

	t.Run("empty script or key path is not cached", func(t *testing.T) {
		c := newKeyPathCache()

		c.set("", "scheme", "0/0")
		_, ok := c.get("")
		require.False(t, ok)

		c.set("script-b", "scheme", "")
		_, ok = c.get("script-b")
		require.False(t, ok)
	})

	t.Run("overwrite", func(t *testing.T) {
		c := newKeyPathCache()

		c.set("script-c", "scheme-main", "0/0")
		c.set("script-c", "scheme-connector", "1/2")

		entry, ok := c.get("script-c")
		require.True(t, ok)
		require.Equal(t, "scheme-connector", entry.derivationScheme)
		require.Equal(t, "1/2", entry.keyPath)
	})
}

func TestKeyPathCache_Bounded(t *testing.T) {
	c := newKeyPathCache()

	total := keyPathCacheSize + 1000
	for i := range total {
		c.set(fmt.Sprintf("script-%d", i), "scheme", fmt.Sprintf("0/%d", i))
	}

	// the cache never grows past its bound
	require.Equal(t, keyPathCacheSize, c.cache.Len())

	// the oldest entries are evicted, the most recent are retained
	_, ok := c.get("script-0")
	require.False(t, ok)

	entry, ok := c.get(fmt.Sprintf("script-%d", total-1))
	require.True(t, ok)
	require.Equal(t, fmt.Sprintf("0/%d", total-1), entry.keyPath)
}

func TestKeyPathCache_Concurrent(t *testing.T) {
	c := newKeyPathCache()
	numberOfRoutines := 100

	wg := sync.WaitGroup{}
	wg.Add(numberOfRoutines)

	for i := range numberOfRoutines {
		go func(i int) {
			defer wg.Done()
			script := fmt.Sprintf("script-%d", i)
			c.set(script, "scheme", fmt.Sprintf("0/%d", i))
			_, _ = c.get(script)
		}(i)
	}

	wg.Wait()

	for i := range numberOfRoutines {
		entry, ok := c.get(fmt.Sprintf("script-%d", i))
		require.True(t, ok)
		require.Equal(t, fmt.Sprintf("0/%d", i), entry.keyPath)
	}
}
