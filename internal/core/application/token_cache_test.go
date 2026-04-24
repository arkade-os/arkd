package application

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTokenCache(t *testing.T) {
	op1 := Outpoint{Txid: "aabbcc1100000000000000000000000000000000000000000000000000000000", VOut: 0}
	op2 := Outpoint{Txid: "ddeeff2200000000000000000000000000000000000000000000000000000000", VOut: 1}
	op3 := Outpoint{Txid: "aabbcc1100000000000000000000000000000000000000000000000000000000", VOut: 2} // same txid as op1, different vout

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name   string
			setup  func(c *tokenCache)
			assert func(t *testing.T, c *tokenCache)
		}{
			{
				name: "getOutpoints returns added outpoints",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1, op2}, time.Now())
				},
				assert: func(t *testing.T, c *tokenCache) {
					outpoints, expiry, ok := c.getOutpoints("hash1")
					require.True(t, ok)
					require.Len(t, outpoints, 2)
					require.Contains(t, outpoints, op1.String())
					require.Contains(t, outpoints, op2.String())
					require.False(t, expiry.IsZero())
				},
			},
			{
				name: "getTxids returns txids",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1, op2}, time.Now())
				},
				assert: func(t *testing.T, c *tokenCache) {
					txids, ok := c.getTxids("hash1")
					require.True(t, ok)
					require.Len(t, txids, 2)
					require.Contains(t, txids, op1.Txid)
					require.Contains(t, txids, op2.Txid)
				},
			},
			{
				name: "getTxids deduplicates outpoints sharing the same txid",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1, op3}, time.Now()) // op1 and op3 share the same txid
				},
				assert: func(t *testing.T, c *tokenCache) {
					txids, ok := c.getTxids("hash1")
					require.True(t, ok)
					require.Len(t, txids, 1)
					require.Contains(t, txids, op1.Txid)
				},
			},
			{
				name:  "getOutpoints returns false for unknown hash",
				setup: func(c *tokenCache) {},
				assert: func(t *testing.T, c *tokenCache) {
					outpoints, expiry, ok := c.getOutpoints("nonexistent")
					require.False(t, ok)
					require.Empty(t, outpoints)
					require.Nil(t, expiry)
				},
			},
			{
				name:  "getTxids returns false for unknown hash",
				setup: func(c *tokenCache) {},
				assert: func(t *testing.T, c *tokenCache) {
					_, ok := c.getTxids("nonexistent")
					require.False(t, ok)
				},
			},
			{
				name: "add same hash is no-op",
				setup: func(c *tokenCache) {
					now := time.Now()
					c.add("hash1", []Outpoint{op1}, now)
					c.add("hash1", []Outpoint{op2}, now)
				},
				assert: func(t *testing.T, c *tokenCache) {
					outpoints, expiry, ok := c.getOutpoints("hash1")
					require.True(t, ok)
					require.Len(t, outpoints, 1)
					require.Contains(t, outpoints, op1.String())
					require.NotContains(t, outpoints, op2.String())
					require.False(t, expiry.IsZero())
				},
			},
			{
				name: "entries expire after invalidation duration",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1}, time.Now())
					time.Sleep(100 * time.Millisecond)
				},
				assert: func(t *testing.T, c *tokenCache) {
					outpints, expiry, ok := c.getOutpoints("hash1")
					require.False(t, ok)
					require.Empty(t, outpints)
					require.Nil(t, expiry)
				},
			},
			{
				name: "entries from different hashes expire independently",
				setup: func(c *tokenCache) {
					now := time.Now()
					c.add("hash1", []Outpoint{op1}, now)
					time.Sleep(30 * time.Millisecond)
					c.add("hash2", []Outpoint{op2}, now.Add(30*time.Millisecond))
					time.Sleep(40 * time.Millisecond) // t≈70ms: hash1 expired, hash2 still live
				},
				assert: func(t *testing.T, c *tokenCache) {
					outpoints, expiry, ok := c.getOutpoints("hash1")
					require.False(t, ok)
					require.Empty(t, outpoints)
					require.Nil(t, expiry)

					outpoints, expiry, ok = c.getOutpoints("hash2")
					require.True(t, ok)
					require.NotEmpty(t, outpoints)
					require.False(t, expiry.IsZero())
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				c := newTokenCache(50 * time.Millisecond)
				tc.setup(c)
				tc.assert(t, c)
			})
		}
	})

	t.Run("list", func(t *testing.T) {
		tests := []struct {
			name   string
			setup  func(c *tokenCache)
			assert func(t *testing.T, c *tokenCache)
		}{
			{
				name: "no filter returns all entries",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1}, time.Now())
					c.add("hash2", []Outpoint{op2}, time.Now())
				},
				assert: func(t *testing.T, c *tokenCache) {
					entries := c.list("", "", "")
					require.Len(t, entries, 2)
				},
			},
			{
				name: "filter by hash",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1}, time.Now())
					c.add("hash2", []Outpoint{op2}, time.Now())
				},
				assert: func(t *testing.T, c *tokenCache) {
					entries := c.list("hash1", "", "")
					require.Len(t, entries, 1)
					require.Equal(t, "hash1", entries[0].Hash)
				},
			},
			{
				name: "filter by outpoint",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1, op2}, time.Now())
					c.add("hash2", []Outpoint{op2, op3}, time.Now())
					c.add("hash3", []Outpoint{op1, op3}, time.Now())
				},
				assert: func(t *testing.T, c *tokenCache) {
					entries := c.list("", op2.String(), "")
					require.Len(t, entries, 2)
				},
			},
			{
				name: "filter by txid",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1}, time.Now())
					c.add("hash2", []Outpoint{op1, op2}, time.Now())
					c.add("hash3", []Outpoint{op2}, time.Now())
				},
				assert: func(t *testing.T, c *tokenCache) {
					entries := c.list("", "", op1.Txid)
					require.Len(t, entries, 2)
				},
			},
			{
				name: "no match returns empty",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1}, time.Now())
				},
				assert: func(t *testing.T, c *tokenCache) {
					entries := c.list("nonexistent", "", "")
					require.Empty(t, entries)
				},
			},
			{
				name: "skips expired entries",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1}, time.Now())
					time.Sleep(100 * time.Millisecond)
				},
				assert: func(t *testing.T, c *tokenCache) {
					entries := c.list("", "", "")
					require.Empty(t, entries)
				},
			},
			{
				name: "returns outpoints and expiry",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1, op2}, time.Now())
				},
				assert: func(t *testing.T, c *tokenCache) {
					entries := c.list("hash1", "", "")
					require.Len(t, entries, 1)
					require.Len(t, entries[0].Outpoints, 2)
					require.False(t, entries[0].ExpiresAt.IsZero())
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				c := newTokenCache(50 * time.Millisecond)
				tc.setup(c)
				tc.assert(t, c)
			})
		}
	})

	t.Run("revoke", func(t *testing.T) {
		tests := []struct {
			name   string
			setup  func(c *tokenCache)
			assert func(t *testing.T, c *tokenCache)
		}{
			{
				name: "by hash",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1}, time.Now())
					c.add("hash2", []Outpoint{op2}, time.Now())
				},
				assert: func(t *testing.T, c *tokenCache) {
					count := c.revoke("hash1", "", "")
					require.Equal(t, 1, count)
					// hash1 gone
					_, _, ok := c.getOutpoints("hash1")
					require.False(t, ok)
					// hash2 still there
					_, _, ok = c.getOutpoints("hash2")
					require.True(t, ok)
				},
			},
			{
				name: "by txid revokes all matching",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1}, time.Now())
					c.add("hash2", []Outpoint{op3}, time.Now()) // op3 shares txid with op1
					c.add("hash3", []Outpoint{op2}, time.Now())
				},
				assert: func(t *testing.T, c *tokenCache) {
					count := c.revoke("", "", op1.Txid)
					require.Equal(t, 2, count)
					_, _, ok := c.getOutpoints("hash1")
					require.False(t, ok)
					_, _, ok = c.getOutpoints("hash2")
					require.False(t, ok)
					// hash3 still there
					_, _, ok = c.getOutpoints("hash3")
					require.True(t, ok)
				},
			},
			{
				name: "no match returns zero",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1}, time.Now())
				},
				assert: func(t *testing.T, c *tokenCache) {
					count := c.revoke("nonexistent", "", "")
					require.Equal(t, 0, count)
					// original entry untouched
					_, _, ok := c.getOutpoints("hash1")
					require.True(t, ok)
				},
			},
			{
				name: "skips expired entries",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1}, time.Now())
					time.Sleep(100 * time.Millisecond)
				},
				assert: func(t *testing.T, c *tokenCache) {
					count := c.revoke("hash1", "", "")
					require.Equal(t, 0, count)
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				c := newTokenCache(50 * time.Millisecond)
				tc.setup(c)
				tc.assert(t, c)
			})
		}
	})
}
