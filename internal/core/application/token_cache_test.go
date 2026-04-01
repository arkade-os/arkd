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
					c.add("hash1", []Outpoint{op1, op2})
				},
				assert: func(t *testing.T, c *tokenCache) {
					outpoints, ok := c.getOutpoints("hash1")
					require.True(t, ok)
					require.Len(t, outpoints, 2)
					require.Contains(t, outpoints, op1.String())
					require.Contains(t, outpoints, op2.String())
				},
			},
			{
				name: "getTxids returns txids",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1, op2})
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
					c.add("hash1", []Outpoint{op1, op3}) // op1 and op3 share the same txid
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
					_, ok := c.getOutpoints("nonexistent")
					require.False(t, ok)
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
					c.add("hash1", []Outpoint{op1})
					c.add("hash1", []Outpoint{op2})
				},
				assert: func(t *testing.T, c *tokenCache) {
					outpoints, ok := c.getOutpoints("hash1")
					require.True(t, ok)
					require.Len(t, outpoints, 1)
					require.Contains(t, outpoints, op1.String())
					require.NotContains(t, outpoints, op2.String())
				},
			},
			{
				name: "entries expire after invalidation duration",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1})
					time.Sleep(100 * time.Millisecond)
				},
				assert: func(t *testing.T, c *tokenCache) {
					_, ok := c.getOutpoints("hash1")
					require.False(t, ok)
				},
			},
			{
				name: "entries from different hashes expire independently",
				setup: func(c *tokenCache) {
					c.add("hash1", []Outpoint{op1})
					time.Sleep(30 * time.Millisecond)
					c.add("hash2", []Outpoint{op2})
					time.Sleep(40 * time.Millisecond) // t≈70ms: hash1 expired, hash2 still live
				},
				assert: func(t *testing.T, c *tokenCache) {
					_, ok := c.getOutpoints("hash1")
					require.False(t, ok, "hash1 should have expired")

					_, ok = c.getOutpoints("hash2")
					require.True(t, ok, "hash2 should still be live")
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
