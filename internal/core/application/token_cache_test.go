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
}
