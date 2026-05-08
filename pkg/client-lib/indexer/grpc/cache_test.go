package grpcIndexer

import (
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScriptsCache(t *testing.T) {
	t.Run("add", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			testCases := []struct {
				name     string
				setup    func(*scriptsCache)
				id       string
				scripts  []string
				expected []string
			}{
				{
					name:     "add scripts to new subscription",
					setup:    func(c *scriptsCache) { c.add("sub1", []string{"script1"}) },
					id:       "sub2",
					scripts:  []string{"script2"},
					expected: []string{"script2"},
				},
				{
					name: "add scripts to existing subscription",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
					},
					id:       "sub1",
					scripts:  []string{"script2", "script3"},
					expected: []string{"script1", "script2", "script3"},
				},
				{
					name: "add and duplicate scripts",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1", "script2"})
					},
					id:       "sub1",
					scripts:  []string{"script2", "script3"},
					expected: []string{"script1", "script2", "script3"},
				},
				{
					name: "add after replace adds to resolved id",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.replace("sub1", "sub2")
					},
					id:       "sub1",
					scripts:  []string{"script2"},
					expected: []string{"script1", "script2"},
				},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					c := newScriptsCache()
					tc.setup(c)
					c.add(tc.id, tc.scripts)
					got := c.get(tc.id)
					sort.Strings(got)
					sort.Strings(tc.expected)
					require.Equal(t, tc.expected, got)
				})
			}
		})
	})

	t.Run("get", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			testCases := []struct {
				name     string
				setup    func(*scriptsCache)
				id       string
				expected []string
			}{
				{
					name: "get existing scripts",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1", "script2"})
					},
					id:       "sub1",
					expected: []string{"script1", "script2"},
				},
				{
					name: "get scripts via replacement chain",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.replace("sub1", "sub2")
					},
					id:       "sub1",
					expected: []string{"script1"},
				},
				{
					name: "get scripts via multi-hop replacement chain",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.replace("sub1", "sub2")
						c.replace("sub2", "sub3")
					},
					id:       "sub1",
					expected: []string{"script1"},
				},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					c := newScriptsCache()
					tc.setup(c)
					got := c.get(tc.id)
					sort.Strings(got)
					sort.Strings(tc.expected)
					require.Equal(t, tc.expected, got)
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			testCases := []struct {
				name  string
				setup func(*scriptsCache)
				id    string
			}{
				{
					name:  "get from empty cache",
					setup: func(_ *scriptsCache) {},
					id:    "sub1",
				},
				{
					name: "get non-existent subscription",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
					},
					id: "sub2",
				},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					c := newScriptsCache()
					tc.setup(c)
					got := c.get(tc.id)
					require.Nil(t, got)
				})
			}
		})
	})

	t.Run("exists", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			testCases := []struct {
				name  string
				setup func(*scriptsCache)
				id    string
			}{
				{
					name: "subscription with scripts exists",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
					},
					id: "sub1",
				},
				{
					name: "subscription with no scripts still exists",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.removeScripts("sub1", []string{"script1"})
					},
					id: "sub1",
				},
				{
					name: "subscription exists via replacement chain",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.replace("sub1", "sub2")
					},
					id: "sub1",
				},
				{
					name: "subscription exists via multi-hop replacement chain",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.replace("sub1", "sub2")
						c.replace("sub2", "sub3")
					},
					id: "sub1",
				},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					c := newScriptsCache()
					tc.setup(c)
					require.True(t, c.exists(tc.id))
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			testCases := []struct {
				name  string
				setup func(*scriptsCache)
				id    string
			}{
				{
					name:  "empty cache",
					setup: func(_ *scriptsCache) {},
					id:    "sub1",
				},
				{
					name: "non-existent subscription",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
					},
					id: "sub2",
				},
				{
					name: "removed subscription does not exist",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.removeSubscription("sub1")
					},
					id: "sub1",
				},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					c := newScriptsCache()
					tc.setup(c)
					require.False(t, c.exists(tc.id))
				})
			}
		})
	})

	t.Run("removeScripts", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			testCases := []struct {
				name     string
				setup    func(*scriptsCache)
				id       string
				scripts  []string
				expected []string
			}{
				{
					name: "remove some scripts",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1", "script2", "script3"})
					},
					id:       "sub1",
					scripts:  []string{"script2"},
					expected: []string{"script1", "script3"},
				},
				{
					name: "remove all scripts",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1", "script2"})
					},
					id:       "sub1",
					scripts:  []string{"script1", "script2"},
					expected: nil,
				},
				{
					name: "remove via replacement chain",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1", "script2"})
						c.replace("sub1", "sub2")
					},
					id:       "sub1",
					scripts:  []string{"script1"},
					expected: []string{"script2"},
				},
				{
					name: "remove scripts via multi-hop replacement chain",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1", "script2"})
						c.replace("sub1", "sub2")
						c.replace("sub2", "sub3")
					},
					id:       "sub1",
					scripts:  []string{"script1"},
					expected: []string{"script2"},
				},
				{
					name:     "remove from non-existent subscription is no-op",
					setup:    func(_ *scriptsCache) {},
					id:       "sub1",
					scripts:  []string{"script1"},
					expected: nil,
				},
				{
					name: "remove non-existent scripts is no-op",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
					},
					id:       "sub1",
					scripts:  []string{"script99"},
					expected: []string{"script1"},
				},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					c := newScriptsCache()
					tc.setup(c)
					c.removeScripts(tc.id, tc.scripts)
					got := c.get(tc.id)
					sort.Strings(got)
					sort.Strings(tc.expected)
					require.Equal(t, tc.expected, got)
				})
			}
		})
	})

	t.Run("removeSubscription", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			testCases := []struct {
				name         string
				setup        func(*scriptsCache)
				id           string
				otherID      string
				otherScripts []string
			}{
				{
					name: "remove subscription",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
					},
					id: "sub1",
				},
				{
					name: "remove via replacement chain",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.replace("sub1", "sub2")
					},
					id: "sub1",
				},
				{
					name: "remove via multi-hop replacement chain",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.replace("sub1", "sub2")
						c.replace("sub2", "sub3")
					},
					id: "sub1",
				},
				{
					name: "remove does not affect other subscriptions",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.add("sub2", []string{"script2"})
					},
					id:           "sub1",
					otherID:      "sub2",
					otherScripts: []string{"script2"},
				},
				{
					name: "remove from middle of chain cleans upstream and downstream",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.replace("sub1", "sub2")
						c.replace("sub2", "sub3")
					},
					id: "sub2",
				},
				{
					name: "remove from tail of chain cleans upstream hops",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.replace("sub1", "sub2")
						c.replace("sub2", "sub3")
					},
					id: "sub3",
				},
				{
					name:  "remove non-existent subscription is no-op",
					setup: func(_ *scriptsCache) {},
					id:    "sub1",
				},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					c := newScriptsCache()
					tc.setup(c)
					c.removeSubscription(tc.id)
					got := c.get(tc.id)
					require.Nil(t, got)
					if tc.otherID != "" {
						got := c.get(tc.otherID)
						sort.Strings(got)
						sort.Strings(tc.otherScripts)
						require.Equal(t, tc.otherScripts, got)
					}
					// Make sure the replacement chain is cleaned
					require.Empty(t, c.replacements)
				})
			}
		})
	})

	t.Run("replace", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			testCases := []struct {
				name          string
				setup         func(*scriptsCache)
				oldID         string
				newID         string
				expectedNewID []string
			}{
				{
					name: "replace subscription id",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1", "script2"})
					},
					oldID:         "sub1",
					newID:         "sub2",
					expectedNewID: []string{"script1", "script2"},
				},
				{
					name: "replace with existing replacement chain",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.replace("sub1", "sub2")
					},
					oldID:         "sub2",
					newID:         "sub3",
					expectedNewID: []string{"script1"},
				},
				{
					name: "old id resolves via replacement chain",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.replace("sub1", "sub2")
					},
					oldID:         "sub1",
					newID:         "sub3",
					expectedNewID: []string{"script1"},
				},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					c := newScriptsCache()
					tc.setup(c)
					c.replace(tc.oldID, tc.newID)
					got := c.get(tc.newID)
					sort.Strings(got)
					sort.Strings(tc.expectedNewID)
					require.Equal(t, tc.expectedNewID, got)
					// Old id should still resolve via replacement chain.
					gotOld := c.get(tc.oldID)
					sort.Strings(gotOld)
					require.Equal(t, tc.expectedNewID, gotOld)
				})
			}
		})

		t.Run("no-op", func(t *testing.T) {
			testCases := []struct {
				name          string
				setup         func(*scriptsCache)
				oldID         string
				newID         string
				expectedOldID []string
				expectedNewID []string
			}{
				{
					name:          "replace non-existent subscription is no-op",
					setup:         func(_ *scriptsCache) {},
					oldID:         "sub1",
					newID:         "sub2",
					expectedOldID: nil,
					expectedNewID: nil,
				},
				{
					name: "self-replacement is no-op",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
					},
					oldID:         "sub1",
					newID:         "sub1",
					expectedOldID: []string{"script1"},
					expectedNewID: []string{"script1"},
				},
				{
					name: "replace to existing id is no-op",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.add("sub2", []string{"script2"})
					},
					oldID:         "sub1",
					newID:         "sub2",
					expectedOldID: []string{"script1"},
					expectedNewID: []string{"script2"},
				},
				{
					name: "replacement cycle is prevented",
					setup: func(c *scriptsCache) {
						c.add("sub1", []string{"script1"})
						c.replace("sub1", "sub2")
					},
					oldID:         "sub2",
					newID:         "sub1",
					expectedOldID: []string{"script1"},
					expectedNewID: []string{"script1"},
				},
			}
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					c := newScriptsCache()
					tc.setup(c)
					c.replace(tc.oldID, tc.newID)
					got := c.get(tc.oldID)
					sort.Strings(got)
					sort.Strings(tc.expectedOldID)
					require.Equal(t, tc.expectedOldID, got)
					got = c.get(tc.newID)
					sort.Strings(got)
					sort.Strings(tc.expectedNewID)
					require.Equal(t, tc.expectedNewID, got)
				})
			}
		})
	})

	t.Run("concurrent access", func(t *testing.T) {
		c := newScriptsCache()
		var wg sync.WaitGroup
		for i := range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				id := "sub1"
				scripts := []string{fmt.Sprintf("script_%d", i)}
				c.add(id, scripts)
				c.get(id)
				c.removeScripts(id, scripts)
			}()
		}
		wg.Wait()
	})

	// Run every mutating method concurrently against the same cache. The cache is protected by a
	// single mutex, so this test ensures there are no data races and that no invariant-breaking
	// interleaving blows up — e.g. replace() racing with removeSubscription() while the underlying
	// scriptsBySubId / replacements maps are being walked in two directions.
	t.Run("concurrent access with replace and removeSubscription", func(t *testing.T) {
		t.Run("distinct subscription ids", func(t *testing.T) {
			c := newScriptsCache()

			const workers = 50
			var wg sync.WaitGroup
			wg.Add(workers)
			for i := range workers {
				go func() {
					defer wg.Done()
					oldId := fmt.Sprintf("sub_%d", i)
					newId := fmt.Sprintf("sub_%d_replaced", i)
					script := fmt.Sprintf("script_%d", i)

					c.add(oldId, []string{script})
					c.get(oldId)
					c.replace(oldId, newId)
					c.get(newId)
					c.add(newId, []string{script + "_extra"})
					c.removeScripts(newId, []string{script})
					c.removeSubscription(oldId)
				}()
			}
			wg.Wait()

			// After all goroutines complete, every subscription should have been removed
			// and the replacements map should be fully drained.
			require.Empty(t, c.scriptsBySubId)
			require.Empty(t, c.replacements)
		})

		// Hammer every mutating method on the same shared id concurrently. Unlike the previous
		// test (distinct ids per worker), here all 50 goroutines contend on "sub1", so the final
		// state is non-deterministic. We assert internal consistency rather than an exact final
		// state: no self-replacements and no dangling chain tails.
		t.Run("same subscription id", func(t *testing.T) {
			c := newScriptsCache()
			c.add("sub1", []string{"seed"})

			const workers = 50
			var wg sync.WaitGroup
			wg.Add(workers)
			for i := range workers {
				go func() {
					defer wg.Done()
					id := "sub1"
					script := fmt.Sprintf("script_%d", i)
					newId := fmt.Sprintf("sub1_replaced_%d", i)

					c.add(id, []string{script})
					c.get(id)
					c.exists(id)
					c.replace(id, newId)
					c.removeScripts(id, []string{script})
					c.removeSubscription(id)
				}()
			}
			wg.Wait()

			// Every surviving entry in replacements must point at something still
			// reachable — either a live scriptsBySubId bucket or a further
			// replacement hop. No self-replacements are allowed.
			for oldId, newId := range c.replacements {
				require.NotEqual(t, oldId, newId, "self-replacement leaked into chain")
				_, directHit := c.scriptsBySubId[newId]
				_, viaChain := c.replacements[newId]
				require.True(
					t, directHit || viaChain,
					"replacement %q -> %q dangles: newId has no scripts entry and no further replacement",
					oldId, newId,
				)
			}
		})
	})
}
