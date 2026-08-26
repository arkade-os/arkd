package application

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// Fraud reactions rely on keyedMutex for two things: callers sharing a key never
// run concurrently (two forfeit broadcasts against the same connector tree would
// conflict), and entries don't accumulate for the lifetime of the process.
func TestKeyedMutex(t *testing.T) {
	const (
		keys           = 4
		goroutines     = 8
		perGoroutine   = 50
		expectedPerKey = goroutines * perGoroutine
	)

	locks := newKeyedMutex()

	// Deliberately unsynchronized: only the keyed lock keeps each counter safe,
	// so a broken lock shows up as a lost update here and as a report under -race.
	counters := make([]int, keys)

	wg := sync.WaitGroup{}
	for k := range keys {
		key := fmt.Sprintf("key-%d", k)
		for range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range perGoroutine {
					unlock := locks.lock(key)
					counters[k]++
					unlock()
				}
			}()
		}
	}
	wg.Wait()

	for k := range keys {
		require.Equal(t, expectedPerKey, counters[k], "lost update on key-%d", k)
	}

	require.Empty(t, locks.locks, "keyed locks not released once idle")
}
