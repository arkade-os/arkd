package wallet

import (
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestOutpointLocker(t *testing.T) {
	t.Run("new", func(t *testing.T) {
		lockDuration := 5 * time.Minute
		locker := newOutpointLocker(lockDuration)

		require.NotNil(t, locker)
		require.Equal(t, lockDuration, locker.lockExpiry)
		require.NotNil(t, locker.lockedOutpoints)
		require.Empty(t, locker.lockedOutpoints)
	})

	t.Run("lock", func(t *testing.T) {
		lockDuration := 1 * time.Hour
		locker := newOutpointLocker(lockDuration)

		outpoint1 := wire.OutPoint{Hash: random32Bytes(), Index: 0}
		outpoint2 := wire.OutPoint{Hash: random32Bytes(), Index: 1}

		// test locking single outpoint
		err := locker.lock(t.Context(), outpoint1)
		require.NoError(t, err)

		// verify outpoint is locked
		lockedOutpoints, err := locker.get(t.Context())
		require.NoError(t, err)
		require.Len(t, lockedOutpoints, 1)
		require.Contains(t, lockedOutpoints, outpoint1)

		// test locking multiple outpoints
		err = locker.lock(t.Context(), outpoint2)
		require.NoError(t, err)

		// verify both outpoints are locked
		lockedOutpoints, err = locker.get(t.Context())
		require.NoError(t, err)
		require.Len(t, lockedOutpoints, 2)
		require.Contains(t, lockedOutpoints, outpoint1)
		require.Contains(t, lockedOutpoints, outpoint2)

		// test locking same outpoint again
		time.Sleep(10 * time.Millisecond)
		err = locker.lock(t.Context(), outpoint1)
		require.ErrorContains(t, err, "already locked")

		// verify outpoint is still locked with updated expiry
		lockedOutpoints, err = locker.get(t.Context())
		require.NoError(t, err)
		require.Len(t, lockedOutpoints, 2)
		require.Contains(t, lockedOutpoints, outpoint1)
		require.Contains(t, lockedOutpoints, outpoint2)
	})

	t.Run("lock and unlock", func(t *testing.T) {
		lockDuration := 100 * time.Millisecond
		locker := newOutpointLocker(lockDuration)

		outpoint1 := wire.OutPoint{Hash: random32Bytes(), Index: 0}
		outpoint2 := wire.OutPoint{Hash: random32Bytes(), Index: 1}

		// lock outpoints
		err := locker.lock(t.Context(), outpoint1, outpoint2)
		require.NoError(t, err)

		lockedOutpoints, err := locker.get(t.Context())
		require.NoError(t, err)
		require.Len(t, lockedOutpoints, 2)
		require.Contains(t, lockedOutpoints, outpoint1)
		require.Contains(t, lockedOutpoints, outpoint2)

		// wait for locks to expire
		time.Sleep(lockDuration + 50*time.Millisecond)

		lockedOutpoints, err = locker.get(t.Context())
		require.NoError(t, err)
		require.Empty(t, lockedOutpoints)
	})
}

func TestOutpointLocker_ConcurrentGetAndLock(t *testing.T) {
	// half lock, half get
	numberOfRoutines := 100
	lockDuration := 100 * time.Millisecond
	locker := newOutpointLocker(lockDuration)

	outpoints := make([]wire.OutPoint, 0, numberOfRoutines/2)
	for index := range numberOfRoutines / 2 {
		outpoints = append(outpoints, wire.OutPoint{Hash: random32Bytes(), Index: uint32(index)})
	}

	wg := sync.WaitGroup{}
	wg.Add(numberOfRoutines)

	go func() {
		// start one half of goroutines that lock the outpoint
		for _, outpoint := range outpoints {
			go func(outpoint wire.OutPoint) {
				err := locker.lock(t.Context(), outpoint)
				require.NoError(t, err)
				wg.Done()
			}(outpoint)
		}
	}()

	go func() {
		// start the other half of goroutines that get locked outpoints
		for range numberOfRoutines / 2 {
			go func() {
				_, err := locker.get(t.Context())
				require.NoError(t, err)
				wg.Done()
			}()
		}
	}()

	wg.Wait()

	lockedOutpoints, err := locker.get(t.Context())
	require.NoError(t, err)
	require.Len(t, lockedOutpoints, len(outpoints))
	for _, outpoint := range outpoints {
		require.Contains(t, lockedOutpoints, outpoint)
	}
}

func random32Bytes() [32]byte {
	var b [32]byte
	rand.Read(b[:])
	return b
}
