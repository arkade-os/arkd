package wallet

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestNewOutpointLocker(t *testing.T) {
	lockDuration := 5 * time.Minute
	locker := newOutpointLocker(lockDuration)

	require.NotNil(t, locker)
	require.Equal(t, lockDuration, locker.lockExpiry)
	require.NotNil(t, locker.lockedOutpoints)
	require.Empty(t, locker.lockedOutpoints)
}

func TestOutpointLocker_Lock(t *testing.T) {
	lockDuration := 1 * time.Hour
	locker := newOutpointLocker(lockDuration)

	hash0 := random32Bytes()
	hash1 := random32Bytes()
	outpoint1 := wire.OutPoint{Hash: hash0, Index: 0}
	outpoint2 := wire.OutPoint{Hash: hash1, Index: 1}

	// test locking single outpoint
	err := locker.lock(context.Background(), outpoint1)
	require.NoError(t, err)

	// verify outpoint is locked
	lockedOutpoints, err := locker.get(context.Background())
	require.NoError(t, err)
	require.Len(t, lockedOutpoints, 1)
	require.Contains(t, lockedOutpoints, outpoint1)

	// test locking multiple outpoints
	err = locker.lock(context.Background(), outpoint2)
	require.NoError(t, err)

	// verify both outpoints are locked
	lockedOutpoints, err = locker.get(context.Background())
	require.NoError(t, err)
	require.Len(t, lockedOutpoints, 2)
	require.Contains(t, lockedOutpoints, outpoint1)
	require.Contains(t, lockedOutpoints, outpoint2)

	// test locking same outpoint again (should update expiry)
	time.Sleep(10 * time.Millisecond) // Small delay to ensure different timestamps
	err = locker.lock(context.Background(), outpoint1)
	require.NoError(t, err)

	// verify outpoint is still locked with updated expiry
	lockedOutpoints, err = locker.get(context.Background())
	require.NoError(t, err)
	require.Len(t, lockedOutpoints, 2)
	require.Contains(t, lockedOutpoints, outpoint1)
	require.Contains(t, lockedOutpoints, outpoint2)
}

func TestOutpointLocker_Get(t *testing.T) {
	lockDuration := 100 * time.Millisecond
	locker := newOutpointLocker(lockDuration)

	hash0 := random32Bytes()
	hash1 := random32Bytes()
	outpoint1 := wire.OutPoint{Hash: hash0, Index: 0}
	outpoint2 := wire.OutPoint{Hash: hash1, Index: 1}

	// lock outpoints
	err := locker.lock(context.Background(), outpoint1, outpoint2)
	require.NoError(t, err)

	lockedOutpoints, err := locker.get(context.Background())
	require.NoError(t, err)
	require.Len(t, lockedOutpoints, 2)
	require.Contains(t, lockedOutpoints, outpoint1)
	require.Contains(t, lockedOutpoints, outpoint2)

	// wait for locks to expire
	time.Sleep(lockDuration + 50*time.Millisecond)

	lockedOutpoints, err = locker.get(context.Background())
	require.NoError(t, err)
	require.Empty(t, lockedOutpoints)
}

func TestOutpointLocker_ConcurrentGetAndLock(t *testing.T) {
	// half lock, half get
	numberOfRoutines := 100
	lockDuration := 100 * time.Millisecond
	locker := newOutpointLocker(lockDuration)

	outpoints := make([]wire.OutPoint, 0, 10)
	for index := range numberOfRoutines / 2 {
		outpoints = append(outpoints, wire.OutPoint{Hash: random32Bytes(), Index: uint32(index)})
	}

	wg := sync.WaitGroup{}
	wg.Add(numberOfRoutines)

	// start 10 goroutines that lock the outpoint
	for _, outpoint := range outpoints {
		go func() {
			err := locker.lock(context.Background(), outpoint)
			require.NoError(t, err)
			wg.Done()
		}()
	}

	// start 10 goroutines that get locked outpoints
	for range numberOfRoutines / 2 {
		go func() {
			_, err := locker.get(context.Background())
			require.NoError(t, err)
			wg.Done()
		}()
	}

	wg.Wait()

	lockedOutpoints, err := locker.get(context.Background())
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
