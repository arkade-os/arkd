package inmemorylivestore

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/arkade-os/arkd/internal/core/ports"
)

type confirmationSessionsStore struct {
	lock                *sync.RWMutex
	intentsHashes       map[[32]byte]bool // hash --> confirmed
	numIntents          int
	numConfirmedIntents int
	initialized         bool
	sessionCompleteCh   chan struct{}
}

func NewConfirmationSessionsStore() ports.ConfirmationSessionsStore {
	return &confirmationSessionsStore{
		lock:              &sync.RWMutex{},
		sessionCompleteCh: make(chan struct{}),
	}
}

func (c *confirmationSessionsStore) Init(_ context.Context, intentIDsHashes [][32]byte) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	hashes := make(map[[32]byte]bool)
	for _, hash := range intentIDsHashes {
		hashes[hash] = false
	}

	c.sessionCompleteCh = make(chan struct{})
	c.intentsHashes = hashes
	c.numIntents = len(intentIDsHashes)
	c.initialized = true
	return nil
}

func (c *confirmationSessionsStore) Confirm(_ context.Context, intentId string) error {
	hash := sha256.Sum256([]byte(intentId))
	c.lock.Lock()
	defer c.lock.Unlock()
	alreadyConfirmed, ok := c.intentsHashes[hash]
	if !ok {
		return fmt.Errorf("intent hash not found")
	}

	if alreadyConfirmed {
		return nil
	}

	c.numConfirmedIntents++
	c.intentsHashes[hash] = true

	if c.numConfirmedIntents == c.numIntents {
		go func() {
			c.sessionCompleteCh <- struct{}{}
		}()
	}

	return nil
}

func (c *confirmationSessionsStore) Get(_ context.Context) (*ports.ConfirmationSessions, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return &ports.ConfirmationSessions{
		IntentsHashes:       c.intentsHashes,
		NumIntents:          c.numIntents,
		NumConfirmedIntents: c.numConfirmedIntents,
	}, nil
}

func (c *confirmationSessionsStore) Reset(_ context.Context) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.sessionCompleteCh != nil {
		close(c.sessionCompleteCh)
	}
	c.intentsHashes = make(map[[32]byte]bool)
	c.numIntents = 0
	c.numConfirmedIntents = 0
	c.initialized = false
	return nil
}

func (c *confirmationSessionsStore) Initialized(_ context.Context) bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.initialized
}

func (c *confirmationSessionsStore) SessionCompleted() <-chan struct{} {
	return c.sessionCompleteCh
}
