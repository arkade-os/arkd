package inmemorylivestore

import (
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

func (c *confirmationSessionsStore) Init(intentIDsHashes [][32]byte) {
	c.lock.Lock()
	defer c.lock.Unlock()

	hashes := make(map[[32]byte]bool)
	for _, hash := range intentIDsHashes {
		hashes[hash] = false
	}

	c.intentsHashes = hashes
	c.numIntents = len(intentIDsHashes)
	c.initialized = true
}

func (c *confirmationSessionsStore) Confirm(intentId string) error {
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
		select {
		case c.sessionCompleteCh <- struct{}{}:
		default:
		}
	}

	return nil
}

func (c *confirmationSessionsStore) Get() *ports.ConfirmationSessions {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return &ports.ConfirmationSessions{
		IntentsHashes:       c.intentsHashes,
		NumIntents:          c.numIntents,
		NumConfirmedIntents: c.numConfirmedIntents,
	}
}

func (c *confirmationSessionsStore) Reset() {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.intentsHashes = make(map[[32]byte]bool)
	c.numIntents = 0
	c.numConfirmedIntents = 0
	c.initialized = false
}

func (c *confirmationSessionsStore) Initialized() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.initialized
}

func (c *confirmationSessionsStore) SessionCompleted() <-chan struct{} {
	return c.sessionCompleteCh
}
