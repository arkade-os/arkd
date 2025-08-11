// This Redis-backed implementation of confirmationSessionsStore matches the API and semantics
// of the in-memory version, but is designed for distributed safety and cross-process correctness.
//
// In the in-memory version, session completion is signaled by directly closing a channel when
// all confirmations are received, because all state and notification are local to the process.
//
// In the Redis-backed version, state is shared across processes. As a result, we use a background
// goroutine (watchSessionCompletion) to poll Redis and close the local sessionCompleteCh channel
// when the session is complete. This ensures any process using this store can be notified, regardless
// of which process performed the final confirmation.
//
// For a truly distributed event notification, using Redis Pub/Sub should be considered: publish a message when
// the session completes, and have all interested processes subscribe to the channel and close their
// local sessionCompleteCh when they receive the event. This avoids polling and provides real-time
// notification across distributed systems.

package redislivestore

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

const (
	confirmationIntentsKey      = "confirmationSessions:intents"
	confirmationNumIntentsKey   = "confirmationSessions:numIntents"
	confirmationNumConfirmedKey = "confirmationSessions:numConfirmedIntents"
	confirmationInitializedKey  = "confirmationSessions:initialized"
)

type confirmationSessionsStore struct {
	rdb               *redis.Client
	sessionCompleteCh chan struct{}
	numOfRetries      int
}

func NewConfirmationSessionsStore(
	rdb *redis.Client, numOfRetries int,
) ports.ConfirmationSessionsStore {
	store := &confirmationSessionsStore{
		rdb:               rdb,
		sessionCompleteCh: make(chan struct{}),
		numOfRetries:      numOfRetries,
	}
	go store.watchSessionCompletion()
	return store
}

func (s *confirmationSessionsStore) Init(intentIDsHashes [][32]byte) {
	ctx := context.Background()
	pipe := s.rdb.TxPipeline()
	intents := make(map[string]interface{})
	for _, hash := range intentIDsHashes {
		intents[string(hash[:])] = 0
	}

	if len(intents) > 0 {
		pipe.Del(ctx, confirmationIntentsKey)
		pipe.HSet(ctx, confirmationIntentsKey, intents)
	}

	pipe.Set(ctx, confirmationNumIntentsKey, len(intentIDsHashes), 0)
	pipe.Set(ctx, confirmationNumConfirmedKey, 0, 0)
	pipe.Set(ctx, confirmationInitializedKey, 1, 0)
	if _, err := pipe.Exec(ctx); err != nil {
		log.Warnf("failed to initialize confirmation store: %v", err)
	}
}

func (s *confirmationSessionsStore) Confirm(intentId string) error {
	ctx := context.Background()
	hash := sha256.Sum256([]byte(intentId))
	hashKey := string(hash[:])
	for attempt := 0; attempt < s.numOfRetries; attempt++ {
		err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			confirmed, err := tx.HGet(ctx, confirmationIntentsKey, hashKey).Int()
			if errors.Is(err, redis.Nil) {
				return fmt.Errorf("intent hash not found")
			} else if err != nil {
				return err
			}

			if confirmed == 1 {
				return nil
			}

			numConfirmed, err := tx.Get(ctx, confirmationNumConfirmedKey).Int()
			if err != nil && !errors.Is(err, redis.Nil) {
				return err
			}

			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, confirmationIntentsKey, hashKey, 1)
				pipe.Set(ctx, confirmationNumConfirmedKey, numConfirmed+1, 0)

				return nil
			})
			return err
		})
		if err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("failed to confirm intent after retries")
}

func (s *confirmationSessionsStore) Get() *ports.ConfirmationSessions {
	ctx := context.Background()
	intents, _ := s.rdb.HGetAll(ctx, confirmationIntentsKey).Result()
	numIntents, _ := s.rdb.Get(ctx, confirmationNumIntentsKey).Int()
	numConfirmed, _ := s.rdb.Get(ctx, confirmationNumConfirmedKey).Int()
	intentsHashes := make(map[[32]byte]bool)
	for k, v := range intents {
		var hash [32]byte
		copy(hash[:], k)
		intentsHashes[hash] = v == "1"
	}
	return &ports.ConfirmationSessions{
		IntentsHashes:       intentsHashes,
		NumIntents:          numIntents,
		NumConfirmedIntents: numConfirmed,
	}
}

func (s *confirmationSessionsStore) Reset() {
	ctx := context.Background()
	pipe := s.rdb.TxPipeline()
	pipe.Del(ctx, confirmationIntentsKey)
	pipe.Del(ctx, confirmationNumIntentsKey)
	pipe.Del(ctx, confirmationNumConfirmedKey)
	pipe.Del(ctx, confirmationInitializedKey)
	_, _ = pipe.Exec(ctx)

	s.sessionCompleteCh = make(chan struct{})
	go s.watchSessionCompletion()
}

func (s *confirmationSessionsStore) Initialized() bool {
	ctx := context.Background()
	val, err := s.rdb.Get(ctx, confirmationInitializedKey).Int()
	return err == nil && val == 1
}

func (s *confirmationSessionsStore) SessionCompleted() <-chan struct{} {
	return s.sessionCompleteCh
}

func (s *confirmationSessionsStore) watchSessionCompletion() {
	ctx := context.Background()
	var chOnce sync.Once
	for {
		numIntents, _ := s.rdb.Get(ctx, confirmationNumIntentsKey).Int()
		numConfirmed, _ := s.rdb.Get(ctx, confirmationNumConfirmedKey).Int()
		if numIntents > 0 && numConfirmed == numIntents {
			chOnce.Do(func() { s.sessionCompleteCh <- struct{}{} })
			return
		}
	}
}
