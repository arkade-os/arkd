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
	lock              sync.RWMutex
	sessionCompleteCh chan struct{}
	cancel            context.CancelFunc
	pollInterval      time.Duration
	numOfRetries      int
	retryDelay        time.Duration
}

func NewConfirmationSessionsStore(
	rdb *redis.Client, numOfRetries int,
) ports.ConfirmationSessionsStore {
	ctx, cancel := context.WithCancel(context.Background())
	store := &confirmationSessionsStore{
		rdb:               rdb,
		sessionCompleteCh: make(chan struct{}),
		cancel:            cancel,
		pollInterval:      100 * time.Millisecond,
		numOfRetries:      numOfRetries,
		retryDelay:        10 * time.Millisecond,
	}
	go store.watchSessionCompletion(ctx)
	return store
}

func (s *confirmationSessionsStore) Init(ctx context.Context, intentIDsHashes [][32]byte) error {
	intents := make(map[string]interface{})
	for _, hash := range intentIDsHashes {
		intents[string(hash[:])] = 0
	}

	var err error
	keys := []string{
		confirmationIntentsKey, confirmationNumIntentsKey,
		confirmationNumConfirmedKey, confirmationInitializedKey,
	}
	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				if len(intents) > 0 {
					pipe.Del(ctx, confirmationIntentsKey)
					pipe.HSet(ctx, confirmationIntentsKey, intents)
				}

				pipe.Set(ctx, confirmationNumIntentsKey, len(intentIDsHashes), 0)
				pipe.Set(ctx, confirmationNumConfirmedKey, 0, 0)
				pipe.Set(ctx, confirmationInitializedKey, 1, 0)
				return nil
			})
			return err
		}, keys...); err == nil {
			return nil
		}
		time.Sleep(s.retryDelay)
	}
	return fmt.Errorf("failed to init confirmation session after max num of retries: %v", err)
}

func (s *confirmationSessionsStore) Confirm(ctx context.Context, intentId string) error {
	hash := sha256.Sum256([]byte(intentId))
	hashKey := string(hash[:])

	confirmed, err := s.rdb.HGet(ctx, confirmationIntentsKey, hashKey).Int()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return fmt.Errorf("intent hash not found")
		}
		return fmt.Errorf("failed to get intent %s: %v", intentId, err)
	}
	if confirmed == 1 {
		return nil
	}

	numConfirmed, err := s.rdb.Get(ctx, confirmationNumConfirmedKey).Int()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("failed to get number of confirmed intents: %v", err)
	}

	keys := []string{confirmationIntentsKey, confirmationNumConfirmedKey}
	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, confirmationIntentsKey, hashKey, 1)
				pipe.Set(ctx, confirmationNumConfirmedKey, numConfirmed+1, 0)

				return nil
			})
			return err
		}, keys...); err == nil {
			return nil
		}
		time.Sleep(s.retryDelay)
	}
	return fmt.Errorf("failed to confirm intent after retries: %v", err)
}

func (s *confirmationSessionsStore) Get(ctx context.Context) (*ports.ConfirmationSessions, error) {
	intents, err := s.rdb.HGetAll(ctx, confirmationIntentsKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get intents: %v", err)
	}
	numIntents, err := s.rdb.Get(ctx, confirmationNumIntentsKey).Int()
	if err != nil {
		return nil, fmt.Errorf("failed to get number of intents: %v", err)
	}
	numConfirmed, err := s.rdb.Get(ctx, confirmationNumConfirmedKey).Int()
	if err != nil {
		return nil, fmt.Errorf("failed to get number of confirmed intents: %v", err)
	}
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
	}, nil
}

func (s *confirmationSessionsStore) Reset(ctx context.Context) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	var err error
	keys := []string{
		confirmationIntentsKey, confirmationNumIntentsKey,
		confirmationNumConfirmedKey, confirmationInitializedKey,
	}
	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Del(
					ctx, confirmationIntentsKey, confirmationNumIntentsKey,
					confirmationNumConfirmedKey, confirmationInitializedKey,
				)
				return nil
			})
			return err
		}, keys...); err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf(
			"failed to reset confirmation session after max number of retries: %v", err,
		)
	}

	if s.cancel != nil {
		s.cancel()
	}

	watchCtx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.sessionCompleteCh = make(chan struct{})
	go s.watchSessionCompletion(watchCtx)
	return nil
}

func (s *confirmationSessionsStore) Initialized(ctx context.Context) bool {
	val, err := s.rdb.Get(ctx, confirmationInitializedKey).Int()
	return err == nil && val == 1
}

func (s *confirmationSessionsStore) SessionCompleted() <-chan struct{} {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.sessionCompleteCh
}

func (s *confirmationSessionsStore) watchSessionCompletion(ctx context.Context) {
	var chOnce sync.Once
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			numIntents, _ := s.rdb.Get(ctx, confirmationNumIntentsKey).Int()
			numConfirmed, _ := s.rdb.Get(ctx, confirmationNumConfirmedKey).Int()
			if numIntents > 0 && numConfirmed == numIntents {
				s.lock.RLock()
				ch := s.sessionCompleteCh
				s.lock.RUnlock()
				if ch != nil {
					chOnce.Do(func() {
						select {
						case <-ctx.Done():
							return
						default:
							func() {
								defer func() {
									if r := recover(); r != nil {
										log.Warnf(
											"watchSessionCompletion:recovered from panic: %v", r,
										)
									}
								}()
								select {
								case ch <- struct{}{}:
								case <-ctx.Done():
									return
								}
							}()
						}
					})
				}
				return
			}
		}
	}
}
