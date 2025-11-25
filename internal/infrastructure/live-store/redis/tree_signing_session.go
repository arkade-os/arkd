// Redis-backed implementation of treeSigningSessionsStore. All session state is stored in Redis hashes.
// Notification channels for nonces and signatures collection are implemented via goroutines that poll Redis state.
// For true distributed notification, consider using Redis Pub/Sub.

package redislivestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

const (
	treeSessMetaKeyFmt   = "treeSignSess:%s:meta"
	treeSessNoncesKeyFmt = "treeSignSess:%s:nonces"
	treeSessSigsKeyFmt   = "treeSignSess:%s:sigs"
)

type treeSigningSessionsStore struct {
	rdb          *redis.Client
	lock         sync.RWMutex
	nonceChs     map[string]chan struct{}
	sigsChs      map[string]chan struct{}
	ctxs         map[string]context.CancelFunc
	pollInterval time.Duration
	numOfRetries int
	retryDelay   time.Duration
}

func NewTreeSigningSessionsStore(
	rdb *redis.Client, numOfRetries int,
) ports.TreeSigningSessionsStore {
	return &treeSigningSessionsStore{
		rdb:          rdb,
		nonceChs:     make(map[string]chan struct{}),
		sigsChs:      make(map[string]chan struct{}),
		ctxs:         make(map[string]context.CancelFunc),
		pollInterval: 100 * time.Millisecond,
		numOfRetries: numOfRetries,
		retryDelay:   10 * time.Millisecond,
	}
}

func (s *treeSigningSessionsStore) New(
	ctx context.Context, roundId string, uniqueSignersPubKeys map[string]struct{},
) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	cosignersBytes, _ := json.Marshal(uniqueSignersPubKeys)
	meta := map[string]interface{}{
		"Cosigners":   cosignersBytes,
		"NbCosigners": len(uniqueSignersPubKeys) + 1, // operator included
	}

	var err error
	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, metaKey, meta)
				return nil
			})
			return err
		}); err == nil {
			break
		}
		time.Sleep(s.retryDelay)
	}
	if err != nil {
		return err
	}

	watchCtx, cancel := context.WithCancel(context.Background())
	s.ctxs[roundId] = cancel
	s.nonceChs[roundId] = make(chan struct{})
	s.sigsChs[roundId] = make(chan struct{})

	go s.watchNoncesCollected(watchCtx, roundId)
	go s.watchSigsCollected(watchCtx, roundId)

	return nil
}

func (s *treeSigningSessionsStore) Get(
	ctx context.Context, roundId string,
) (*ports.MusigSigningSession, error) {
	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	meta, err := s.rdb.HGetAll(ctx, metaKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}
	if len(meta) == 0 {
		return nil, nil
	}

	var cosigners map[string]struct{}
	if err := json.Unmarshal([]byte(meta["Cosigners"]), &cosigners); err != nil {
		return nil, fmt.Errorf("malformed cosigners in storage: %v", err)
	}
	nbCosigners := 0
	if _, err := fmt.Sscanf(meta["NbCosigners"], "%d", &nbCosigners); err != nil {
		return nil, fmt.Errorf("malformed number of cosigners in storage: %v", err)
	}

	noncesKey := fmt.Sprintf(treeSessNoncesKeyFmt, roundId)
	noncesMap, err := s.rdb.HGetAll(ctx, noncesKey).Result()
	if err != nil {
		return nil, err
	}

	nonces := make(map[string]tree.TreeNonces)
	for pub, val := range noncesMap {
		var n tree.TreeNonces
		if err := json.Unmarshal([]byte(val), &n); err != nil {
			return nil, fmt.Errorf("malformed nonces in storage for cosigner %s: %v", pub, err)
		}
		nonces[pub] = n
	}

	sigsKey := fmt.Sprintf(treeSessSigsKeyFmt, roundId)
	sigsMap, err := s.rdb.HGetAll(ctx, sigsKey).Result()
	if err != nil {
		return nil, err
	}

	sigs := make(map[string]tree.TreePartialSigs)
	for pub, val := range sigsMap {
		signatures := make(tree.TreePartialSigs)
		if err := json.Unmarshal([]byte(val), &signatures); err != nil {
			return nil, fmt.Errorf("malformed signatures in storage for cosigner %s: %v", pub, err)
		}
		sigs[pub] = signatures
	}

	return &ports.MusigSigningSession{
		Cosigners:   cosigners,
		NbCosigners: nbCosigners,
		Nonces:      nonces,
		Signatures:  sigs,
	}, nil
}

func (s *treeSigningSessionsStore) Delete(ctx context.Context, roundId string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	noncesKey := fmt.Sprintf(treeSessNoncesKeyFmt, roundId)
	sigsKey := fmt.Sprintf(treeSessSigsKeyFmt, roundId)

	var err error
	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Del(ctx, metaKey, noncesKey, sigsKey)
				return nil
			})
			return err
		}); err == nil {
			break
		}
		time.Sleep(s.retryDelay)
	}
	if err != nil {
		return err
	}

	if cancel, ok := s.ctxs[roundId]; ok {
		cancel()
		delete(s.ctxs, roundId)
	}

	if ch, ok := s.nonceChs[roundId]; ok {
		close(ch)
		delete(s.nonceChs, roundId)
	}
	if ch, ok := s.sigsChs[roundId]; ok {
		close(ch)
		delete(s.sigsChs, roundId)
	}

	return nil
}

func (s *treeSigningSessionsStore) AddNonces(
	ctx context.Context, roundId string, pubkey string, nonces tree.TreeNonces,
) error {
	noncesKey := fmt.Sprintf(treeSessNoncesKeyFmt, roundId)
	val, err := json.Marshal(nonces)
	if err != nil {
		return fmt.Errorf("failed to marshal nonces: %v", err)
	}

	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, noncesKey, pubkey, val)
				return nil
			})
			return err
		}); err == nil {
			return nil
		}
		time.Sleep(s.retryDelay)
	}
	return err
}

func (s *treeSigningSessionsStore) AddSignatures(
	ctx context.Context, roundId string, pubkey string, sigs tree.TreePartialSigs,
) error {
	sigsKey := fmt.Sprintf(treeSessSigsKeyFmt, roundId)
	val, err := json.Marshal(sigs)
	if err != nil {
		return fmt.Errorf("failed to marshal signatures: %v", err)
	}

	for range s.numOfRetries {
		if err = s.rdb.Watch(ctx, func(tx *redis.Tx) error {
			_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, sigsKey, pubkey, val)
				return nil
			})
			return err
		}); err == nil {
			return nil
		}
		time.Sleep(s.retryDelay)
	}
	return err
}

func (s *treeSigningSessionsStore) NoncesCollected(roundId string) <-chan struct{} {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.nonceChs[roundId]
}

func (s *treeSigningSessionsStore) SignaturesCollected(roundId string) <-chan struct{} {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.sigsChs[roundId]
}

func (s *treeSigningSessionsStore) watchNoncesCollected(ctx context.Context, roundId string) {
	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	noncesKey := fmt.Sprintf(treeSessNoncesKeyFmt, roundId)

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			meta, err := s.rdb.HGetAll(ctx, metaKey).Result()
			if err != nil || len(meta) == 0 {
				continue
			}
			nbCosigners := 0
			if _, err := fmt.Sscanf(meta["NbCosigners"], "%d", &nbCosigners); err != nil {
				log.Warnf("watchNoncesCollected:failed to parse NbCosigners: %v", err)
				continue
			}
			noncesMap, _ := s.rdb.HGetAll(ctx, noncesKey).Result()
			if len(noncesMap) == nbCosigners-1 {
				s.lock.RLock()
				ch := s.nonceChs[roundId]
				s.lock.RUnlock()
				if ch != nil {
					select {
					case <-ctx.Done():
						return
					default:
						func() {
							defer func() {
								if r := recover(); r != nil {
									log.Warnf("watchNoncesCollected:recovered from panic: %v", r)
								}
							}()
							select {
							case ch <- struct{}{}:
							case <-ctx.Done():
								return
							}
						}()
					}
				}
				return
			}
		}
	}
}

func (s *treeSigningSessionsStore) watchSigsCollected(ctx context.Context, roundId string) {
	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	sigsKey := fmt.Sprintf(treeSessSigsKeyFmt, roundId)

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			meta, err := s.rdb.HGetAll(ctx, metaKey).Result()
			if err != nil || len(meta) == 0 {
				continue
			}
			nbCosigners := 0
			if _, err := fmt.Sscanf(meta["NbCosigners"], "%d", &nbCosigners); err != nil {
				log.Warnf("watchSigsCollected:failed to parse NbCosigners: %v", err)
				continue
			}
			sigsMap, _ := s.rdb.HGetAll(ctx, sigsKey).Result()
			if len(sigsMap) == nbCosigners-1 {
				s.lock.RLock()
				ch := s.sigsChs[roundId]
				s.lock.RUnlock()
				if ch != nil {
					select {
					case <-ctx.Done():
						return
					default:
						func() {
							defer func() {
								if r := recover(); r != nil {
									log.Warnf("watchSigsCollected:recovered from panic: %v", r)
								}
							}()
							select {
							case ch <- struct{}{}:
							case <-ctx.Done():
								return
							}
						}()
					}
				}
				return
			}
		}
	}
}
