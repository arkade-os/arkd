// Redis-backed implementation of treeSigningSessionsStore. All session state is stored in Redis hashes.
// Notification channels for nonces and signatures collection are implemented via goroutines that poll Redis state.
// For true distributed notification, consider using Redis Pub/Sub.

package redislivestore

import (
	"context"
	"encoding/json"
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
}

func NewTreeSigningSessionsStore(rdb *redis.Client) ports.TreeSigningSessionsStore {
	return &treeSigningSessionsStore{
		rdb:          rdb,
		nonceChs:     make(map[string]chan struct{}),
		sigsChs:      make(map[string]chan struct{}),
		ctxs:         make(map[string]context.CancelFunc),
		pollInterval: 100 * time.Millisecond,
	}
}

func (s *treeSigningSessionsStore) New(
	roundId string, uniqueSignersPubKeys map[string]struct{},
) *ports.MusigSigningSession {
	s.lock.Lock()
	defer s.lock.Unlock()

	ctx := context.Background()
	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	cosignersBytes, _ := json.Marshal(uniqueSignersPubKeys)
	meta := map[string]interface{}{
		"Cosigners":   cosignersBytes,
		"NbCosigners": len(uniqueSignersPubKeys) + 1, // operator included
	}
	s.rdb.HSet(ctx, metaKey, meta)

	watchCtx, cancel := context.WithCancel(context.Background())
	s.ctxs[roundId] = cancel
	s.nonceChs[roundId] = make(chan struct{})
	s.sigsChs[roundId] = make(chan struct{})

	go s.watchNoncesCollected(watchCtx, roundId)
	go s.watchSigsCollected(watchCtx, roundId)

	return &ports.MusigSigningSession{
		Cosigners:   uniqueSignersPubKeys,
		NbCosigners: len(uniqueSignersPubKeys) + 1,
		Nonces:      make(map[string]tree.TreeNonces),
		Signatures:  make(map[string]tree.TreePartialSigs),
	}
}

func (s *treeSigningSessionsStore) Get(roundId string) (*ports.MusigSigningSession, bool) {
	ctx := context.Background()

	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	meta, err := s.rdb.HGetAll(ctx, metaKey).Result()
	if err != nil || len(meta) == 0 {
		return nil, false
	}

	var cosigners map[string]struct{}
	if err := json.Unmarshal([]byte(meta["Cosigners"]), &cosigners); err != nil {
		return nil, false
	}
	nbCosigners := 0
	if _, err := fmt.Sscanf(meta["NbCosigners"], "%d", &nbCosigners); err != nil {
		log.Warnf("get:failed to parse NbCosigners: %v", err)
	}

	noncesKey := fmt.Sprintf(treeSessNoncesKeyFmt, roundId)
	noncesMap, _ := s.rdb.HGetAll(ctx, noncesKey).Result()
	nonces := make(map[string]tree.TreeNonces)
	for pub, val := range noncesMap {
		var n tree.TreeNonces
		if err := json.Unmarshal([]byte(val), &n); err != nil {
			log.Warnf("get:failed to unmarshal nonces for %s: %v", pub, err)
			return nil, false
		}
		nonces[pub] = n
	}

	sigsKey := fmt.Sprintf(treeSessSigsKeyFmt, roundId)
	sigsMap, _ := s.rdb.HGetAll(ctx, sigsKey).Result()
	sigs := make(map[string]tree.TreePartialSigs)
	for pub, val := range sigsMap {
		signatures := make(tree.TreePartialSigs)
		if err := json.Unmarshal([]byte(val), &signatures); err != nil {
			log.Warnf("get:failed to unmarshal signatures for %s: %v", pub, err)
			return nil, false
		}
		sigs[pub] = signatures
	}

	sess := &ports.MusigSigningSession{
		Cosigners:   cosigners,
		NbCosigners: nbCosigners,
		Nonces:      nonces,
		Signatures:  sigs,
	}
	return sess, true
}

func (s *treeSigningSessionsStore) Delete(roundId string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	ctx := context.Background()
	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	noncesKey := fmt.Sprintf(treeSessNoncesKeyFmt, roundId)
	sigsKey := fmt.Sprintf(treeSessSigsKeyFmt, roundId)
	s.rdb.Del(ctx, metaKey, noncesKey, sigsKey)

	if cancel, exists := s.ctxs[roundId]; exists {
		cancel()
		delete(s.ctxs, roundId)
	}

	if ch, exists := s.nonceChs[roundId]; exists {
		close(ch)
		delete(s.nonceChs, roundId)
	}
	if ch, exists := s.sigsChs[roundId]; exists {
		close(ch)
		delete(s.sigsChs, roundId)
	}
}

func (s *treeSigningSessionsStore) AddNonces(
	ctx context.Context, roundId string, pubkey string, nonces tree.TreeNonces,
) error {
	noncesKey := fmt.Sprintf(treeSessNoncesKeyFmt, roundId)
	val, _ := json.Marshal(nonces)
	if err := s.rdb.HSet(ctx, noncesKey, pubkey, val).Err(); err != nil {
		return err
	}
	return nil
}

func (s *treeSigningSessionsStore) AddSignatures(
	ctx context.Context, roundId string, pubkey string, sigs tree.TreePartialSigs,
) error {
	sigsKey := fmt.Sprintf(treeSessSigsKeyFmt, roundId)
	val, _ := json.Marshal(sigs)
	if err := s.rdb.HSet(ctx, sigsKey, pubkey, val).Err(); err != nil {
		return err
	}
	return nil
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
	for {
		select {
		case <-ctx.Done():
			return
		default:
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
	for {
		select {
		case <-ctx.Done():
			return
		default:
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
