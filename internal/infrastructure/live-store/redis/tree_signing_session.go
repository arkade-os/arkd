// Redis-backed implementation of treeSigningSessionsStore. All session state is stored in Redis hashes.
// Notification channels for nonces and signatures collection are implemented via goroutines that poll Redis state.
// For true distributed notification, consider using Redis Pub/Sub.

package redislivestore

import (
	"context"
	"encoding/json"
	"fmt"
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
	nonceCh      chan struct{}
	sigsCh       chan struct{}
	pollInterval time.Duration
}

func NewTreeSigningSessionsStore(rdb *redis.Client) ports.TreeSigningSessionsStore {
	return &treeSigningSessionsStore{
		rdb:          rdb,
		pollInterval: 100 * time.Millisecond,
	}
}

func (s *treeSigningSessionsStore) New(
	roundId string, uniqueSignersPubKeys map[string]struct{},
) *ports.MusigSigningSession {
	ctx := context.Background()
	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	cosignersBytes, _ := json.Marshal(uniqueSignersPubKeys)
	meta := map[string]interface{}{
		"Cosigners":   cosignersBytes,
		"NbCosigners": len(uniqueSignersPubKeys) + 1, // operator included
	}
	s.rdb.HSet(ctx, metaKey, meta)

	s.nonceCh = make(chan struct{})
	s.sigsCh = make(chan struct{})
	go s.watchNoncesCollected(roundId)
	go s.watchSigsCollected(roundId)

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
	ctx := context.Background()
	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	noncesKey := fmt.Sprintf(treeSessNoncesKeyFmt, roundId)
	sigsKey := fmt.Sprintf(treeSessSigsKeyFmt, roundId)
	s.rdb.Del(ctx, metaKey, noncesKey, sigsKey)
	if s.nonceCh != nil {
		close(s.nonceCh)
		s.nonceCh = nil
	}
	if s.sigsCh != nil {
		close(s.sigsCh)
		s.sigsCh = nil
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
	return s.nonceCh
}

func (s *treeSigningSessionsStore) SignaturesCollected(roundId string) <-chan struct{} {
	return s.sigsCh
}

func (s *treeSigningSessionsStore) watchNoncesCollected(roundId string) {
	ctx := context.Background()
	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	noncesKey := fmt.Sprintf(treeSessNoncesKeyFmt, roundId)
	for {
		meta, err := s.rdb.HGetAll(ctx, metaKey).Result()
		if err != nil || len(meta) == 0 {
			continue
		}
		nbCosigners := 0
		if _, err := fmt.Sscanf(meta["NbCosigners"], "%d", &nbCosigners); err != nil {
			log.Warnf("watchNoncesCollected:failed to parse NbCosigners: %v", err)
		}
		noncesMap, _ := s.rdb.HGetAll(ctx, noncesKey).Result()
		if len(noncesMap) == nbCosigners-1 {
			if s.nonceCh != nil {
				s.nonceCh <- struct{}{}
			}
			return
		}
	}
}

func (s *treeSigningSessionsStore) watchSigsCollected(roundId string) {
	ctx := context.Background()
	metaKey := fmt.Sprintf(treeSessMetaKeyFmt, roundId)
	sigsKey := fmt.Sprintf(treeSessSigsKeyFmt, roundId)
	for {
		meta, err := s.rdb.HGetAll(ctx, metaKey).Result()
		if err != nil || len(meta) == 0 {
			continue
		}
		nbCosigners := 0
		if _, err := fmt.Sscanf(meta["NbCosigners"], "%d", &nbCosigners); err != nil {
			log.Warnf("watchSigsCollected:failed to parse NbCosigners: %v", err)
		}
		sigsMap, _ := s.rdb.HGetAll(ctx, sigsKey).Result()
		if len(sigsMap) == nbCosigners-1 {
			if s.sigsCh != nil {
				s.sigsCh <- struct{}{}
			}
			return
		}
	}
}
