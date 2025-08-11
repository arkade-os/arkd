package inmemorylivestore

import (
	"context"
	"fmt"
	"sync"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
)

type treeSigningSessionsStore struct {
	lock             *sync.RWMutex
	sessions         map[string]*ports.MusigSigningSession
	nonceCollectedCh map[string]chan struct{}
	sigsCollectedCh  map[string]chan struct{}
}

func NewTreeSigningSessionsStore() ports.TreeSigningSessionsStore {
	return &treeSigningSessionsStore{
		lock:             &sync.RWMutex{},
		sessions:         make(map[string]*ports.MusigSigningSession),
		nonceCollectedCh: make(map[string]chan struct{}),
		sigsCollectedCh:  make(map[string]chan struct{}),
	}
}

func (s *treeSigningSessionsStore) New(
	roundId string, uniqueSignersPubKeys map[string]struct{},
) *ports.MusigSigningSession {
	s.lock.Lock()
	defer s.lock.Unlock()

	sess := &ports.MusigSigningSession{
		Cosigners:   uniqueSignersPubKeys,
		NbCosigners: len(uniqueSignersPubKeys) + 1, // operator included
		Nonces:      make(map[string]tree.TreeNonces),
		Signatures:  make(map[string]tree.TreePartialSigs),
	}
	s.sessions[roundId] = sess
	s.nonceCollectedCh[roundId] = make(chan struct{})
	s.sigsCollectedCh[roundId] = make(chan struct{})
	return sess
}

func (s *treeSigningSessionsStore) Get(roundId string) (*ports.MusigSigningSession, bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	sess, ok := s.sessions[roundId]
	return sess, ok
}
func (s *treeSigningSessionsStore) Delete(roundId string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if _, exists := s.nonceCollectedCh[roundId]; exists {
		close(s.nonceCollectedCh[roundId])
	}
	if _, exists := s.sigsCollectedCh[roundId]; exists {
		close(s.sigsCollectedCh[roundId])
	}

	delete(s.nonceCollectedCh, roundId)
	delete(s.sigsCollectedCh, roundId)
	delete(s.sessions, roundId)
}

func (s *treeSigningSessionsStore) AddNonces(
	ctx context.Context, roundId string, pubkey string, nonces tree.TreeNonces,
) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	session, ok := s.sessions[roundId]
	if !ok {
		return fmt.Errorf(`signing session not found for round "%s"`, roundId)
	}
	if _, ok := session.Cosigners[pubkey]; !ok {
		return fmt.Errorf(`cosigner %s not found for round "%s"`, pubkey, roundId)
	}
	if _, exists := s.nonceCollectedCh[roundId]; !exists {
		return fmt.Errorf("nonce channel not initialized for round %s", roundId)
	}

	s.sessions[roundId].Nonces[pubkey] = nonces

	if len(s.sessions[roundId].Nonces) == s.sessions[roundId].NbCosigners-1 {
		s.nonceCollectedCh[roundId] <- struct{}{}
	}
	return nil
}

func (s *treeSigningSessionsStore) AddSignatures(
	ctx context.Context, roundId string, pubkey string, sigs tree.TreePartialSigs,
) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	session, ok := s.sessions[roundId]
	if !ok {
		return fmt.Errorf(`signing session not found for round "%s"`, roundId)
	}
	if _, ok := session.Cosigners[pubkey]; !ok {
		return fmt.Errorf(`cosigner %s not found for round "%s"`, pubkey, roundId)
	}
	if _, exists := s.sigsCollectedCh[roundId]; !exists {
		return fmt.Errorf("signature channel not initialized for round %s", roundId)
	}

	s.sessions[roundId].Signatures[pubkey] = sigs

	if len(s.sessions[roundId].Signatures) == s.sessions[roundId].NbCosigners-1 {
		s.sigsCollectedCh[roundId] <- struct{}{}
	}

	return nil
}

func (s *treeSigningSessionsStore) NoncesCollected(roundId string) <-chan struct{} {
	return s.nonceCollectedCh[roundId]
}

func (s *treeSigningSessionsStore) SignaturesCollected(roundId string) <-chan struct{} {
	return s.sigsCollectedCh[roundId]
}
