package inmemorylivestore

import (
	"github.com/arkade-os/arkd/internal/core/ports"
)

type inMemoryLiveStore struct {
	intentStore               ports.IntentStore
	forfeitTxsStore           ports.ForfeitTxsStore
	offChainTxStore           ports.OffChainTxStore
	currentRoundStore         ports.CurrentRoundStore
	confirmationSessionsStore ports.ConfirmationSessionsStore
	treeSigningSessions       ports.TreeSigningSessionsStore
	boardingInputsStore       ports.BoardingInputsStore
}

func NewLiveStore(txBuilder ports.TxBuilder) ports.LiveStore {
	return &inMemoryLiveStore{
		intentStore:               NewIntentStore(),
		forfeitTxsStore:           NewForfeitTxsStore(txBuilder),
		offChainTxStore:           NewOffChainTxStore(),
		currentRoundStore:         NewCurrentRoundStore(),
		confirmationSessionsStore: NewConfirmationSessionsStore(),
		treeSigningSessions:       NewTreeSigningSessionsStore(),
		boardingInputsStore:       NewBoardingInputsStore(),
	}
}

func (s *inMemoryLiveStore) Intents() ports.IntentStore {
	return s.intentStore
}
func (s *inMemoryLiveStore) ForfeitTxs() ports.ForfeitTxsStore {
	return s.forfeitTxsStore
}
func (s *inMemoryLiveStore) OffchainTxs() ports.OffChainTxStore {
	return s.offChainTxStore
}
func (s *inMemoryLiveStore) CurrentRound() ports.CurrentRoundStore {
	return s.currentRoundStore
}
func (s *inMemoryLiveStore) ConfirmationSessions() ports.ConfirmationSessionsStore {
	return s.confirmationSessionsStore
}
func (s *inMemoryLiveStore) TreeSigingSessions() ports.TreeSigningSessionsStore {
	return s.treeSigningSessions
}
func (s *inMemoryLiveStore) BoardingInputs() ports.BoardingInputsStore {
	return s.boardingInputsStore
}
