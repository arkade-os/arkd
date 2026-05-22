package redislivestore

import (
	"time"

	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/redis/go-redis/v9"
)

type redisLiveStore struct {
	intentStore               ports.IntentStore
	forfeitTxsStore           ports.ForfeitTxsStore
	offChainTxStore           ports.OffChainTxStore
	currentRoundStore         ports.CurrentRoundStore
	confirmationSessionsStore ports.ConfirmationSessionsStore
	treeSigningSessions       ports.TreeSigningSessionsStore
	boardingInputsStore       ports.BoardingInputsStore
	scheduledTasksStore       ports.ScheduledTasksStore
}

func NewLiveStore(rdb *redis.Client, builder ports.TxBuilder, numOfRetries int, scheduledTaskTTL time.Duration) ports.LiveStore {
	return &redisLiveStore{
		intentStore:               NewIntentStore(rdb, numOfRetries),
		forfeitTxsStore:           NewForfeitTxsStore(rdb, builder, numOfRetries),
		offChainTxStore:           NewOffChainTxStore(rdb, numOfRetries),
		currentRoundStore:         NewCurrentRoundStore(rdb, numOfRetries),
		confirmationSessionsStore: NewConfirmationSessionsStore(rdb, numOfRetries),
		treeSigningSessions:       NewTreeSigningSessionsStore(rdb, numOfRetries),
		boardingInputsStore:       NewBoardingInputsStore(rdb, numOfRetries),
		scheduledTasksStore:       NewScheduledTasksStore(rdb, scheduledTaskTTL),
	}
}

func (s *redisLiveStore) Intents() ports.IntentStore            { return s.intentStore }
func (s *redisLiveStore) ForfeitTxs() ports.ForfeitTxsStore     { return s.forfeitTxsStore }
func (s *redisLiveStore) OffchainTxs() ports.OffChainTxStore    { return s.offChainTxStore }
func (s *redisLiveStore) CurrentRound() ports.CurrentRoundStore { return s.currentRoundStore }
func (s *redisLiveStore) ConfirmationSessions() ports.ConfirmationSessionsStore {
	return s.confirmationSessionsStore
}
func (s *redisLiveStore) TreeSigingSessions() ports.TreeSigningSessionsStore {
	return s.treeSigningSessions
}
func (s *redisLiveStore) BoardingInputs() ports.BoardingInputsStore {
	return s.boardingInputsStore
}
func (s *redisLiveStore) ScheduledTasks() ports.ScheduledTasksStore {
	return s.scheduledTasksStore
}
