package domain

import "context"

type EventType int

const (
	EventTypeUndefined EventType = iota

	// Round
	EventTypeTxRequestsRegistered
	EventTypeRoundStarted
	EventTypeRoundFinalizationStarted
	EventTypeRoundFinalized
	EventTypeRoundFailed
	EventTypeBatchSwept
)

const (
	// OffchainTx
	EventTypeOffchainTxRequested EventType = iota + 100
	EventTypeOffchainTxAccepted
	EventTypeOffchainTxFinalized
	EventTypeOffchainTxFailed
)

type Event interface {
	GetTopic() string
	GetType() EventType
}

type EventRepository interface {
	Save(ctx context.Context, topic, id string, events []Event) error
	RegisterEventsHandler(topic string, handler func(events []Event))
	ClearRegisteredHandlers(topic ...string)
	Close()
}
