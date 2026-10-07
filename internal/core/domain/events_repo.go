package domain

import "context"

type EventType int

const (
	EventTypeUndefined EventType = iota

	// Round
	EventTypeIntentsRegistered
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

const (
	// OnchainTx
	EventTypeOnchainTxBroadcasted EventType = iota + 200
	EventTypeOnchainTxConfirmed
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
