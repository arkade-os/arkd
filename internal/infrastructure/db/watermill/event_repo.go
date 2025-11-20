package watermilldb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/arkade-os/arkd/internal/core/domain"
	log "github.com/sirupsen/logrus"
)

type subscriber struct {
	topic   string
	handler func(events []domain.Event)
}

type eventRepository struct {
	publisher message.Publisher
	db        *sql.DB

	subscribers    map[string][]subscriber // topic -> subscribers
	subscriberLock *sync.Mutex
}

func NewWatermillEventRepository(publisher message.Publisher, db *sql.DB) domain.EventRepository {
	return &eventRepository{
		publisher:      publisher,
		db:             db,
		subscribers:    make(map[string][]subscriber),
		subscriberLock: &sync.Mutex{},
	}
}

func (e *eventRepository) ClearRegisteredHandlers(topics ...string) {
	e.subscriberLock.Lock()
	defer e.subscriberLock.Unlock()

	if len(topics) == 0 {
		e.subscribers = make(map[string][]subscriber)
		return
	}

	for _, topic := range topics {
		delete(e.subscribers, topic)
	}
}

func (e *eventRepository) Close() {
	//nolint:errcheck
	e.publisher.Close()
}

func (e *eventRepository) RegisterEventsHandler(
	topic string, handler func(events []domain.Event),
) {
	e.subscriberLock.Lock()
	defer e.subscriberLock.Unlock()

	if _, ok := e.subscribers[topic]; !ok {
		e.subscribers[topic] = make([]subscriber, 0)
	}

	e.subscribers[topic] = append(e.subscribers[topic], subscriber{
		topic:   topic,
		handler: handler,
	})
}

func (e *eventRepository) Save(
	ctx context.Context, topic string, id string, events []domain.Event,
) error {
	err := e.publish(topic, events)
	if err != nil {
		return err
	}
	// dispatch events to subscribers
	if err := e.dispatch(topic, id); err != nil {
		log.WithError(err).Error("failed to dispatch saved events")
	}

	return nil
}

func (e *eventRepository) dispatch(topic string, id string) error {
	// get all events for the topic from the database
	events, err := e.getAllEvents(context.Background(), topic, id)
	if err != nil {
		return err
	}

	if len(events) == 0 {
		return nil
	}

	// run the handlers in go routines
	e.subscriberLock.Lock()
	defer e.subscriberLock.Unlock()
	for _, subscriber := range e.subscribers[topic] {
		go subscriber.handler(events)
	}
	return nil
}

// getAllEvents queries the database for all historical messages in a topic filtered by id.
// Watermill table name is (watermill_<topic>).
// Messages are filtered by the Id field in the JSON payload (thanks to postgres JSONB type)
// and ordered by created_at.
func (e *eventRepository) getAllEvents(
	ctx context.Context, topic, id string,
) ([]domain.Event, error) {
	if e.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	query := fmt.Sprintf(
		`SELECT payload FROM watermill_%s WHERE payload->>'Id' = $1 ORDER BY "offset" ASC;`,
		topic,
	)

	rows, err := e.db.QueryContext(ctx, query, id)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to query messages for topic %s with id %s: %w",
			topic, id, err,
		)
	}
	// nolint
	defer rows.Close()

	records := make([][]byte, 0)
	for rows.Next() {
		var record []byte
		if err := rows.Scan(&record); err != nil {
			return nil, fmt.Errorf("failed to scan message payload: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"error iterating messages for topic %s with id %s: %w", topic, id, err,
		)
	}

	events := make([]domain.Event, 0, len(records))
	for _, record := range records {
		event, err := deserializeEvent(record)
		if err != nil {
			log.WithError(err).Warnf("failed to deserialize event: %s", string(record))
			continue
		}
		events = append(events, event)
	}

	return events, nil
}

func (e *eventRepository) publish(topic string, events []domain.Event) error {
	watermillMessages := toWatermillMessages(events)
	return e.publisher.Publish(topic, watermillMessages...)
}

func toWatermillMessages(events []domain.Event) []*message.Message {
	watermillMessages := make([]*message.Message, 0, len(events))
	for _, event := range events {
		payload, err := json.Marshal(event)
		if err != nil {
			continue
		}

		watermillMessages = append(
			watermillMessages,
			message.NewMessage(watermill.NewUUID(), payload),
		)
	}

	return watermillMessages
}

func deserializeEvent(buf []byte) (domain.Event, error) {
	var eventType struct {
		Type domain.EventType
	}

	if err := json.Unmarshal(buf, &eventType); err != nil {
		return nil, err
	}

	switch eventType.Type {
	case domain.EventTypeRoundStarted:
		var event = domain.RoundStarted{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeRoundFinalizationStarted:
		var event = domain.RoundFinalizationStarted{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeRoundFinalized:
		var event = domain.RoundFinalized{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeRoundFailed:
		var event = domain.RoundFailed{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeBatchSwept:
		var event = domain.BatchSwept{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeIntentsRegistered:
		var event = domain.IntentsRegistered{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeOffchainTxRequested:
		var event = domain.OffchainTxRequested{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeOffchainTxAccepted:
		var event = domain.OffchainTxAccepted{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeOffchainTxFinalized:
		var event = domain.OffchainTxFinalized{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	case domain.EventTypeOffchainTxFailed:
		var event = domain.OffchainTxFailed{}
		if err := json.Unmarshal(buf, &event); err == nil {
			return event, nil
		}
	}

	return nil, fmt.Errorf("unknown event")
}
