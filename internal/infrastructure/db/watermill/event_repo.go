package watermilldb

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/arkade-os/arkd/internal/core/domain"
)

type subscriber struct {
	topic   string
	handler func(events []domain.Event)
}

type eventRepository struct {
	publisher message.Publisher

	subscribers    map[string][]subscriber // topic -> subscribers
	subscriberLock *sync.Mutex
	caches         map[string]*eventCache // topic -> cache
	cacheLock      *sync.Mutex
}

func NewWatermillEventRepository(publisher message.Publisher) domain.EventRepository {
	return &eventRepository{
		publisher:      publisher,
		subscribers:    make(map[string][]subscriber),
		subscriberLock: &sync.Mutex{},
		caches:         make(map[string]*eventCache),
		cacheLock:      &sync.Mutex{},
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

	e.cacheLock.Lock()
	defer e.cacheLock.Unlock()

	// create cache if it doesn't exist
	if _, ok := e.caches[topic]; !ok {
		e.caches[topic] = newEventCache()
	}

	// push events to cache
	e.caches[topic].add(id, events)

	// dispatch events to subscribers
	e.dispatch(topic, id)

	return nil
}

func (e *eventRepository) dispatch(topic string, id string) {
	// get events from cache
	events := e.caches[topic].get(id)
	if len(events) == 0 {
		return
	}

	// run the handlers in go routines
	e.subscriberLock.Lock()
	for _, subscriber := range e.subscribers[topic] {
		go subscriber.handler(events)
	}
	e.subscriberLock.Unlock()

	// remove the cached events for this id if the last event is a final one
	lastEvent := events[len(events)-1]
	if noMoreEventsAfter(lastEvent.GetType()) {
		e.caches[topic].remove(id)
	}
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

func noMoreEventsAfter(eventType domain.EventType) bool {
	return eventType == domain.EventTypeOffchainTxFailed ||
		eventType == domain.EventTypeOffchainTxFinalized ||
		eventType == domain.EventTypeRoundFailed ||
		eventType == domain.EventTypeRoundFinalized
}
