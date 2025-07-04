package badgerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/dgraph-io/badger/v4"
	"github.com/timshannon/badgerhold/v4"
)

const eventStoreDir = "round-events"

type eventsDTO struct {
	Events [][]byte
}

type update struct {
	topic  string
	events []domain.Event
}

type eventRepository struct {
	store         *badgerhold.Store
	lock          *sync.RWMutex
	chUpdates     chan update
	eventHandlers map[string][]func(events []domain.Event)
	done          chan struct{}
}

func NewEventRepository(config ...interface{}) (domain.EventRepository, error) {
	if len(config) != 2 {
		return nil, fmt.Errorf("invalid config")
	}
	baseDir, ok := config[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid base directory")
	}

	var logger badger.Logger
	if config[1] != nil {
		logger, ok = config[1].(badger.Logger)
		if !ok {
			return nil, fmt.Errorf("invalid logger")
		}
	}

	var dir string
	if len(baseDir) > 0 {
		dir = filepath.Join(baseDir, eventStoreDir)
	}
	store, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open round events store: %s", err)
	}
	repo := &eventRepository{
		store:         store,
		lock:          &sync.RWMutex{},
		chUpdates:     make(chan update),
		eventHandlers: make(map[string][]func(events []domain.Event)),
		done:          make(chan struct{}),
	}
	go repo.listen()
	return repo, nil
}

func (r *eventRepository) Save(
	ctx context.Context, topic, id string, events []domain.Event,
) error {
	allEvents, err := r.get(ctx, id)
	if err != nil {
		return err
	}

	allEvents = append(allEvents, events...)
	if err := r.upsert(ctx, id, allEvents); err != nil {
		return err
	}

	go r.publishUpdate(update{topic, allEvents})

	return nil
}

func (r *eventRepository) RegisterEventsHandler(
	topic string, handler func(events []domain.Event),
) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if _, ok := r.eventHandlers[topic]; !ok {
		r.eventHandlers[topic] = make([]func(events []domain.Event), 0)
	}

	r.eventHandlers[topic] = append(r.eventHandlers[topic], handler)
}

func (r *eventRepository) ClearRegisteredHandlers(topics ...string) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if len(topics) == 0 {
		r.eventHandlers = make(map[string][]func(events []domain.Event))
		return
	}

	for _, topic := range topics {
		delete(r.eventHandlers, topic)
	}
}

func (r *eventRepository) Close() {
	close(r.done)

	close(r.chUpdates)
	// nolint:all
	r.store.Close()
}

func (r *eventRepository) get(
	ctx context.Context, id string,
) ([]domain.Event, error) {
	dto := eventsDTO{}
	var err error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		err = r.store.TxGet(tx, id, &dto)
	} else {
		err = r.store.Get(id, &dto)
	}
	if err != nil {
		if err == badgerhold.ErrNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get events with id %s: %s", id, err)
	}

	return deserializeEvents(dto.Events)
}

func (r *eventRepository) upsert(
	ctx context.Context, id string, events []domain.Event,
) error {
	buf, err := serializeEvents(events)
	if err != nil {
		return err
	}
	var upsertFn func() error
	if ctx.Value("tx") != nil {
		tx := ctx.Value("tx").(*badger.Txn)
		upsertFn = func() error {
			return r.store.TxUpsert(tx, id, buf)
		}
	} else {
		upsertFn = func() error {
			return r.store.Upsert(id, buf)
		}
	}

	if err := upsertFn(); err != nil {
		if errors.Is(err, badger.ErrConflict) {
			attempts := 1
			for errors.Is(err, badger.ErrConflict) && attempts <= maxRetries {
				time.Sleep(100 * time.Millisecond)
				err = upsertFn()
				attempts++
			}
		}
		return fmt.Errorf("failed to upsert events with id %s: %s", id, err)
	}
	return nil
}

func (r *eventRepository) listen() {
	for {
		select {
		case <-r.done:
			return
		case update := <-r.chUpdates:
			r.lock.RLock()
			for _, handler := range r.eventHandlers[update.topic] {
				handler(update.events)
			}
			r.lock.RUnlock()
		}
	}
}

func (r *eventRepository) publishUpdate(u update) {
	select {
	case <-r.done:
		return
	case r.chUpdates <- u:
	}
}
