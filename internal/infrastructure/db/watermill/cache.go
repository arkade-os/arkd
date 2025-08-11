package watermilldb

import (
	"sync"

	"github.com/arkade-os/arkd/internal/core/domain"
)

type eventCache struct {
	cache map[string][]domain.Event // id -> events
	lock  *sync.Mutex
}

func newEventCache() *eventCache {
	return &eventCache{
		cache: make(map[string][]domain.Event),
		lock:  &sync.Mutex{},
	}
}

func (c *eventCache) add(id string, events []domain.Event) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if _, ok := c.cache[id]; !ok {
		c.cache[id] = make([]domain.Event, 0)
	}

	c.cache[id] = append(c.cache[id], events...)
}

func (c *eventCache) get(id string) []domain.Event {
	c.lock.Lock()
	defer c.lock.Unlock()

	return c.cache[id]
}

func (c *eventCache) remove(id string) {
	c.lock.Lock()
	defer c.lock.Unlock()

	delete(c.cache, id)
}
