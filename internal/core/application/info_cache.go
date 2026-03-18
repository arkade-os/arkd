package application

import (
	"sync"

	"github.com/arkade-os/arkd/internal/core/domain"
)

type infoData struct {
	dust             uint64
	scheduledSession *domain.ScheduledSession
	intentFees       domain.IntentFees
}

type infoCache struct {
	mu     sync.RWMutex
	data   *infoData
	loader func() (*infoData, error)
}

func newInfoCache(loader func() (*infoData, error)) *infoCache {
	return &infoCache{loader: loader}
}

func (c *infoCache) get() (*infoData, error) {
	c.mu.RLock()
	d := c.data
	c.mu.RUnlock()

	if d != nil {
		return d, nil
	}

	// if nil, load
	return c.loader()
}

func (c *infoCache) refresh() error {
	d, err := c.loader()
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.data = d
	c.mu.Unlock()
	return nil
}
