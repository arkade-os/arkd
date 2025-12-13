package utils

import (
	"strings"
	"sync"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
)

type SupportedType[V any] map[string]V

func (t SupportedType[V]) String() string {
	types := make([]string, 0, len(t))
	for tt := range t {
		types = append(types, tt)
	}
	return strings.Join(types, " | ")
}

func (t SupportedType[V]) Supports(typeStr string) bool {
	_, ok := t[typeStr]
	return ok
}

type ClientFactory func(string) (client.TransportClient, error)

type Cache[V any] struct {
	mapping map[string]V
	lock    *sync.RWMutex
}

func NewCache[V any]() *Cache[V] {
	return &Cache[V]{
		mapping: make(map[string]V),
		lock:    &sync.RWMutex{},
	}
}

func (c Cache[V]) Set(key string, value V) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.mapping[key] = value
}

func (c Cache[V]) Get(key string) (V, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	val, ok := c.mapping[key]
	return val, ok
}
