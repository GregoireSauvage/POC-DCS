package cache

import (
	"sync"
	"time"
)

type entry[V any] struct {
	value     V
	expiresAt time.Time
}

type TTL[K comparable, V any] struct {
	mu         sync.Mutex
	store      map[K]entry[V]
	maxEntries int
	defaultTTL time.Duration
}

func NewTTL[K comparable, V any](maxEntries int, defaultTTL time.Duration) *TTL[K, V] {
	if maxEntries < 1 {
		maxEntries = 1
	}
	if defaultTTL <= 0 {
		defaultTTL = time.Second
	}
	return &TTL[K, V]{
		store:      make(map[K]entry[V], maxEntries),
		maxEntries: maxEntries,
		defaultTTL: defaultTTL,
	}
}

func (t *TTL[K, V]) Get(key K) (V, bool) {
	var zero V
	t.mu.Lock()
	defer t.mu.Unlock()

	item, ok := t.store[key]
	if !ok {
		return zero, false
	}
	if time.Now().After(item.expiresAt) {
		delete(t.store, key)
		return zero, false
	}
	return item.value, true
}

func (t *TTL[K, V]) Set(key K, value V, ttl time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if ttl <= 0 {
		ttl = t.defaultTTL
	}
	if len(t.store) >= t.maxEntries {
		for k := range t.store {
			delete(t.store, k)
			break
		}
	}
	t.store[key] = entry[V]{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
}

func (t *TTL[K, V]) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	clear(t.store)
}
