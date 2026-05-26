package maputils

import (
	"sync"
	"time"
)

type TTLMapEntry[V any] struct {
	Value      V
	Expiration int64 // Nanosecond unix timestamp
}

type TTLMap[K comparable, V any] struct {
	mu              sync.RWMutex
	store           map[K]TTLMapEntry[V]
	ttl             time.Duration
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

type Option[K comparable, V any] func(*TTLMap[K, V])

func WithTTL[K comparable, V any](ttl time.Duration) Option[K, V] {
	return func(m *TTLMap[K, V]) {
		m.ttl = ttl
	}
}

func WithCleanupInterval[K comparable, V any](interval time.Duration) Option[K, V] {
	return func(m *TTLMap[K, V]) {
		m.cleanupInterval = interval
	}
}

func NewTTLMap[K comparable, V any](opts ...Option[K, V]) *TTLMap[K, V] {
	m := &TTLMap[K, V]{
		store:           make(map[K]TTLMapEntry[V]),
		ttl:             5 * time.Minute,
		cleanupInterval: 30 * time.Second,
		stopCleanup:     make(chan struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	go m.startCleanup()
	return m
}

func (m *TTLMap[K, V]) Set(key K, value V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[key] = TTLMapEntry[V]{
		Value:      value,
		Expiration: time.Now().Add(m.ttl).UnixNano(),
	}
}

func (m *TTLMap[K, V]) Get(key K) (V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, exists := m.store[key]
	if !exists || time.Now().UnixNano() > entry.Expiration {
		var zero V
		return zero, false
	}
	return entry.Value, true
}

func (m *TTLMap[K, V]) Delete(key K) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.store, key)
}

func (m *TTLMap[K, V]) Close() {
	close(m.stopCleanup)
}

func (m *TTLMap[K, V]) startCleanup() {
	ticker := time.NewTicker(m.cleanupInterval)
	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now().UnixNano()
			for k, v := range m.store {
				if now > v.Expiration {
					delete(m.store, k)
				}
			}
			m.mu.Unlock()
		case <-m.stopCleanup:
			ticker.Stop()
			return
		}
	}
}
