package main

import (
	"container/list"
	"crypto/sha256"
	"sync"
	"time"
)

type cachedValue[T any] struct {
	key     [sha256.Size]byte
	value   T
	expires time.Time
}

type boundedCache[T any] struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]*list.Element
	order   list.List
	limit   int
}

func newBoundedCache[T any](limit int) *boundedCache[T] {
	return &boundedCache[T]{entries: make(map[[sha256.Size]byte]*list.Element, limit), limit: limit}
}

func (c *boundedCache[T]) get(key [sha256.Size]byte) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		value := entry.Value.(cachedValue[T])
		if time.Now().Before(value.expires) {
			c.order.MoveToFront(entry)
			return value.value, true
		}
		c.remove(entry)
	}
	var zero T
	return zero, false
}

func (c *boundedCache[T]) put(key [sha256.Size]byte, value T, expires time.Time) {
	if !time.Now().Before(expires) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		entry.Value = cachedValue[T]{key, value, expires}
		c.order.MoveToFront(entry)
		return
	}
	if len(c.entries) == c.limit {
		c.remove(c.order.Back())
	}
	c.entries[key] = c.order.PushFront(cachedValue[T]{key, value, expires})
}

func (c *boundedCache[T]) remove(entry *list.Element) {
	delete(c.entries, entry.Value.(cachedValue[T]).key)
	c.order.Remove(entry)
}

func cacheUntil(seconds int, expiries ...time.Time) time.Time {
	if seconds == 0 {
		return time.Time{}
	}
	end := time.Now().Add(time.Duration(seconds) * time.Second)
	for _, expiry := range expiries {
		if !expiry.IsZero() && expiry.Before(end) {
			end = expiry
		}
	}
	return end
}
