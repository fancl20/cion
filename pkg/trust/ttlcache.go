package trust

import (
	"sync"
	"time"
)

// A ttlCache is a map of values that each expire. Expiry is lazy by
// construction: no janitor goroutine exists to start, which keeps a
// holder whole inside a fake-time bubble, and a read that finds an entry
// expired deletes it, so what the map holds stays close to the live set —
// an entry no read ever touches again lingers as one slot, bounded by the
// distinct keys ever added. A nil *ttlCache caches nothing: get reports
// only misses and add stores nothing.
type ttlCache[V any] struct {
	mu sync.RWMutex
	m  map[string]ttlEntry[V]
}

// A ttlEntry is one cached value and the instant it expires.
type ttlEntry[V any] struct {
	value   V
	expires time.Time
}

// newTTLCache returns an empty cache.
func newTTLCache[V any]() *ttlCache[V] {
	return &ttlCache[V]{m: make(map[string]ttlEntry[V])}
}

// get reports the value stored for key, but only while it is unexpired;
// an absent key, an expired one, and a nil cache all report the zero
// value and false. An expired entry is deleted under the write lock on
// the way to reporting the miss.
func (c *ttlCache[V]) get(key string) (V, bool) {
	var zero V
	if c == nil {
		return zero, false
	}
	c.mu.RLock()
	e, ok := c.m[key]
	c.mu.RUnlock()
	if !ok {
		return zero, false
	}
	if time.Now().Before(e.expires) {
		return e.value, true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Look the key up again: a straggler add may have refreshed the entry
	// after the read above refused it, and that fresh entry must survive.
	if e, ok := c.m[key]; ok {
		if time.Now().Before(e.expires) {
			return e.value, true
		}
		delete(c.m, key)
	}
	return zero, false
}

// add stores value under key, expiring ttl from now. An existing
// unexpired entry is kept — first-write-wins — so concurrent fetches of
// one key install a single window, the first fetch's, and the losers'
// results are dropped.
func (c *ttlCache[V]) add(key string, value V, ttl time.Duration) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if e, ok := c.m[key]; ok && now.Before(e.expires) {
		return
	}
	c.m[key] = ttlEntry[V]{value: value, expires: now.Add(ttl)}
}
