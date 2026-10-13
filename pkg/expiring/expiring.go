// Package expiring holds values that each expire at an instant of their own.
// A shared library: no loops of its own, no policy.
package expiring

import (
	"sync"
	"time"
)

// Map is a map whose entries each expire. Expiry is lazy: no goroutine sweeps
// the map, which keeps a holder whole inside a fake-time bubble. A read that
// finds its entry expired deletes it, and a write sweeps out every expired
// entry once the map has doubled in size since the last sweep, so a write
// costs amortized constant time and the map holds at most about twice the
// entries the last sweep kept. A nil *Map holds nothing: Get reports misses
// and writes store nothing.
type Map[K comparable, V any] struct {
	mtx sync.Mutex
	m   map[K]entry[V]
	// sweepAt is the size at which the next write sweeps: twice the entries
	// the last sweep kept.
	sweepAt int
}

// An entry is one value and the instant it expires.
type entry[V any] struct {
	value   V
	expires time.Time
}

// New returns an empty map.
func New[K comparable, V any]() *Map[K, V] {
	return &Map[K, V]{m: make(map[K]entry[V])}
}

// Get reports the value stored under key while its entry lives, before the
// entry's expiry; otherwise it reports the zero value and false, deleting an
// expired entry.
func (m *Map[K, V]) Get(key K) (V, bool) {
	var zero V
	if m == nil {
		return zero, false
	}
	m.mtx.Lock()
	defer m.mtx.Unlock()
	e, ok := m.m[key]
	if !ok {
		return zero, false
	}
	if !time.Now().Before(e.expires) {
		delete(m.m, key)
		return zero, false
	}
	return e.value, true
}

// Set stores value under key until expires, replacing the key's entry.
func (m *Map[K, V]) Set(key K, value V, expires time.Time) {
	if m == nil {
		return
	}
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.store(key, value, expires, time.Now())
}

// SetIfAbsent stores value under key until expires unless the key's entry
// lives: of concurrent writers, the first keeps the key with its value and
// expiry.
func (m *Map[K, V]) SetIfAbsent(key K, value V, expires time.Time) {
	if m == nil {
		return
	}
	m.mtx.Lock()
	defer m.mtx.Unlock()
	now := time.Now()
	if e, ok := m.m[key]; ok && now.Before(e.expires) {
		return
	}
	m.store(key, value, expires, now)
}

// store writes the entry, first sweeping out the entries expired at now when
// the map has doubled since the last sweep.
func (m *Map[K, V]) store(key K, value V, expires, now time.Time) {
	if len(m.m) >= m.sweepAt {
		for k, e := range m.m {
			if !now.Before(e.expires) {
				delete(m.m, k)
			}
		}
		m.sweepAt = 2 * len(m.m)
	}
	m.m[key] = entry[V]{value: value, expires: expires}
}
