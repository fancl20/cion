// Package ratelimit rate-caps admissions per key, the shape the node's doors
// share: one admission per interval for each key, in bounded memory. A shared
// library: no loops of its own, no policy.
package ratelimit

import (
	"sync"
	"time"
)

// keyCap bounds the keys a Keyed tracks.
const keyCap = 1024

// Keyed rate-caps admissions per key: one admission per interval, and a key
// silent for an interval is admitted again and stops being tracked. It tracks
// at most keyCap keys and sweeps the silent ones at most once per interval,
// so a flood of fresh keys costs bounded memory and amortized time; a fresh
// key arriving while the table is full is refused.
type Keyed[K comparable] struct {
	interval time.Duration

	mtx   sync.Mutex
	last  map[K]time.Time
	swept time.Time
}

// NewKeyed returns a limiter that admits each key at most once per interval.
func NewKeyed[K comparable](interval time.Duration) *Keyed[K] {
	return &Keyed[K]{interval: interval, last: make(map[K]time.Time)}
}

// Admit reports whether the key may be admitted now, recording the admission
// when it may.
func (l *Keyed[K]) Admit(key K) bool {
	now := time.Now()
	l.mtx.Lock()
	defer l.mtx.Unlock()
	at, held := l.last[key]
	if held && now.Sub(at) < l.interval {
		return false
	}
	if !held && len(l.last) >= keyCap && !l.sweep(now) {
		return false
	}
	l.last[key] = now
	return true
}

// sweep forgets the keys silent for an interval — each would be admitted
// again, so forgetting it changes no answer — at most once per interval, and
// reports whether the table has room for a fresh key.
func (l *Keyed[K]) sweep(now time.Time) bool {
	if now.Sub(l.swept) >= l.interval {
		l.swept = now
		for k, at := range l.last {
			if now.Sub(at) >= l.interval {
				delete(l.last, k)
			}
		}
	}
	return len(l.last) < keyCap
}
