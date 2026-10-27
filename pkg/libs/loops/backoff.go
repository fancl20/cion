package loops

import (
	"context"
	"iter"
	"math"
	"math/rand/v2"
	"time"
)

// Backoff is the node's one retry schedule. The wait before the first retry
// is Base and each later wait doubles the one before, up to Max; every wait
// is drawn at random from its upper half, so nodes that failed together
// retry apart and no wait exceeds its cap.
type Backoff struct {
	// Base is the wait before the first retry.
	Base time.Duration
	// Max caps every wait; zero caps none.
	Max time.Duration
}

// Tries returns one operation's tries on the schedule: the first at once,
// and each retry after its wait. It yields each try's number, counted from
// 1, and ends once ctx does; the caller breaks out of its loop once a try
// succeeds, or at a bound of its own:
//
//	for range backoff.Tries(ctx) {
//		if err := publish(ctx); err == nil {
//			break
//		}
//	}
func (b Backoff) Tries(ctx context.Context) iter.Seq[int] {
	return func(yield func(int) bool) {
		if ctx.Err() != nil {
			return
		}
		for n := 1; yield(n); n++ {
			if !Sleep(ctx, b.delay(n)) {
				return
			}
		}
	}
}

// delay returns the wait before retry n, counted from 1.
func (b Backoff) delay(n int) time.Duration {
	d := b.Base
	for i := 1; i < n && (b.Max == 0 || d < b.Max) && d <= math.MaxInt64/2; i++ {
		d *= 2
	}
	if b.Max > 0 && d > b.Max {
		d = b.Max
	}
	half := d / 2
	return d - half + rand.N(half+1)
}

// Attempts tracks a schedule's retries per key, for a loop retrying many
// entries at once: how many tries each key took, and when its next is due.
// Its zero value with Backoff set is ready. It is not safe for concurrent
// use: one loop owns it.
type Attempts[K comparable] struct {
	// Backoff spaces a key's tries.
	Backoff Backoff
	// Limit bounds a key's tries; zero bounds none.
	Limit int

	tries map[K]try
}

// try is one key's record: its count of tries, and when the next is due.
type try struct {
	count int
	next  time.Time
}

// Due reports whether the key may try at now: it never tried, or its delay
// passed with its tries under Limit.
func (a *Attempts[K]) Due(k K, now time.Time) bool {
	t, ok := a.tries[k]
	if !ok {
		return true
	}
	return (a.Limit == 0 || t.count < a.Limit) && !now.Before(t.next)
}

// Tried records a try of the key at now: its next is due the schedule's
// delay for its count later.
func (a *Attempts[K]) Tried(k K, now time.Time) {
	if a.tries == nil {
		a.tries = make(map[K]try)
	}
	t := a.tries[k]
	t.count++
	t.next = now.Add(a.Backoff.delay(t.count))
	a.tries[k] = t
}

// Forget drops the key — its operation succeeded, or no longer applies — so
// its next try is due at once, counted afresh.
func (a *Attempts[K]) Forget(k K) {
	delete(a.tries, k)
}

// Retain forgets every key keep rejects: a loop drops the entries its pass
// no longer retries.
func (a *Attempts[K]) Retain(keep func(K) bool) {
	for k := range a.tries {
		if !keep(k) {
			delete(a.tries, k)
		}
	}
}
