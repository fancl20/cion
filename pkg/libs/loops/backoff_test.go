package loops

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

// TestBackoffDelay checks the schedule's waits: each doubles the one before
// from Base up to Max, drawn from the upper half of its value, and an
// uncapped schedule's late retries neither overflow nor shrink.
func TestBackoffDelay(t *testing.T) {
	b := Backoff{Base: time.Second, Max: 8 * time.Second}
	for _, tt := range []struct {
		n    int
		want time.Duration
	}{
		{1, time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 8 * time.Second},
		{100, 8 * time.Second},
	} {
		for range 200 {
			if got := b.delay(tt.n); got < tt.want/2 || got > tt.want {
				t.Fatalf("delay(%d) = %v, want within [%v, %v]", tt.n, got, tt.want/2, tt.want)
			}
		}
	}
	uncapped := Backoff{Base: time.Second}
	if got := uncapped.delay(1000); got < uncapped.delay(40)/2 {
		t.Errorf("an uncapped late delay = %v, want no less than an earlier one's lower bound", got)
	}
}

// TestBackoffTries checks the tries: the first at once, each retry after
// its wait within its band, the waits doubling up to Max; a break ends them
// with no further wait.
func TestBackoffTries(t *testing.T) {
	b := Backoff{Base: time.Second, Max: 4 * time.Second}
	synctest.Test(t, func(t *testing.T) {
		bands := [][2]time.Duration{
			{0, 0},
			{time.Second / 2, time.Second},
			{time.Second, 2 * time.Second},
			{2 * time.Second, 4 * time.Second},
			{2 * time.Second, 4 * time.Second},
		}
		last := time.Now()
		tries := 0
		for n := range b.Tries(t.Context()) {
			tries++
			if n != tries {
				t.Fatalf("try %d yielded as %d", tries, n)
			}
			band := bands[n-1]
			if gap := time.Since(last); gap < band[0] || gap > band[1] {
				t.Errorf("try %d came %v after the one before, want within [%v, %v]", n, gap, band[0], band[1])
			}
			last = time.Now()
			if n == len(bands) {
				break
			}
		}
		if tries != len(bands) {
			t.Fatalf("tries = %d, want %d", tries, len(bands))
		}
		if waited := time.Since(last); waited != 0 {
			t.Errorf("the break waited %v, want no further wait", waited)
		}
	})
}

// TestBackoffTriesEndWithContext checks the context's end: no try runs once
// it ended, and a wait it cuts short ends the tries.
func TestBackoffTriesEndWithContext(t *testing.T) {
	b := Backoff{Base: time.Second, Max: 4 * time.Second}
	synctest.Test(t, func(t *testing.T) {
		ended, cancel := context.WithCancel(t.Context())
		cancel()
		for range b.Tries(ended) {
			t.Fatal("a try ran after the context ended")
		}

		// The first retry comes within a second and the second no sooner
		// than 1.5 seconds in: a deadline between them cuts the second
		// retry's wait short.
		start := time.Now()
		ctx, cancel := context.WithTimeout(t.Context(), 1400*time.Millisecond)
		defer cancel()
		tries := 0
		for range b.Tries(ctx) {
			tries++
		}
		if tries != 2 {
			t.Errorf("tries before the deadline = %d, want 2", tries)
		}
		if ran := time.Since(start); ran != 1400*time.Millisecond {
			t.Errorf("the tries ended %v in, want at the deadline", ran)
		}
	})
}

// TestAttempts checks the per-key tracking: a key never tried is due, a
// tried one again once its delay passed, never past Limit, and Next tells
// when; a forgotten key is due at once, and Retain forgets the keys it
// rejects.
func TestAttempts(t *testing.T) {
	a := Attempts[int]{Backoff: Backoff{Base: time.Second, Max: 4 * time.Second}, Limit: 3}
	t0 := time.Unix(1000, 0)
	if !a.Due(1, t0) {
		t.Fatal("a key never tried is not due")
	}
	a.Tried(1, t0)
	if a.Due(1, t0.Add(time.Second/2-time.Millisecond)) {
		t.Error("a key is due before the lower bound of its first delay")
	}
	if !a.Due(1, t0.Add(time.Second)) {
		t.Error("a key is not due at its first delay's upper bound")
	}
	a.Tried(1, t0.Add(time.Second))
	if next, ok := a.Next(1); !ok || next.Before(t0.Add(2*time.Second)) || next.After(t0.Add(3*time.Second)) {
		t.Errorf("Next(1) = %v, %t, want within [2s, 3s] past t0", next.Sub(t0), ok)
	}
	a.Tried(1, t0.Add(3*time.Second))
	if a.Due(1, t0.Add(time.Hour)) {
		t.Error("a key is due past its Limit")
	}
	if _, ok := a.Next(1); ok {
		t.Error("Next reports a try past the key's Limit")
	}
	if next, ok := a.Next(9); !ok || !next.IsZero() {
		t.Errorf("Next(9) = %v, %t, want a key never tried due at once", next, ok)
	}
	a.Forget(1)
	if !a.Due(1, t0.Add(time.Hour)) {
		t.Error("a forgotten key is not due")
	}

	a.Tried(2, t0)
	a.Tried(3, t0)
	a.Retain(func(k int) bool { return k == 2 })
	if a.Due(2, t0) || !a.Due(3, t0) {
		t.Error("Retain kept a rejected key or forgot a kept one")
	}
}
