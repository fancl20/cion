package expiring

import (
	"fmt"
	"maps"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// keys returns the keys the map holds, live or expired, sorted.
func keys[V any](m *Map[string, V]) []string {
	return slices.Sorted(maps.Keys(m.m))
}

// TestMapRoundtrip checks the plain hit: a value reads back while its entry
// lives, and a key never stored reports the zero value.
func TestMapRoundtrip(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := New[string, string]()
		m.Set("key", "value", time.Now().Add(time.Minute))

		if v, ok := m.Get("key"); !ok || v != "value" {
			t.Errorf("Get(%q) = %q, %t, want %q, true", "key", v, ok, "value")
		}
		if v, ok := m.Get("absent"); ok || v != "" {
			t.Errorf("Get(%q) = %q, %t, want the zero value, false", "absent", v, ok)
		}
	})
}

// TestMapExpiry checks the window to the nanosecond: an entry lives until its
// expiry and not at it, the read that refuses it deletes it, and a following
// write of the key stores fresh.
func TestMapExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := New[string, string]()
		m.Set("key", "first", time.Now().Add(time.Minute))

		time.Sleep(time.Minute - time.Nanosecond)
		if v, ok := m.Get("key"); !ok || v != "first" {
			t.Errorf("Get a nanosecond before the expiry = %q, %t, want %q, true", v, ok, "first")
		}
		time.Sleep(time.Nanosecond)
		if got, want := keys(m), []string{"key"}; !slices.Equal(got, want) {
			t.Fatalf("keys at the expiry = %q, want %q: no read has refused the entry yet", got, want)
		}
		if v, ok := m.Get("key"); ok || v != "" {
			t.Errorf("Get at the expiry = %q, %t, want the zero value, false", v, ok)
		}
		if got := keys(m); len(got) != 0 {
			t.Errorf("keys after the refusing read = %q, want none", got)
		}

		m.Set("key", "second", time.Now().Add(time.Minute))
		if v, ok := m.Get("key"); !ok || v != "second" {
			t.Errorf("Get after the re-store = %q, %t, want %q, true", v, ok, "second")
		}
	})
}

// TestMapSetReplaces checks Set over a live entry: the new value and the new
// expiry replace the old.
func TestMapSetReplaces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := New[string, string]()
		m.Set("key", "first", time.Now().Add(time.Minute))
		m.Set("key", "second", time.Now().Add(2*time.Minute))

		time.Sleep(time.Minute)
		if v, ok := m.Get("key"); !ok || v != "second" {
			t.Errorf("Get past the first expiry = %q, %t, want the replacing %q, true", v, ok, "second")
		}
	})
}

// TestMapSetIfAbsentFirstWriteWins checks SetIfAbsent: a write over a live
// entry keeps the first value and the first expiry, and once that entry has
// expired the next write takes the key, though no sweep has removed it.
func TestMapSetIfAbsentFirstWriteWins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := New[string, string]()
		// Two longer-lived entries put the next sweep past the writes below.
		m.Set("a", "", time.Now().Add(3*time.Minute))
		m.Set("b", "", time.Now().Add(3*time.Minute))
		m.SetIfAbsent("key", "first", time.Now().Add(time.Minute))
		m.SetIfAbsent("key", "second", time.Now().Add(2*time.Minute))

		if v, ok := m.Get("key"); !ok || v != "first" {
			t.Errorf("Get = %q, %t, want the first %q, true", v, ok, "first")
		}

		time.Sleep(time.Minute)
		if got, want := keys(m), []string{"a", "b", "key"}; !slices.Equal(got, want) {
			t.Fatalf("keys past the first expiry = %q, want %q", got, want)
		}
		m.SetIfAbsent("key", "third", time.Now().Add(time.Minute))
		if v, ok := m.Get("key"); !ok || v != "third" {
			t.Errorf("Get after a write over the expired entry = %q, %t, want %q, true", v, ok, "third")
		}
	})
}

// TestMapSweepsOnDoubling checks the bound: a write sweeps out the expired
// entries once the map has doubled since the last sweep, and only then, and
// the live entries survive every sweep.
func TestMapSweepsOnDoubling(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := New[string, int]()
		in := func(d time.Duration) time.Time { return time.Now().Add(d) }
		// The writes so far sweep nothing out and leave the next sweep at four
		// entries.
		m.Set("a", 0, in(2*time.Minute))
		m.Set("b", 0, in(2*time.Minute))
		m.Set("c", 0, in(time.Minute))
		m.Set("d", 0, in(time.Minute))

		// c and d expire; the write finding four entries sweeps them out and
		// keeps a and b, leaving the next sweep at four entries again.
		time.Sleep(time.Minute)
		m.Set("e", 0, in(2*time.Minute))
		if got, want := keys(m), []string{"a", "b", "e"}; !slices.Equal(got, want) {
			t.Fatalf("keys after the doubled write = %q, want %q", got, want)
		}

		// a and b expire; the write finding three entries leaves them in
		// place, and the next, finding four, sweeps them out.
		time.Sleep(time.Minute)
		m.Set("f", 0, in(2*time.Minute))
		if got, want := keys(m), []string{"a", "b", "e", "f"}; !slices.Equal(got, want) {
			t.Fatalf("keys before the map doubled = %q, want %q", got, want)
		}
		m.Set("g", 0, in(2*time.Minute))
		if got, want := keys(m), []string{"e", "f", "g"}; !slices.Equal(got, want) {
			t.Errorf("keys after the doubled write = %q, want %q", got, want)
		}
	})
}

// TestMapNil checks the nil map: it reports misses, and its writes store
// nothing.
func TestMapNil(t *testing.T) {
	var m *Map[string, string]
	m.Set("key", "value", time.Now().Add(time.Minute))
	m.SetIfAbsent("key", "value", time.Now().Add(time.Minute))
	if v, ok := m.Get("key"); ok || v != "" {
		t.Errorf("Get on a nil map = %q, %t, want the zero value, false", v, ok)
	}
}

// TestMapConcurrent runs writes and reads from concurrent goroutines for the
// race detector: a first-write-wins key, a replaced key, absent keys, and
// entries stored already expired, the last for the deleting read and the
// sweeps. With the two live keys kept by every sweep, the map ends holding at
// most four entries.
func TestMapConcurrent(t *testing.T) {
	m := New[string, int]()
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Go(func() {
			for i := range 50 {
				now := time.Now()
				m.SetIfAbsent("live", i, now.Add(time.Duration(g+1)*time.Minute))
				m.Set("replaced", i, now.Add(time.Minute))
				m.Set(fmt.Sprintf("dead-%d-%d", g, i), i, now.Add(-time.Minute))
				m.SetIfAbsent("dead", i, now.Add(-time.Minute))
				m.Get("live")
				m.Get("dead")
				m.Get("absent")
			}
		})
	}
	wg.Wait()
	for _, key := range []string{"live", "replaced"} {
		if _, ok := m.Get(key); !ok {
			t.Errorf("Get(%q) after the episodes = false, want the live entry kept", key)
		}
	}
	if _, ok := m.Get("dead"); ok {
		t.Error(`Get("dead") = true, want entries stored expired never reported`)
	}
	if got := keys(m); len(got) > 4 {
		t.Errorf("keys after the episodes = %q, want at most four", got)
	}
}
