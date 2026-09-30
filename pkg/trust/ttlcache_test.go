package trust

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// TestTTLCacheRoundtrip checks the plain hit: a value reads back inside
// its window, and a key never added reports the zero value.
func TestTTLCacheRoundtrip(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newTTLCache[string]()
		c.add("key", "value", time.Minute)

		if v, ok := c.get("key"); !ok || v != "value" {
			t.Errorf("get(%q) = %q, %t, want %q, true", "key", v, ok, "value")
		}
		if v, ok := c.get("absent"); ok || v != "" {
			t.Errorf("get(%q) = %q, %t, want the zero value, false", "absent", v, ok)
		}
	})
}

// TestTTLCacheExpiry checks the lazy window: once the bubble advances past
// the entry's expiry, the read refuses the value while the map still
// holds the entry, that refusing read deletes it, and a following add of
// the same key stores fresh.
func TestTTLCacheExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newTTLCache[string]()
		c.add("key", "first", time.Minute)

		time.Sleep(time.Minute + time.Second)
		synctest.Wait()

		if e, ok := c.m["key"]; !ok {
			t.Fatal("the map dropped the entry before any read refused it")
		} else if time.Now().Before(e.expires) {
			t.Fatalf("entry expires at %v, want before now %v", e.expires, time.Now())
		}
		if v, ok := c.get("key"); ok || v != "" {
			t.Errorf("get after expiry = %q, %t, want the zero value, false", v, ok)
		}
		if _, ok := c.m["key"]; ok {
			t.Error("the refusing read left the expired entry in the map")
		}

		c.add("key", "second", time.Minute)
		if v, ok := c.get("key"); !ok || v != "second" {
			t.Errorf("get(%q) after the re-add = %q, %t, want %q, true", "key", v, ok, "second")
		}
	})
}

// TestTTLCacheFirstWriteWins checks the add semantics: an add over a live
// entry keeps both the first value and the first window, and once that
// window has passed the next add takes the key.
func TestTTLCacheFirstWriteWins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newTTLCache[string]()
		c.add("key", "first", time.Minute)
		first := c.m["key"].expires

		c.add("key", "second", 2*time.Minute)

		if v, ok := c.get("key"); !ok || v != "first" {
			t.Errorf("get(%q) = %q, %t, want the first value %q, true", "key", v, ok, "first")
		}
		if got := c.m["key"].expires; !got.Equal(first) {
			t.Errorf("expiry = %v, want the first add's %v", got, first)
		}

		time.Sleep(time.Minute + time.Second)
		synctest.Wait()
		c.add("key", "second", time.Minute)
		if v, ok := c.get("key"); !ok || v != "second" {
			t.Errorf("get(%q) after the window passed = %q, %t, want %q, true",
				"key", v, ok, "second")
		}
	})
}

// TestTTLCacheConcurrent runs add and get episodes from concurrent
// goroutines for the race detector: one live key, absent keys, and
// born-expired entries, the last to exercise the pruning write.
func TestTTLCacheConcurrent(t *testing.T) {
	c := newTTLCache[int]()
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Go(func() {
			for i := range 50 {
				c.add("live", i, time.Duration(g+1)*time.Minute)
				c.add("dead", i, -time.Minute)
				c.get("live")
				c.get("dead")
				c.get("absent")
			}
		})
	}
	wg.Wait()
	if _, ok := c.get("live"); !ok {
		t.Error("get(live) after the episodes = false, want the live entry kept")
	}
	if _, ok := c.get("dead"); ok {
		t.Error("get(dead) = true, want born-expired entries never reported")
	}
}
