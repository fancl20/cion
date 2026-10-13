package ratelimit

import (
	"testing"
	"testing/synctest"
	"time"
)

// TestKeyedAdmitsOncePerInterval checks the per-key pace in a fake-time
// bubble: a key admitted once is refused until its interval has passed, to
// the nanosecond, while another key is admitted beside it.
func TestKeyedAdmitsOncePerInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := NewKeyed[int](time.Second)
		if !l.Admit(1) {
			t.Fatal("a fresh key was refused")
		}
		if l.Admit(1) {
			t.Error("a key was admitted twice inside its interval")
		}
		if !l.Admit(2) {
			t.Error("a second key was refused beside the first")
		}
		time.Sleep(time.Second - time.Nanosecond)
		if l.Admit(1) {
			t.Error("a key was admitted before its interval passed")
		}
		time.Sleep(time.Nanosecond)
		if !l.Admit(1) {
			t.Error("a key was refused once its interval passed")
		}
	})
}

// TestKeyedCap checks the limiter's bound and its sweep in a fake-time
// bubble: a full table refuses a fresh key while no held key has been silent
// for an interval, sweeps at most once per interval, and once a sweep runs it
// forgets the silent keys and keeps the one inside its interval.
func TestKeyedCap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const half = time.Second / 2
		l := NewKeyed[int](time.Second)
		for k := range keyCap - 1 {
			if !l.Admit(k) {
				t.Fatalf("key %d refused below the cap", k)
			}
		}
		time.Sleep(half)
		if !l.Admit(keyCap - 1) {
			t.Fatal("the last key below the cap was refused")
		}
		if l.Admit(keyCap) {
			t.Fatal("a fresh key was admitted past the cap")
		}
		if l.Admit(0) {
			t.Error("a held key was admitted inside its interval")
		}

		time.Sleep(half)
		if !l.Admit(0) {
			t.Error("a held key was refused once its interval passed")
		}
		if l.Admit(keyCap) {
			t.Error("a fresh key was admitted by a second sweep inside one interval")
		}

		time.Sleep(half)
		if !l.Admit(keyCap) {
			t.Fatal("a fresh key was refused once the sweep could forget the silent keys")
		}
		if l.Admit(0) {
			t.Error("the sweep forgot a key inside its interval")
		}
		if len(l.last) != 2 {
			t.Errorf("the limiter holds %d keys after the sweep, want the two inside their interval",
				len(l.last))
		}
	})
}
