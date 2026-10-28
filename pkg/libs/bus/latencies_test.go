package bus

import (
	"testing"
	"time"
)

// TestLinkLatencies checks the latencies: an event holds the estimates its
// map held, copied, leaves the zero delays out, and reports zero for a link
// it lacks; the zero event holds none.
func TestLinkLatencies(t *testing.T) {
	m := map[uint16]time.Duration{1: 5 * time.Millisecond, 2: 0}
	l := NewLinkLatencies(m)
	m[1] = time.Second
	if got := l.Of(1); got != 5*time.Millisecond {
		t.Errorf("link 1's estimate = %v, want 5ms, unchanged by its map's later write", got)
	}
	if _, ok := l.m[2]; ok {
		t.Error("a zero delay was kept")
	}
	if got := l.Of(3); got != 0 {
		t.Errorf("a link the event lacks = %v, want 0", got)
	}
	var zero LinkLatencies
	if got := zero.Of(1); got != 0 {
		t.Errorf("the zero event's estimate = %v, want 0", got)
	}
}
