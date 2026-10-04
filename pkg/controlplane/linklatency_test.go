package controlplane

import (
	"testing"
	"time"
)

// TestLinkLatencySampleLifecycle checks the sample table's lifecycle: a
// recorded sample reads back until a later window replaces it, and a link
// the latest window did not measure declares nothing again.
func TestLinkLatencySampleLifecycle(t *testing.T) {
	l := NewLinkLatency()
	if got := l.Sample(3); got != 0 {
		t.Errorf("unsampled interface = %v, want 0", got)
	}
	l.Record(3, 5*time.Millisecond)
	if got := l.Sample(3); got != 5*time.Millisecond {
		t.Errorf("sample = %v, want 5ms", got)
	}
	l.Record(3, 6*time.Millisecond)
	if got := l.Sample(3); got != 6*time.Millisecond {
		t.Errorf("replaced sample = %v, want 6ms", got)
	}
	l.Record(3, 0)
	if got := l.Sample(3); got != 0 {
		t.Errorf("dropped sample = %v, want 0", got)
	}
}
