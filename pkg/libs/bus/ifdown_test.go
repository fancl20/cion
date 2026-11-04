package bus

import (
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/segment"
)

// TestInterfaceDownState checks the interface-down state: a signal stands
// from its arrival until RequestLapse after it, a later signal on its link
// replaces its arrival, the next signal leaves the lapsed ones out, and a
// published state is never mutated.
func TestInterfaceDownState(t *testing.T) {
	t0 := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	link := func(as addr.AS, ifID uint16) segment.LinkID {
		return segment.LinkID{IA: addr.MustIAFrom(1, as), IfID: ifID}
	}
	arrived := func(s InterfaceDownState, l segment.LinkID, now time.Time) time.Time {
		at, ok := s.Arrived(l, now)
		if !ok {
			return time.Time{}
		}
		return at
	}

	var zero InterfaceDownState
	if _, ok := zero.Arrived(link(1, 1), t0); ok {
		t.Error("the zero state holds a signal")
	}

	first := zero.Signaled(link(1, 1), t0)
	if got := arrived(first, link(1, 1), t0.Add(RequestLapse-time.Nanosecond)); !got.Equal(t0) {
		t.Errorf("the signal's arrival just before its lapse = %v, want %v", got, t0)
	}
	if _, ok := first.Arrived(link(1, 1), t0.Add(RequestLapse)); ok {
		t.Error("a signal stood past its lapse")
	}
	if _, ok := first.Arrived(link(1, 2), t0); ok {
		t.Error("a signal named a link it does not name")
	}
	if _, ok := zero.Arrived(link(1, 1), t0); ok {
		t.Error("a published state was mutated")
	}

	second := first.Signaled(link(1, 1), t0.Add(time.Minute))
	if got := arrived(second, link(1, 1), t0.Add(RequestLapse)); !got.Equal(t0.Add(time.Minute)) {
		t.Errorf("the link's arrival after a later signal = %v, want the later %v",
			got, t0.Add(time.Minute))
	}

	// Past the first signal's lapse, the next signal leaves it out.
	third := first.Signaled(link(2, 1), t0.Add(RequestLapse))
	if _, ok := third.arrived[link(1, 1)]; ok {
		t.Error("the next state kept a lapsed signal")
	}
	if got := arrived(third, link(2, 1), t0.Add(RequestLapse)); !got.Equal(t0.Add(RequestLapse)) {
		t.Errorf("the new signal's arrival = %v, want %v", got, t0.Add(RequestLapse))
	}
}
