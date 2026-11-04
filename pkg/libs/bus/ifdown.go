package bus

import (
	"time"

	"github.com/fancl20/cion/pkg/libs/segment"
)

// InterfaceDownState is the SCMP External Interface Down signals the node
// holds: when each signaled link's latest signal arrived, for RequestLapse,
// the lapse of the callers' reports. A published InterfaceDownState is never
// mutated. The zero InterfaceDownState holds no signal.
type InterfaceDownState struct {
	// arrived maps each signaled link to when its latest signal arrived.
	arrived map[segment.LinkID]time.Time
}

// Signaled returns the state with one more signal on the link, arrived at
// now. Whatever lapsed by now is left out.
func (s InterfaceDownState) Signaled(link segment.LinkID, now time.Time) InterfaceDownState {
	next := InterfaceDownState{arrived: make(map[segment.LinkID]time.Time, len(s.arrived)+1)}
	for l, at := range s.arrived {
		if now.Sub(at) < RequestLapse {
			next.arrived[l] = at
		}
	}
	if now.After(next.arrived[link]) {
		next.arrived[link] = now
	}
	return next
}

// Arrived returns when the latest signal the state holds on the link
// arrived, false when none stands at now.
func (s InterfaceDownState) Arrived(link segment.LinkID, now time.Time) (time.Time, bool) {
	at, ok := s.arrived[link]
	if !ok || now.Sub(at) >= RequestLapse {
		return time.Time{}, false
	}
	return at, true
}
