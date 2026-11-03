package bus

import (
	"iter"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/segment"
)

// InterfaceDownState is the SCMP External Interface Down signals the node
// holds: each signaled link until its signal lapses, and the destinations
// whose packets the signals quoted. A published InterfaceDownState is never
// mutated. The zero InterfaceDownState holds no signal.
type InterfaceDownState struct {
	// seq counts the signals the state has taken.
	seq uint64
	// held maps each signaled link to when its signal lapses.
	held map[segment.LinkID]time.Time
	// quoted maps each quoted destination to its latest quote.
	quoted map[addr.IA]quote
}

// quote is a signal's quote of a packet to one destination: the signal's
// count in the state, and when the signal lapses.
type quote struct {
	seq   uint64
	until time.Time
}

// Signaled returns the state with one more signal, received at now and held
// until until: the link signaled down and, unless zero, the destination of
// the packet the signal quoted. Whatever lapsed by now is left out.
func (s InterfaceDownState) Signaled(link segment.LinkID, dst addr.IA, now, until time.Time) InterfaceDownState {
	next := InterfaceDownState{
		seq:    s.seq + 1,
		held:   make(map[segment.LinkID]time.Time, len(s.held)+1),
		quoted: make(map[addr.IA]quote, len(s.quoted)+1),
	}
	for l, lapse := range s.held {
		if now.Before(lapse) {
			next.held[l] = lapse
		}
	}
	for d, q := range s.quoted {
		if now.Before(q.until) {
			next.quoted[d] = q
		}
	}
	if until.After(next.held[link]) {
		next.held[link] = until
	}
	if !dst.IsZero() {
		next.quoted[dst] = quote{seq: next.seq, until: until}
	}
	return next
}

// Holds reports whether a signal the state holds names the link at now.
func (s InterfaceDownState) Holds(link segment.LinkID, now time.Time) bool {
	lapse, ok := s.held[link]
	return ok && now.Before(lapse)
}

// Lapse returns when the signal the state holds on the link lapses, false
// when no signal holds it at now.
func (s InterfaceDownState) Lapse(link segment.LinkID, now time.Time) (time.Time, bool) {
	lapse, ok := s.held[link]
	if !ok || !now.Before(lapse) {
		return time.Time{}, false
	}
	return lapse, true
}

// Seq counts the signals the state has taken, each state's count above its
// predecessor's.
func (s InterfaceDownState) Seq() uint64 {
	return s.seq
}

// QuotedAfter returns the destinations whose packets a signal the state
// holds quoted after the state's seq-th signal.
func (s InterfaceDownState) QuotedAfter(seq uint64) iter.Seq[addr.IA] {
	return func(yield func(addr.IA) bool) {
		for d, q := range s.quoted {
			if q.seq > seq && !yield(d) {
				return
			}
		}
	}
}
