package bus

import (
	"iter"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/segment"
)

// PathID names a path by the (ISD-AS, interface) pairs its packets cross, in
// order: the identity a path keeps while the segments it is composed of
// refresh.
type PathID string

// PathIDOf returns the ID of the path whose packets cross the links in order.
func PathIDOf(links []segment.LinkID) PathID {
	var b strings.Builder
	for i, l := range links {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(l.IA.String())
		b.WriteByte('#')
		b.WriteString(strconv.Itoa(int(l.IfID)))
	}
	return PathID(b.String())
}

// PathRole is what a requester needs a path measured for.
type PathRole uint8

// The roles, most demanding first: a path two requesters name takes the
// earlier role.
const (
	// PathInUse is the path a destination's pick or lease holds.
	PathInUse PathRole = iota
	// PathPriced is a route a requester prices by its measurements.
	PathPriced
	// PathStandby is the path the one in use would fail over to.
	PathStandby
	// PathSuspect is a path the evidence doubts whose prior order beats the
	// one in use, due the verification that decides.
	PathSuspect
	// PathHalfOpen is an ejected path due for the probe that may return it.
	PathHalfOpen
)

// RequestLapse is how long a request stands after its destination's last
// pick, use, or pricing.
const RequestLapse = 10 * time.Minute

// PathRequest is one path a requester needs measured.
type PathRequest struct {
	// ID is the path's identity.
	ID PathID
	// Dst is the path's destination.
	Dst addr.IA
	// Links are the (ISD-AS, interface) pairs the path's packets cross.
	Links []segment.LinkID
	// Path is the data-plane path the probes ride.
	Path *spath.Decoded
	// Role is what the path is measured for.
	Role PathRole
	// Due is when a half-open probe is due; zero for the other roles.
	Due time.Time
	// Picked is when the destination was last picked, used, or priced.
	Picked time.Time
	// Confirmed is when a caller's traffic last confirmed the path; zero
	// while none did.
	Confirmed time.Time
	// Doubted is when a caller's traffic last doubted the path; zero while
	// none did.
	Doubted time.Time
}

// PathRequests is the paths the node's requesters need measured: each
// requester's entries, by destination. A published PathRequests is never
// mutated, nor are the entries it holds. The zero PathRequests requests
// nothing.
type PathRequests struct {
	by map[string]map[addr.IA][]PathRequest
}

// Requested returns the requests with the requester's entries for dst
// replaced by entries, and each of the requester's destinations last picked
// before lapsed left out.
func (r PathRequests) Requested(
	requester string, dst addr.IA, entries []PathRequest, lapsed time.Time,
) PathRequests {

	next := PathRequests{by: make(map[string]map[addr.IA][]PathRequest, len(r.by)+1)}
	for name, dsts := range r.by {
		if name != requester {
			next.by[name] = dsts
		}
	}
	own := make(map[addr.IA][]PathRequest, len(r.by[requester])+1)
	for d, es := range r.by[requester] {
		if d != dst && !es[0].Picked.Before(lapsed) {
			own[d] = es
		}
	}
	if len(entries) > 0 {
		own[dst] = slices.Clone(entries)
	}
	next.by[requester] = own
	return next
}

// Replaced returns the requests with the requester's entries replaced by
// entries, by destination.
func (r PathRequests) Replaced(requester string, entries map[addr.IA][]PathRequest) PathRequests {
	next := PathRequests{by: make(map[string]map[addr.IA][]PathRequest, len(r.by)+1)}
	for name, dsts := range r.by {
		if name != requester {
			next.by[name] = dsts
		}
	}
	own := make(map[addr.IA][]PathRequest, len(entries))
	for dst, es := range entries {
		if len(es) > 0 {
			own[dst] = slices.Clone(es)
		}
	}
	next.by[requester] = own
	return next
}

// All yields every request, every requester's.
func (r PathRequests) All() iter.Seq[PathRequest] {
	return func(yield func(PathRequest) bool) {
		for _, dsts := range r.by {
			for _, es := range dsts {
				for _, e := range es {
					if !yield(e) {
						return
					}
				}
			}
		}
	}
}

// PathSamples is how many probes a path's record keeps.
const PathSamples = 20

// PathSample is one probe's outcome.
type PathSample struct {
	// At is when the probe was sent.
	At time.Time
	// RTT is the probe's round trip, zero when it was lost.
	RTT time.Duration
	// Lost reports whether the probe went unanswered.
	Lost bool
}

// PathRecord is one path's measurements.
type PathRecord struct {
	// Dst is the path's destination.
	Dst addr.IA
	// Links are the (ISD-AS, interface) pairs the path's packets cross.
	Links []segment.LinkID
	// Samples are the path's last probes, oldest first, at most
	// PathSamples. The first answer after a lost burst restarts them: the
	// probes lost before it describe an outage that ended.
	Samples []PathSample
	// LastAnswer is when the path last answered; zero while it has not.
	LastAnswer time.Time
	// LastLoss is when a probe of the path was last lost; zero while none
	// was.
	LastLoss time.Time
	// LostBursts counts the bursts lost whole since the last answer.
	LostBursts int
}

// PathMeasurements is the ping application's records of the paths it
// probes, by path. A published PathMeasurements is never mutated, nor are
// the records it holds. The zero PathMeasurements holds no record.
type PathMeasurements struct {
	records map[PathID]PathRecord
}

// NewPathMeasurements returns the measurements the map holds, copied.
func NewPathMeasurements(records map[PathID]PathRecord) PathMeasurements {
	return PathMeasurements{records: maps.Clone(records)}
}

// Of returns the path's record, false when the measurements hold none.
func (m PathMeasurements) Of(id PathID) (PathRecord, bool) {
	r, ok := m.records[id]
	return r, ok
}

// All yields every record with its path's ID.
func (m PathMeasurements) All() iter.Seq2[PathID, PathRecord] {
	return maps.All(m.records)
}
