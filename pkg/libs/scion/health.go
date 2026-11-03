package scion

import (
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/segment"
)

// Health is what the measurements and the signals say of a path's delivery.
type Health uint8

const (
	// HealthUnknown is a path nothing measured lately; its prior stands in.
	HealthUnknown Health = iota
	// HealthHealthy is a path that answered within the trust window.
	HealthHealthy
	// HealthSuspect is a path with a reason for doubt: a signal newer than
	// its last answer, stale segments, or a link it shares with failed paths.
	HealthSuspect
	// HealthEjected is a path that lost a burst whole since its last answer,
	// or nearly every recent probe.
	HealthEjected
)

const (
	// trustWindow is how long a path's last answer counts it healthy: three
	// of the ping application's slowest probes.
	trustWindow = 3 * time.Minute
	// ejectSamples and ejectShare eject a path whose records hold at least
	// ejectSamples probes, ejectShare of them lost.
	ejectSamples = 10
	ejectShare   = 0.9
	// lossCap bounds the loss a cost counts, so a lossy path's cost stays
	// finite.
	lossCap = 0.9
	// backoffBase and backoffCap space an ejected path's half-open probes:
	// backoffBase after its first lost burst, doubling with each, at most
	// backoffCap.
	backoffBase = 10 * time.Second
	backoffCap  = time.Minute
	// bandShare and bandFloor are the band within which two costs tie: a
	// difference within bandShare of the smaller or within bandFloor.
	bandShare = 0.2
	bandFloor = 2 * time.Millisecond
	// picksRequester names the picks' entries among the path requests.
	picksRequester = "picks"
)

// assess gives the candidate its health and cost by what the view holds. Its
// health is the first of: ejected, by its record; suspect, for a held signal
// on a link it crosses newer than its last answer; healthy, for an answer
// within the trust window; suspect, for stale segments or a crossed link its
// failed paths share; unknown. Its cost is its measured cost, else twice its
// declared one-way sum.
func (v view) assess(c *Candidate) {
	r, measured := v.measured.Of(c.ID)
	switch {
	case measured && ejected(r):
		c.Health = HealthEjected
	case v.signaledSince(c.Crossed, r.LastAnswer):
		c.Health = HealthSuspect
	case measured && !r.LastAnswer.IsZero() && v.now.Sub(r.LastAnswer) < trustWindow:
		c.Health = HealthHealthy
	case c.Stale || slices.ContainsFunc(c.Crossed, func(l segment.LinkID) bool { return v.suspect[l] }):
		c.Health = HealthSuspect
	default:
		c.Health = HealthUnknown
	}
	if cost, ok := measuredCost(r); ok {
		c.Cost = &cost
	} else if c.Latency != nil {
		prior := 2 * *c.Latency
		c.Cost = &prior
	}
}

// signaledSince reports whether a held signal names one of the links later
// than since.
func (v view) signaledSince(links []segment.LinkID, since time.Time) bool {
	for _, l := range links {
		if lapse, ok := v.down.Lapse(l, v.now); ok && lapse.Add(-InterfaceDownHold).After(since) {
			return true
		}
	}
	return false
}

// ejected reports whether the record ejects its path: a burst lost whole
// since its last answer, or ejectShare of at least ejectSamples probes lost.
func ejected(r bus.PathRecord) bool {
	if r.LostBursts > 0 {
		return true
	}
	return len(r.Samples) >= ejectSamples && float64(lost(r))/float64(len(r.Samples)) >= ejectShare
}

// lost counts the record's lost probes.
func lost(r bus.PathRecord) int {
	n := 0
	for _, s := range r.Samples {
		if s.Lost {
			n++
		}
	}
	return n
}

// measuredCost returns the record's median answered round trip divided by
// its delivery rate, its loss counted up to lossCap; false when no probe
// answered.
func measuredCost(r bus.PathRecord) (time.Duration, bool) {
	var rtts []time.Duration
	for _, s := range r.Samples {
		if !s.Lost {
			rtts = append(rtts, s.RTT)
		}
	}
	if len(rtts) == 0 {
		return 0, false
	}
	slices.Sort(rtts)
	median := rtts[len(rtts)/2]
	loss := min(float64(len(r.Samples)-len(rtts))/float64(len(r.Samples)), lossCap)
	return time.Duration(float64(median) / (1 - loss)), true
}

// suspectLinks returns the links the records' failed paths share: each link
// a path with an ejecting record crosses and no healthy path crosses, while
// some healthy path answers.
func suspectLinks(m bus.PathMeasurements, now time.Time) map[segment.LinkID]bool {
	failed := make(map[segment.LinkID]bool)
	healthy := make(map[segment.LinkID]bool)
	answering := false
	for _, r := range m.All() {
		switch {
		case ejected(r):
			for _, l := range r.Links {
				failed[l] = true
			}
		case !r.LastAnswer.IsZero() && now.Sub(r.LastAnswer) < trustWindow:
			answering = true
			for _, l := range r.Links {
				healthy[l] = true
			}
		}
	}
	if !answering {
		return nil
	}
	for l := range failed {
		if healthy[l] {
			delete(failed, l)
		}
	}
	return failed
}

// ranksAbove reports whether a ranks above b among the picks: by health,
// a healthy or unknown path before a suspect one, a suspect one crossing no
// held signal before one crossing it, an ejected one last; then by cost,
// where both have one and the two differ beyond the band; then by Outranks.
func ranksAbove(a, b *Candidate) bool {
	if ta, tb := tier(a.Health), tier(b.Health); ta != tb {
		return ta < tb
	}
	if a.Health == HealthSuspect && a.Crossing != b.Crossing {
		return !a.Crossing
	}
	if a.Cost != nil && b.Cost != nil && beyondBand(*a.Cost, *b.Cost) {
		return *a.Cost < *b.Cost
	}
	return a.Outranks(b)
}

// tier orders the healths for the picks: healthy and unknown paths share the
// first tier, their costs ordering them.
func tier(h Health) int {
	switch h {
	case HealthSuspect:
		return 1
	case HealthEjected:
		return 2
	default:
		return 0
	}
}

// beyondBand reports whether two costs differ by more than the band.
func beyondBand(a, b time.Duration) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d > bandFloor && float64(d) > bandShare*float64(min(a, b))
}

// backoff returns how long after its last loss an ejected path is due for a
// half-open probe: backoffBase after its first lost burst, doubling with each
// one after, at most backoffCap.
func backoff(lostBursts int) time.Duration {
	d := backoffBase
	for i := 1; i < lostBursts && d < backoffCap; i++ {
		d *= 2
	}
	return min(d, backoffCap)
}

// request updates the picks' entries for the destination: the pick, in use;
// the best other candidate crossing none of its links, else the best other,
// standby; the best suspect candidate besides the standby whose prior order
// beats the pick's, suspect, for the verification that decides; and the best
// ejected candidate whose prior order beats the pick's, half-open once its
// backoff elapses. A provider without the requests topic, and a pick without
// an identity, request nothing.
func (p *PathProvider) request(dst addr.IA, pick *Candidate, candidates []Candidate, v view) {
	if p.Requests == nil || pick.ID == "" {
		return
	}
	entries := []bus.PathRequest{entry(dst, pick, bus.PathInUse, time.Time{}, v.now)}
	var standby, disjoint, halfOpen *Candidate
	for i := range candidates {
		c := &candidates[i]
		if c.ID == "" || c.ID == pick.ID {
			continue
		}
		if c.Health == HealthEjected {
			if c.Outranks(pick) && (halfOpen == nil || c.Outranks(halfOpen)) {
				halfOpen = c
			}
			continue
		}
		if standby == nil || ranksAbove(c, standby) {
			standby = c
		}
		if !sharesLink(c, pick) && (disjoint == nil || ranksAbove(c, disjoint)) {
			disjoint = c
		}
	}
	if disjoint != nil {
		standby = disjoint
	}
	if standby != nil {
		entries = append(entries, entry(dst, standby, bus.PathStandby, time.Time{}, v.now))
	}
	var suspect *Candidate
	for i := range candidates {
		c := &candidates[i]
		if c.ID == "" || c.ID == pick.ID || c == standby || c.Health != HealthSuspect || !c.Outranks(pick) {
			continue
		}
		if suspect == nil || ranksAbove(c, suspect) {
			suspect = c
		}
	}
	if suspect != nil {
		entries = append(entries, entry(dst, suspect, bus.PathSuspect, time.Time{}, v.now))
	}
	if halfOpen != nil {
		r, _ := v.measured.Of(halfOpen.ID)
		due := r.LastLoss.Add(backoff(r.LostBursts))
		entries = append(entries, entry(dst, halfOpen, bus.PathHalfOpen, due, v.now))
	}
	p.Requests.Update(func(r bus.PathRequests) bus.PathRequests {
		return r.Requested(picksRequester, dst, entries, v.now.Add(-bus.RequestLapse))
	})
}

// entry returns the request of one candidate.
func entry(dst addr.IA, c *Candidate, role bus.PathRole, due, picked time.Time) bus.PathRequest {
	return bus.PathRequest{
		ID:     c.ID,
		Dst:    dst,
		Links:  c.Crossed,
		Path:   c.Path,
		Role:   role,
		Due:    due,
		Picked: picked,
	}
}

// sharesLink reports whether two candidates cross a link in common.
func sharesLink(a, b *Candidate) bool {
	return slices.ContainsFunc(a.Crossed, func(l segment.LinkID) bool {
		return slices.Contains(b.Crossed, l)
	})
}
