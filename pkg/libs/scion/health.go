package scion

import (
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/libs/segment"
)

// Health is what the measurements, the callers' reports, and the signals say
// of a path's delivery.
type Health uint8

const (
	// HealthUnknown is a path nothing measured lately; its prior stands in.
	HealthUnknown Health = iota
	// HealthHealthy is a path that answered within the trust window.
	HealthHealthy
	// HealthSuspect is a path with a reason for doubt: a signal or a
	// caller's loss newer than its last answer, stale segments, or a link it
	// shares with failed paths.
	HealthSuspect
	// HealthEjected is a path whose delivery lies under ejectLine.
	HealthEjected
)

const (
	// trustWindow is how long a path's last answer counts it healthy: three
	// of the ping application's slowest probes.
	trustWindow = 3 * time.Minute
	// ejectLine is the delivery under which a path is ejected: one that
	// delivers less than half of what it carries costs each exchange more
	// than two attempts.
	ejectLine = 0.5
	// reportedLosses is how many of its latest losses a caller's report of
	// a path keeps: more than the losses in a row that put a delivery under
	// ejectLine.
	reportedLosses = bus.PathSamples
	// backoffBase and backoffCap space an ejected path's half-open probes:
	// backoffBase after its first lost burst, doubling with each, at most
	// backoffCap.
	backoffBase = 10 * time.Second
	backoffCap  = time.Minute
	// bandShare, bandFloor, and bandCap make the band, which two prices
	// ranked by their values tie within and a lease's move must clear:
	// bandShare of the smaller, at least bandFloor — jitter on a fast path —
	// and at most bandCap, one transit's price, so a path that saves a
	// transit takes over however long the path.
	bandShare = 0.2
	bandFloor = 2 * time.Millisecond
	bandCap   = 2 * TransitPenalty
	// picksRequester names the picks' entries among the path requests.
	picksRequester = "picks"
	// hotSpan is how far back a path's marked answers read: six heartbeats
	// of a path in use. hotLine is the share of its answers unmarked under
	// which a path is hot, with hotConfidence: three answers marked in a row
	// make it so.
	hotSpan       = 30 * time.Second
	hotLine       = 0.5
	hotConfidence = 0.8
)

// The kinds of estimate a candidate carries, each over its record's probes
// and bounded at BoundConfidence: its cost's, the median of the last
// bus.PathSamples sent within ReadingSpan, its reading's, the 80th
// percentile of every probe within ReadingSpan, and its reading's bounds',
// that percentile over BoundSpan. A path in use is probed every few seconds
// and another a minute apart or less often, so the count alone would span
// from under two minutes to far beyond the span: the span keeps the prices
// the picks and the leases compare within one horizon. At BoundConfidence, a
// median's bounds stand from ReadingSamples probes, each missing it with odds
// of one in 32.
var (
	costKind = evidence.Kind{Quantile: 0.5, Confidence: BoundConfidence, Span: ReadingSpan,
		Count: bus.PathSamples}
	readingKind = evidence.Kind{Quantile: readingQuantile, Confidence: BoundConfidence, Span: ReadingSpan}
	boundKind   = evidence.Kind{Quantile: readingQuantile, Confidence: BoundConfidence, Span: BoundSpan,
		Count: BoundSamples}
)

// report is what callers' traffic saw of one path: when it last delivered,
// and its losses since, the latest reportedLosses of them.
type report struct {
	delivered time.Time
	losses    []time.Time
}

// doubted returns the report's latest loss, zero for none.
func (r report) doubted() time.Time {
	if len(r.losses) == 0 {
		return time.Time{}
	}
	return r.losses[len(r.losses)-1]
}

// lostSince counts the report's losses after since and no earlier than
// within.
func (r report) lostSince(since, within time.Time) int {
	n := 0
	for _, at := range r.losses {
		if at.After(since) && !at.Before(within) {
			n++
		}
	}
	return n
}

// assess gives the candidate its health and cost by what the view holds; its
// last answer is the later of its probes' and its callers' last delivery. It
// is signaled while a signal on a link it crosses arrived after its last
// answer. Its health is the first of: ejected, for a delivery under
// ejectLine; suspect, signaled or for a caller's loss newer than its last
// answer; healthy, for an answer within the trust window; suspect, for stale
// segments or a crossed link its failed paths share; unknown. An ejected
// candidate is due its half-open probe its backoff after its last loss. It
// carries the estimates of its cost, its reading, and its bounds; its cost
// is the cost estimate's value, and its reading the reading estimate's, each
// else twice its declared one-way sum. The reading is read once
// ReadingSamples of its probes answered, and bounded where its probes give
// bounds.
func (v view) assess(c *Candidate) {
	r, _ := v.measured.Of(c.ID)
	rep := v.reports[c.ID]
	answered := later(r.LastAnswer, rep.delivered)
	c.Signaled = v.signaledSince(c.Crossed, answered)
	switch {
	case ejected(r, rep, v.now):
		c.Health = HealthEjected
		c.Retry = r.LastLoss.Add(backoff(r.LostBursts))
	case c.Signaled, rep.doubted().After(answered):
		c.Health = HealthSuspect
	case !answered.IsZero() && v.now.Sub(answered) < trustWindow:
		c.Health = HealthHealthy
	case c.Stale || slices.ContainsFunc(c.Crossed, func(l segment.LinkID) bool { return v.suspect[l] }):
		c.Health = HealthSuspect
	default:
		c.Health = HealthUnknown
	}
	c.Hot = hot(r.Samples, v.now)
	c.Evidence = costKind.Of(r.Samples, v.now)
	if c.Evidence.Answered > 0 {
		cost := c.Evidence.Value
		c.Cost = &cost
	} else if c.Latency != nil {
		prior := 2 * *c.Latency
		c.Cost = &prior
	}
	reading := readingKind.Of(r.Samples, v.now)
	c.ReadingEvidence = reading
	if reading.Answered > 0 {
		c.Reading, c.Read = &reading.Value, reading.Answered >= ReadingSamples
	} else if c.Latency != nil {
		prior := 2 * *c.Latency
		c.Reading = &prior
	}
	bounds := boundKind.Of(r.Samples, v.now)
	c.BoundsEvidence = bounds
	if bounds.HasLo && bounds.Lo > 0 {
		c.Low = &bounds.Lo
		if bounds.HasHi && bounds.Hi > 0 {
			c.High = &bounds.Hi
		}
	}
}

// signaledSince reports whether a signal standing on one of the links
// arrived later than since.
func (v view) signaledSince(links []segment.LinkID, since time.Time) bool {
	for _, l := range links {
		if at, ok := v.down.Arrived(l, v.now); ok && at.After(since) {
			return true
		}
	}
	return false
}

// recent returns the record's last bus.PathSamples probes, the ones its
// ejection reads.
func recent(r bus.PathRecord) []bus.PathSample {
	return r.Samples[max(0, len(r.Samples)-bus.PathSamples):]
}

// ejected reports whether a path's delivery lies under ejectLine at
// BoundConfidence by its record and its callers' report: over its losses
// since its last answer — the probes lost in a row at its record's end, sent
// since its callers' last delivery, beside its callers' losses since its
// probes' last answer within the trust window — or over its recent probes,
// unless a caller delivered since its last loss.
func ejected(r bus.PathRecord, rep report, now time.Time) bool {
	lost := rep.lostSince(r.LastAnswer, now.Add(-trustWindow))
	for i := len(r.Samples) - 1; i >= 0 && r.Samples[i].Lost && r.Samples[i].At.After(rep.delivered); i-- {
		lost++
	}
	under := func(s evidence.Proportion) bool { return s.Under(ejectLine) == evidence.Better }
	return under(evidence.Proportion{Sent: lost, Confidence: BoundConfidence}) ||
		!rep.delivered.After(r.LastLoss) && under(evidence.ProportionOf(recent(r), BoundConfidence))
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
		case ejected(r, report{}, now):
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
// a healthy or unknown path before a suspect one, an ejected one last; then
// a path that is not hot before a hot one, and a suspect one no signal names
// since its last answer before a signaled one; then by price, where both
// have one and the two differ beyond the band; then by Outranks.
func ranksAbove(a, b *Candidate) bool {
	if ta, tb := tier(a.Health), tier(b.Health); ta != tb {
		return ta < tb
	}
	if a.Hot != b.Hot {
		return !a.Hot
	}
	if a.Health == HealthSuspect && a.Signaled != b.Signaled {
		return !a.Signaled
	}
	pa, aPriced := a.Price()
	pb, bPriced := b.Price()
	if aPriced && bPriced && BeyondBand(pa, pb) {
		return pa < pb
	}
	return a.Outranks(b)
}

// tier orders the healths for the picks: healthy and unknown paths share the
// first tier, their prices ordering them.
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

// BeyondBand reports whether two prices differ by the band or more: by what
// the picks rank by and what has a lease weigh a path.
func BeyondBand(a, b time.Duration) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d >= Band(a, b)
}

// Band returns the band of two prices: bandShare of the smaller, at least
// bandFloor and at most bandCap.
func Band(a, b time.Duration) time.Duration {
	return max(bandFloor, min(time.Duration(bandShare*float64(min(a, b))), bandCap))
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

// request updates the requester's entries for the destination about the
// path in use: that path; the best other when it ranks above the one in use,
// weighed, so a lease measures the path it would move to as often as its
// own; the best other candidate crossing none of its links, else the best
// other, standby unless weighed; the best suspect candidate besides those
// whose prior order beats the one in use, suspect, for the verification
// that decides; and the best ejected candidate whose prior order beats the
// one in use, half-open once its backoff elapses. Each entry carries the
// destination's last pick or use, and when callers last confirmed and
// doubted its path. A provider without the requests topic, and a path in use
// without an identity, request nothing.
func (p *PathProvider) request(requester string, dst addr.IA, inUse *Candidate, picked time.Time,
	candidates []Candidate, v view) {

	if p.Requests == nil || inUse.ID == "" {
		return
	}
	entries := []bus.PathRequest{v.entry(dst, inUse, bus.PathInUse, time.Time{}, picked)}
	var best, disjoint, halfOpen *Candidate
	for i := range candidates {
		c := &candidates[i]
		if c.ID == "" || c.ID == inUse.ID {
			continue
		}
		if c.Health == HealthEjected {
			if c.Outranks(inUse) && (halfOpen == nil || c.Outranks(halfOpen)) {
				halfOpen = c
			}
			continue
		}
		if best == nil || ranksAbove(c, best) {
			best = c
		}
		if !sharesLink(c, inUse) && (disjoint == nil || ranksAbove(c, disjoint)) {
			disjoint = c
		}
	}
	standby := best
	if disjoint != nil {
		standby = disjoint
	}
	var weighed *Candidate
	if best != nil && ranksAbove(best, inUse) {
		weighed = best
		entries = append(entries, v.entry(dst, weighed, bus.PathWeighed, time.Time{}, picked))
	}
	if standby != nil && standby != weighed {
		entries = append(entries, v.entry(dst, standby, bus.PathStandby, time.Time{}, picked))
	}
	var suspect *Candidate
	for i := range candidates {
		c := &candidates[i]
		if c.ID == "" || c.ID == inUse.ID || c == standby || c == weighed || c.Health != HealthSuspect ||
			!c.Outranks(inUse) {
			continue
		}
		if suspect == nil || ranksAbove(c, suspect) {
			suspect = c
		}
	}
	if suspect != nil {
		entries = append(entries, v.entry(dst, suspect, bus.PathSuspect, time.Time{}, picked))
	}
	if halfOpen != nil {
		entries = append(entries, v.entry(dst, halfOpen, bus.PathHalfOpen, halfOpen.Retry, picked))
	}
	p.Requests.Update(func(r bus.PathRequests) bus.PathRequests {
		return r.Requested(requester, dst, entries, v.now.Add(-bus.RequestLapse))
	})
}

// entry returns the request of one candidate.
func (v view) entry(dst addr.IA, c *Candidate, role bus.PathRole, due, picked time.Time) bus.PathRequest {
	rep := v.reports[c.ID]
	return bus.PathRequest{
		ID:        c.ID,
		Dst:       dst,
		Links:     c.Crossed,
		Path:      c.Path,
		Role:      role,
		Due:       due,
		Picked:    picked,
		Confirmed: rep.delivered,
		Doubted:   rep.doubted(),
	}
}

// sharesLink reports whether two candidates cross a link in common.
func sharesLink(a, b *Candidate) bool {
	return slices.ContainsFunc(a.Crossed, func(l segment.LinkID) bool {
		return slices.Contains(b.Crossed, l)
	})
}

// hot reports whether the probes answered within hotSpan of now came back
// marked more than half the time, with hotConfidence.
func hot(samples []bus.PathSample, now time.Time) bool {
	answered, marked := 0, 0
	for _, s := range samples {
		if s.Lost || now.Sub(s.At) > hotSpan {
			continue
		}
		answered++
		if s.Marked {
			marked++
		}
	}
	return hotShare(marked, answered)
}

// hotShare reports whether marked of sent outcomes stand more than half,
// with hotConfidence.
func hotShare(marked, sent int) bool {
	unmarked := evidence.Proportion{Answered: sent - marked, Sent: sent, Confidence: hotConfidence}
	return unmarked.Under(hotLine) == evidence.Better
}
