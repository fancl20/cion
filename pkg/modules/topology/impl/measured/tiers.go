package measured

import (
	"slices"
	"sort"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/links"
)

// The window's tiers: the latency classes the sample map falls into, the
// facts the comparator's rules read off them, and each up link's excluded
// measurement.

// tier is one latency class of the window's sample map beside the facts the
// rules read — a decision label local to the node, derived each window from
// the samples and the last window's tiers, exchanged with no one.
type tier struct {
	// members are the classed peers, ascending by direct round trip.
	members []member
	// upLinks are the local sides of the tier's established links whose
	// verdicts are up — a down link is not the tier's redundancy and not its
	// route count's first term — one link ID per link: every composed path
	// over an up segment of the node names the interface it leaves through.
	upLinks []segment.LinkID
	// price is the cheapest clean read route into the tier at its price,
	// which an exclusion's harm reads, and estimate the least of those
	// routes' price estimates, the tier's price as the comparisons weigh it.
	// Zero and the zero estimate when no read route prices the tier, and no
	// priced rule fires on it.
	price    time.Duration
	estimate evidence.Estimate
	// prices is each member's own price as the comparisons weigh it: the
	// least of the price estimates of its clean read routes. A member no read
	// route prices is absent.
	prices map[addr.IA]evidence.Estimate
	// cheapest holds each member's cheapest clean route at its price, read
	// or not, requested priced so it is read, and one through a dead link is
	// ejected and the price rises to the routes that serve. A member no
	// route prices is absent.
	cheapest map[addr.IA]*scion.Candidate
	// routes is the independent routes into the tier, saturated at two.
	routes int
	// stranded reports that no up link reaches the tier and none of its
	// clean routes is healthy or unknown: the measurements doubt every one.
	stranded bool
	// excluded holds each up member link's excluded measurement.
	excluded map[addr.IA]excludedSample
}

// member is one classed peer with its direct round trip, and the estimate
// its direct side's bounds come from, which the walk weighs.
type member struct {
	ia     addr.IA
	direct time.Duration
	bounds evidence.Estimate
}

// excludedSample is one up link's excluded measurement: the tier's clean
// candidates that avoid the link — its survivors — the freshest of them
// requested priced. One measurement answering the useless test, the
// cut-critical reading, and the eviction's tests and ranking.
type excludedSample struct {
	// survivor is the freshest survivor, and dst the member it resolves
	// into; nil when none resolved.
	survivor *scion.Candidate
	dst      addr.IA
	// answered reports that the freshest survivor is healthy: the
	// measurements heard it within the trust window, and nothing doubted it
	// since. Otherwise the window decides nothing about the link.
	answered bool
	// price is the cheapest read survivor at its price, which an
	// exclusion's harm reads. Zero when no read survivor prices the tier.
	price time.Duration
	// routes is the tier's route count without the link: its other up links
	// beside the survivors, saturated at two.
	routes int
	// survivors is the least of the read survivors' price estimates, the
	// tier's price without the link as the comparisons weigh it, and
	// crossing the same over the read routes crossing the link; the zero
	// estimate where none prices. survivorsOf and crossingOf hold each
	// member's over its own; a member none of them reaches is absent.
	survivors, crossing     evidence.Estimate
	survivorsOf, crossingOf map[addr.IA]evidence.Estimate
	// cheapest holds each member's cheapest survivor at its price, read or
	// not, requested priced so it is read, and one through a dead link is
	// ejected before its price retires the link. A member no survivor
	// prices is absent.
	cheapest map[addr.IA]*scion.Candidate
	// cutOff holds the members no survivor reaches that a clean route or
	// the link reaches: the link's own neighbor, which the link reaches
	// whatever composes, is cut off unless a survivor reaches it.
	cutOff map[addr.IA]bool
}

// deriveTiers classes the window's samples by direct round trip, walked
// ascending, from the last window's tiers: at each peer, the bounds estimate
// of the median member of the current tier as walked, scaled by TierGap,
// weighs against the peer's, and the peer
//
//   - opens the next tier on better, and joins the current one on not
//     better;
//   - on undecided, keeps the side the last tiers held it on: a peer they
//     held in the tier the current one continues, or below it, joins, and
//     one they held above it opens the next tier, unless the first later
//     peer not so kept joins, for the tiers are runs of the walk;
//   - when none of the last tiers holds it, as in the first window, opens
//     the next tier when its round trip exceeds TierGap times the median's.
//
// Each tier continues one of the last: the first tier its first peer's, and
// a tier a peer opens that peer's when it was higher, else the one after.
// Unmeasured peers class into none — a peer with routes but no direct
// answer is not placed.
func deriveTiers(samples map[addr.IA]sample, last []tier) []tier {
	prev := make(map[addr.IA]int)
	for i, t := range last {
		for _, m := range t.members {
			prev[m.ia] = i
		}
	}
	var walk []member
	for ia, s := range samples {
		if s.direct > 0 {
			walk = append(walk, member{ia: ia, direct: s.direct, bounds: s.bounds})
		}
	}
	sort.Slice(walk, func(i, j int) bool {
		if walk[i].direct != walk[j].direct {
			return walk[i].direct < walk[j].direct
		}
		return uint64(walk[i].ia) < uint64(walk[j].ia)
	})
	var ts []tier
	start, cur := 0, 0
	for i, m := range walk {
		if i == 0 {
			cur = prev[m.ia]
			continue
		}
		med := walk[(start+i)/2]
		opens, kept := step(m, med, prev, cur)
		for j := i + 1; kept && j < len(walk); j++ {
			opens, kept = step(walk[j], med, prev, cur)
		}
		if !opens {
			continue
		}
		ts = append(ts, tier{members: walk[start:i]})
		start = i
		cur++
		if was, ok := prev[m.ia]; ok && was > cur {
			cur = was
		}
	}
	if start < len(walk) {
		ts = append(ts, tier{members: walk[start:]})
	}
	return ts
}

// step weighs a peer against the tier being walked, whose median member is
// med and which continues the last tiers' place cur, as deriveTiers does:
// whether the peer opens the next tier, and whether it opens only because
// the weighing is undecided and the last tiers held it above cur. prev
// holds the place of each peer's tier among the last tiers.
func step(m, med member, prev map[addr.IA]int, cur int) (opens, kept bool) {
	was, ok := prev[m.ia]
	if !ok {
		return m.direct > ratioOf(med.direct, TierGap), false
	}
	switch compare(med.bounds.Mul(TierGap), m.bounds, 0) {
	case evidence.Better:
		return true, false
	case evidence.NotBetter:
		return false, false
	}
	return was > cur, was > cur
}

// windowTiers derives the window's tiers from the samples and the last
// window's, which they replace, computes their facts from the store, the
// verdicts, and the per-peer enumerations, and runs each up member link's
// excluded measurement over the window's candidates. A candidate that is
// not clean is no route, so it prices nothing and counts as nothing; one
// whose reading is not read prices no decision.
func (s *selection) windowTiers(
	neighbors map[addr.IA]*links.Link,
	samples map[addr.IA]sample,
) []tier {

	ts := deriveTiers(samples, s.tiers)
	s.tiers = slices.Clone(ts) // the members alone: the facts below fill ts
	for i := range ts {
		t := &ts[i]
		up := make(map[addr.IA]segment.LinkID)
		clean := make(map[addr.IA][]*scion.Candidate)
		var routes []*scion.Candidate
		for _, m := range t.members {
			if l, ok := neighbors[m.ia]; ok && s.linkUp(l.IfID) {
				link := segment.LinkID{IA: s.cfg.IA, IfID: l.IfID}
				up[m.ia] = link
				t.upLinks = append(t.upLinks, link)
			}
			sm := samples[m.ia]
			for j := range sm.candidates {
				if c := &sm.candidates[j]; s.clean(c) {
					clean[m.ia] = append(clean[m.ia], c)
					routes = append(routes, c)
				}
			}
		}
		_, t.price = cheapest(readRoutes(routes))
		t.estimate = leastPrice(readRoutes(routes))
		t.prices = make(map[addr.IA]evidence.Estimate, len(t.members))
		t.cheapest = make(map[addr.IA]*scion.Candidate, len(t.members))
		for _, m := range t.members {
			if c, _ := cheapest(clean[m.ia]); c != nil {
				t.cheapest[m.ia] = c
			}
			if price := leastPrice(readRoutes(clean[m.ia])); price.Answered > 0 {
				t.prices[m.ia] = price
			}
		}
		t.routes = routeCount(t.upLinks, routes)
		t.stranded = len(t.upLinks) == 0 && !slices.ContainsFunc(routes, func(c *scion.Candidate) bool {
			return c.Health == scion.HealthHealthy || c.Health == scion.HealthUnknown
		})
		t.excluded = make(map[addr.IA]excludedSample, len(up))
		for ia, link := range up {
			t.excluded[ia] = measureExcluded(t, clean, ia, link)
		}
	}
	return ts
}

// measureExcluded runs one up link's excluded measurement over the window's
// candidates: the tier's clean candidates that do not traverse the link —
// either of its two interface IDs sufficing, a hard filter, for a survivor
// crossing the link would answer the question falsely — the freshest of
// them, and each member's cheapest, requested priced over the member it
// resolves into, the read ones pricing. The measurement crosses the
// survivors, not the questioned link.
func measureExcluded(
	t *tier,
	clean map[addr.IA][]*scion.Candidate,
	neighbor addr.IA,
	link segment.LinkID,
) excludedSample {

	excluded := []segment.LinkID{link}
	var survivors []*scion.Candidate
	ex := excludedSample{}
	for _, m := range t.members {
		for _, c := range clean[m.ia] {
			if traverses(c, excluded) {
				continue
			}
			survivors = append(survivors, c)
			if ex.survivor == nil || c.Fresh.After(ex.survivor.Fresh) {
				ex.survivor, ex.dst = c, m.ia
			}
		}
	}
	others := slices.DeleteFunc(slices.Clone(t.upLinks), func(l segment.LinkID) bool {
		return l == link
	})
	ex.routes = routeCount(others, survivors)
	if ex.survivor == nil {
		return ex
	}
	ex.answered = ex.survivor.Health == scion.HealthHealthy
	_, ex.price = cheapest(readRoutes(survivors))
	ex.survivors = leastPrice(readRoutes(survivors))
	ex.survivorsOf = make(map[addr.IA]evidence.Estimate, len(t.members))
	ex.crossingOf = make(map[addr.IA]evidence.Estimate)
	ex.cheapest = make(map[addr.IA]*scion.Candidate, len(t.members))
	ex.cutOff = make(map[addr.IA]bool)
	var crossing []*scion.Candidate
	for _, m := range t.members {
		var own, crossed []*scion.Candidate
		for _, c := range clean[m.ia] {
			if slices.Contains(survivors, c) {
				own = append(own, c)
			} else {
				crossed = append(crossed, c)
			}
		}
		crossing = append(crossing, readRoutes(crossed)...)
		if price := leastPrice(readRoutes(crossed)); price.Answered > 0 {
			ex.crossingOf[m.ia] = price
		}
		if len(own) == 0 && (len(clean[m.ia]) > 0 || m.ia.Equal(neighbor)) {
			ex.cutOff[m.ia] = true
			continue
		}
		if c, _ := cheapest(own); c != nil {
			ex.cheapest[m.ia] = c
		}
		if price := leastPrice(readRoutes(own)); price.Answered > 0 {
			ex.survivorsOf[m.ia] = price
		}
	}
	ex.crossing = leastPrice(crossing)
	return ex
}

// judge reads an up link's useless test off its tier this window, the
// direct side of the link's own neighbor given. Better when the link helps
// no one: its exclusion keeps the tier's route count and cuts no member off,
// and the survivors beat the read routes crossing the link, for the tier and
// for every member those routes reach, and the neighbor's direct side, each
// by no line. Not better once the link helps anyone, so a pair between
// promotion's line and no help at all keeps its link. Undecided while no
// read route prices the tier, the freshest survivor went unanswered, a
// member's routes none read, or a comparison lacks its evidence — a member
// the survivors reach but no read survivor prices among them: a price
// unknown is not unchanged. A link no answered route avoids decides
// nothing: the cut-critical link, which no useless retirement takes.
func judge(t *tier, ia addr.IA, direct evidence.Estimate) evidence.Verdict {
	ex, ok := excludedOf(t, ia)
	if !ok {
		return evidence.Undecided
	}
	if ex.routes != t.routes || len(ex.cutOff) > 0 {
		return evidence.NotBetter
	}
	verdicts := []evidence.Verdict{compare(ex.survivorsOf[ia], direct, 0)}
	if ex.crossing.Answered > 0 {
		verdicts = append(verdicts, compare(ex.survivors, ex.crossing, 0))
	}
	for m, crossing := range ex.crossingOf {
		verdicts = append(verdicts, compare(ex.survivorsOf[m], crossing, 0))
	}
	if t.unread(ia) {
		verdicts = append(verdicts, evidence.Undecided)
	}
	return fold(verdicts)
}

// judgeOutside reads the useless test of an up link the clustering does not
// allow, whatever its prices: decided once a survivor answered, useless
// when the link's exclusion keeps the tier's route count and cuts no member
// off, and joined reports that a chosen pair links the two units.
func judgeOutside(t *tier, ia addr.IA, joined bool) (decided, useless bool) {
	if t == nil {
		return false, false
	}
	ex, ok := t.excluded[ia]
	if !ok || !ex.answered {
		return false, false
	}
	if !joined || ex.routes != t.routes {
		return true, false
	}
	for _, m := range t.members {
		if ex.cutOff[m.ia] {
			return true, false
		}
	}
	return true, true
}

// yields reads whether an up link would not earn its place today, the
// direct side of the link's own neighbor given: its exclusion keeps the
// tier's route count and cuts no member off, and the read routes crossing
// it beat the survivors by the band for no price they reach — the tier's,
// every member's those routes reach, and the neighbor's by its direct side
// — each comparison not better. A link that would not earn its place today
// yields its slot to a candidate that does; one better or undecided
// anywhere, its worth near the line, keeps it, as does one beside a member
// whose routes none read.
func yields(t *tier, ia addr.IA, direct evidence.Estimate) bool {
	ex, ok := excludedOf(t, ia)
	if !ok || ex.routes != t.routes || len(ex.cutOff) > 0 || t.unread(ia) {
		return false
	}
	if byBand(direct, ex.survivorsOf[ia]) != evidence.NotBetter {
		return false
	}
	if ex.crossing.Answered > 0 && byBand(ex.crossing, ex.survivors) != evidence.NotBetter {
		return false
	}
	for m, crossing := range ex.crossingOf {
		if byBand(crossing, ex.survivorsOf[m]) != evidence.NotBetter {
			return false
		}
	}
	return true
}

// outgained reads whether an up link yields its slot to a candidate gaining
// gain on its price, the direct side of the link's own neighbor given: its
// exclusion keeps the tier's route count and cuts no member off, and the
// gain beats what the link saves every price it reaches by the band of the
// two — the survivors' price less the crossing routes', for the tier and
// every member those routes reach, and the neighbor's survivors less its
// direct side. A saving the gain does not beat, or one undecided, keeps the
// link's slot, as does a member whose routes none read.
func outgained(t *tier, ia addr.IA, direct, gain evidence.Estimate) bool {
	ex, ok := excludedOf(t, ia)
	if !ok || ex.routes != t.routes || len(ex.cutOff) > 0 || t.unread(ia) {
		return false
	}
	beaten := func(saving evidence.Estimate) bool { return byBand(saving, gain) == evidence.Better }
	if !beaten(ex.survivorsOf[ia].Sub(direct)) {
		return false
	}
	if ex.crossing.Answered > 0 && !beaten(ex.survivors.Sub(ex.crossing)) {
		return false
	}
	for m, crossing := range ex.crossingOf {
		if !beaten(ex.survivorsOf[m].Sub(crossing)) {
			return false
		}
	}
	return true
}

// seen returns the survivors whose fresh probes a useless retirement's hold
// reads: those reaching the link's own neighbor, else the tier's, else the
// freshest survivor, which answered for any window that decides.
func (ex excludedSample) seen(neighbor addr.IA) evidence.Estimate {
	switch {
	case ex.survivorsOf[neighbor].Answered > 0:
		return ex.survivorsOf[neighbor]
	case ex.survivors.Answered > 0:
		return ex.survivors
	case ex.survivor != nil:
		return priceBounds(ex.survivor)
	}
	return evidence.Estimate{}
}

// excludedOf returns the excluded measurement of the up link to the peer
// when the window can judge it: a read route prices the tier, and the
// freshest survivor answered.
func excludedOf(t *tier, ia addr.IA) (excludedSample, bool) {
	if t == nil || t.estimate.Answered == 0 {
		return excludedSample{}, false
	}
	ex, ok := t.excluded[ia]
	return ex, ok && ex.answered
}

// unread reports whether a member of the tier other than the link's own
// neighbor has clean routes none of which is read: its price is unknown.
func (t *tier) unread(neighbor addr.IA) bool {
	return slices.ContainsFunc(t.members, func(m member) bool {
		_, priced := t.prices[m.ia]
		return !m.ia.Equal(neighbor) && !priced && t.cheapest[m.ia] != nil
	})
}

// harm is how far a link's exclusion moves its tier's price.
func harm(t *tier, ia addr.IA) time.Duration {
	d := t.excluded[ia].price - t.price
	if d < 0 {
		return -d
	}
	return d
}

// tierOf returns the tier holding the peer, nil when the window left it
// unclassed.
func tierOf(ts []tier, ia addr.IA) *tier {
	for i := range ts {
		for _, m := range ts[i].members {
			if m.ia.Equal(ia) {
				return &ts[i]
			}
		}
	}
	return nil
}

// beats weighs the member's direct side against its own price, the tier's
// when no route prices the member, by the band of the two, and returns the
// verdict beside the price weighed: better when the direct link buys what
// the path policy moves a lease for. A member whose routes none read weighs
// nothing until one is: its price is unknown. An unpriced tier weighs
// nothing.
func (t *tier) beats(ia addr.IA, direct evidence.Estimate) (evidence.Verdict, evidence.Estimate) {
	price, ok := t.prices[ia]
	if !ok {
		if t.cheapest[ia] != nil {
			return evidence.Undecided, evidence.Estimate{}
		}
		price = t.estimate
	}
	return byBand(direct, price), price
}

// secondRoute weighs the member's direct side against the ceiling of a tier
// of one route: better when the direct link, the tier's second route, costs
// no more than that — redundancy purchased at a bounded latency price. A
// tier of other than one route weighs nothing.
func (t *tier) secondRoute(direct evidence.Estimate) evidence.Verdict {
	if t.routes != 1 {
		return evidence.Undecided
	}
	return compare(direct, secondRouteCeiling(t.estimate), 0)
}

// secondRouteCeiling returns the most a second route may cost against the
// price: the price scaled by SecondRouteRatio.
func secondRouteCeiling(price evidence.Estimate) evidence.Estimate {
	return price.Mul(SecondRouteRatio)
}

// gain returns what the member's direct side saves on its price as beats
// weighs the two: the price's estimate less the direct side's; the zero
// estimate where beats weighs nothing.
func (t *tier) gain(ia addr.IA, direct evidence.Estimate) evidence.Estimate {
	_, price := t.beats(ia, direct)
	return price.Sub(direct)
}

// compare weighs whether a beats b by the line, as evidence.Beats does;
// undecided where either rests on no answered sample.
func compare(a, b evidence.Estimate, line time.Duration) evidence.Verdict {
	if a.Answered == 0 || b.Answered == 0 {
		return evidence.Undecided
	}
	return evidence.Beats(a, b, line)
}

// byBand weighs whether a beats b by the band of their values: what the
// path policy moves a lease for.
func byBand(a, b evidence.Estimate) evidence.Verdict {
	return compare(a, b, scion.Band(a.Value, b.Value))
}

// fold returns the verdict of comparisons that must all be better: not
// better at any not better, else undecided at any undecided, else better.
func fold(verdicts []evidence.Verdict) evidence.Verdict {
	out := evidence.Better
	for _, v := range verdicts {
		switch v {
		case evidence.NotBetter:
			return evidence.NotBetter
		case evidence.Undecided:
			out = evidence.Undecided
		}
	}
	return out
}

// leastPrice returns the least of the routes' price estimates: each route's
// bounds' estimate at its price.
func leastPrice(routes []*scion.Candidate) evidence.Estimate {
	prices := make([]evidence.Estimate, len(routes))
	for i, c := range routes {
		prices[i] = priceBounds(c)
	}
	return evidence.Min(prices...)
}

// priceBounds returns the estimate a route's price and its bounds come from:
// its bounds' estimate, charged scion.TransitPenalty for every AS it crosses
// between its ends, each way.
func priceBounds(c *scion.Candidate) evidence.Estimate {
	return c.BoundsEvidence.Add(c.Charge())
}

// readRoutes returns the routes whose readings decide: those resting on at
// least scion.ReadingSamples answered probes.
func readRoutes(routes []*scion.Candidate) []*scion.Candidate {
	return slices.DeleteFunc(slices.Clone(routes), func(c *scion.Candidate) bool { return !c.Read })
}

// cheapest returns the route a set of routes is priced by, and that price:
// the cheapest of them, each at its price, the picks' own — its cost, the
// measured round trip or else its declared one-way sum doubled, charged
// scion.TransitPenalty for every AS it crosses between its ends, each way —
// the first of the cheapest. A route without a cost, or with a zero one,
// prices nothing: an undeclared edge is unknown, not free. Nil and zero when
// nothing prices the set.
func cheapest(routes []*scion.Candidate) (*scion.Candidate, time.Duration) {
	var out *scion.Candidate
	var price time.Duration
	for _, c := range routes {
		if p, ok := c.Price(); ok && *c.Cost > 0 && (out == nil || p < price) {
			out, price = c, p
		}
	}
	return out, price
}
