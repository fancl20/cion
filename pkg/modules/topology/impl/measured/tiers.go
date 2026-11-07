package measured

import (
	"slices"
	"sort"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/links"
)

// The window's tiers: the latency classes the sample map falls into, the
// facts the comparator's rules read off them, and each up link's excluded
// measurement.

// tier is one latency class of the window's sample map beside the facts the
// rules read — a decision label local to the node, recomputed each window,
// keyed by nothing stable, exchanged with no one.
type tier struct {
	// members are the classed peers, ascending by direct round trip.
	members []member
	// upLinks are the local sides of the tier's established links whose
	// verdicts are up — a down link is not the tier's redundancy and not its
	// route count's first term — one link ID per link: every composed path
	// over an up segment of the node names the interface it leaves through.
	upLinks []segment.LinkID
	// price is the cheapest clean read route into the tier at its cost.
	// Zero when no read route prices the tier, and no priced rule fires on
	// it.
	price time.Duration
	// prices is each member's own price: the cheapest clean read route into
	// the member, priced as memberRoute prices routes. A member no read
	// route prices is absent.
	prices map[addr.IA]time.Duration
	// low is the lowest lower bound of the tier's clean read routes at
	// their costs, and lows each member's over its own at their prices: what
	// the member's price stays above with confidence. Zero, or absent, where
	// no read route bounds it.
	low  time.Duration
	lows map[addr.IA]time.Duration
	// cheapest holds each member's cheapest clean route at its cost, read or
	// not, requested priced so it is read, and one through a dead link is
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

// member is one classed peer with its direct round trip and the round
// trip's lower bound.
type member struct {
	ia     addr.IA
	direct time.Duration
	low    time.Duration
}

// excludedSample is one up link's excluded measurement: the tier's clean
// candidates that avoid the link — its survivors — the freshest of them
// requested priced. One measurement answering the useless test, the
// cut-critical reading, and the eviction ranking.
type excludedSample struct {
	// survivor is the freshest survivor, and dst the member it resolves
	// into; nil when none resolved.
	survivor *scion.Candidate
	dst      addr.IA
	// answered reports that the freshest survivor is healthy: the
	// measurements heard it within the trust window, and nothing doubted it
	// since. Otherwise the window decides nothing about the link.
	answered bool
	// price is the cheapest read survivor at its cost. Zero when no read
	// survivor prices the tier.
	price time.Duration
	// routes is the tier's route count without the link: its other up links
	// beside the survivors, saturated at two.
	routes int
	// prices is each member's price over its read survivors, priced as
	// memberRoute prices routes. A member no read survivor prices is absent.
	prices map[addr.IA]time.Duration
	// cheapest holds each member's cheapest survivor at its cost, read or
	// not, requested priced so it is read, and one through a dead link is
	// ejected before its price retires the link. A member no survivor
	// prices is absent.
	cheapest map[addr.IA]*scion.Candidate
	// cutOff holds the members no survivor reaches that a clean route or
	// the link reaches: the link's own neighbor, which the link reaches
	// whatever composes, is cut off unless a survivor reaches it.
	cutOff map[addr.IA]bool
	// The bounds the history confirms a judgment by. crossed reports that a
	// clean read route into the tier crosses the link; low is the lowest
	// lower bound of those routes and high the lowest upper bound of the
	// read survivors, at their costs. lows holds each member a read route
	// crossing the link reaches, at the lowest lower bound of those routes,
	// and highs each member's lowest upper bound over its read survivors,
	// each at its price. A bound the probes do not give is zero.
	crossed   bool
	low, high time.Duration
	lows      map[addr.IA]time.Duration
	highs     map[addr.IA]time.Duration
}

// deriveTiers classes the window's samples by direct round trip: walked
// ascending, a peer joins the current tier while its round trip is at most
// TierGap times the median of that tier's members as walked and opens the
// next when it exceeds it. Unmeasured peers class into none — a peer with
// routes but no direct answer is not placed.
func deriveTiers(samples map[addr.IA]sample) []tier {
	var walk []member
	for ia, s := range samples {
		if s.direct > 0 {
			walk = append(walk, member{ia: ia, direct: s.direct, low: s.lo})
		}
	}
	sort.Slice(walk, func(i, j int) bool {
		if walk[i].direct != walk[j].direct {
			return walk[i].direct < walk[j].direct
		}
		return uint64(walk[i].ia) < uint64(walk[j].ia)
	})
	var ts []tier
	start := 0
	for i, m := range walk {
		if i > start && m.direct > ratioOf(walk[(start+i)/2].direct, TierGap) {
			ts = append(ts, tier{members: walk[start:i]})
			start = i
		}
	}
	if start < len(walk) {
		ts = append(ts, tier{members: walk[start:]})
	}
	return ts
}

// windowTiers derives the window's tiers, computes their facts from the
// store, the verdicts, and the per-peer enumerations, and runs each up
// member link's excluded measurement over the window's candidates. A
// candidate that is not clean is no route, so it prices nothing and counts
// as nothing; one whose reading is not read prices no decision.
func (s *selection) windowTiers(
	neighbors map[addr.IA]*links.Link,
	samples map[addr.IA]sample,
) []tier {

	ts := deriveTiers(samples)
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
		t.price = cheapest(readRoutes(routes))
		t.prices = make(map[addr.IA]time.Duration, len(t.members))
		t.lows = make(map[addr.IA]time.Duration, len(t.members))
		t.cheapest = make(map[addr.IA]*scion.Candidate, len(t.members))
		for _, c := range readRoutes(routes) {
			if c.Low != nil {
				t.low = lower(t.low, *c.Low)
			}
		}
		for _, m := range t.members {
			if c, _ := memberRoute(clean[m.ia]); c != nil {
				t.cheapest[m.ia] = c
			}
			if _, price := memberRoute(readRoutes(clean[m.ia])); price > 0 {
				t.prices[m.ia] = price
			}
			for _, c := range readRoutes(clean[m.ia]) {
				if lo, _ := boundsOf(c); lo > 0 {
					t.lows[m.ia] = lower(t.lows[m.ia], lo)
				}
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
	ex.price = cheapest(readRoutes(survivors))
	ex.prices = make(map[addr.IA]time.Duration, len(t.members))
	ex.cheapest = make(map[addr.IA]*scion.Candidate, len(t.members))
	ex.cutOff = make(map[addr.IA]bool)
	ex.lows = make(map[addr.IA]time.Duration)
	ex.highs = make(map[addr.IA]time.Duration)
	for _, m := range t.members {
		for _, c := range readRoutes(clean[m.ia]) {
			lo, hi := boundsOf(c)
			if slices.Contains(survivors, c) {
				if hi > 0 {
					ex.highs[m.ia] = lower(ex.highs[m.ia], hi)
					ex.high = lower(ex.high, *c.High)
				}
				continue
			}
			ex.crossed = true
			ex.lows[m.ia] = lower(ex.lows[m.ia], lo)
			if c.Low != nil {
				ex.low = lower(ex.low, *c.Low)
			}
		}
	}
	for _, m := range t.members {
		var own []*scion.Candidate
		for _, c := range clean[m.ia] {
			if slices.Contains(survivors, c) {
				own = append(own, c)
			}
		}
		if len(own) == 0 && (len(clean[m.ia]) > 0 || m.ia.Equal(neighbor)) {
			ex.cutOff[m.ia] = true
			continue
		}
		if c, _ := memberRoute(own); c != nil {
			ex.cheapest[m.ia] = c
		}
		if _, price := memberRoute(readRoutes(own)); price > 0 {
			ex.prices[m.ia] = price
		}
	}
	return ex
}

// judge reads an up link's useless test off its tier this window. The
// window decides when a read route prices the tier and the freshest route
// avoiding the link answered. It decides useless when the link helps no one,
// by the readings and by the history: its exclusion leaves the tier's route
// count and price unchanged, cuts no member off, and leaves every priced
// member a read survivor no dearer than its own price — the link's own
// neighbor than its direct round trip, the sample promotion compares with
// the same price — and the bounds confirm each such price, the survivors'
// upper bound no higher than the link's lower bound. A link that helps
// anyone stays, so a pair between promotion's line and no help at all keeps
// its link, and so does one whose uselessness the history does not confirm
// yet: the history lags a change, the readings follow it. A member the
// survivors reach but no read survivor prices, or one whose routes none
// read, leaves the window undecided: its price is unknown, not unchanged. A
// member no route prices holds nothing against the link. A link no answered
// route avoids decides nothing — the cut-critical link, which no useless
// retirement takes.
func judge(t *tier, ia addr.IA) (decided, useless bool) {
	decided, useless = weigh(t, ia, func(with, without time.Duration) bool { return without > with })
	if !decided || !useless {
		return decided, useless
	}
	return true, confirmed(t, ia, func(low, high time.Duration) bool { return high <= low })
}

// yields reads an up link's eviction test off its tier this window: judge's,
// with each price the link holds down weighed as promotion weighs a direct
// round trip — the link helps where its reading would earn its place, by
// PromotionRatio and MarginFloor — and the bounds confirming that it gains
// no member what the path policy moves a lease for. A link that would not
// earn its place today, and whose history confirms it, yields its slot to a
// candidate that does; one whose worth noise holds near the line keeps it.
func yields(t *tier, ia addr.IA) (decided, weak bool) {
	decided, weak = weigh(t, ia, func(with, without time.Duration) bool {
		return with < ratioOf(without, PromotionRatio) && without-with >= MarginFloor
	})
	if !decided || !weak {
		return decided, weak
	}
	return true, confirmed(t, ia, func(low, high time.Duration) bool { return !gains(low, high) })
}

// confirmed reports whether the history confirms a judgment of an up link:
// for the tier, where a read route crosses the link, and for every member a
// read route crossing the link reaches, the link's lower bound and the
// survivors' upper bound stand as holds has them — the link's own neighbor
// by its direct side's lower bound. A bound the probes do not give confirms
// nothing.
func confirmed(t *tier, ia addr.IA, holds func(low, high time.Duration) bool) bool {
	ex := t.excluded[ia]
	if ex.crossed && (ex.low == 0 || ex.high == 0 || !holds(ex.low, ex.high)) {
		return false
	}
	for _, m := range t.members {
		low, ok := ex.lows[m.ia]
		if m.ia.Equal(ia) {
			low, ok = m.low, true
		}
		if !ok {
			continue
		}
		if high := ex.highs[m.ia]; low == 0 || high == 0 || !holds(low, high) {
			return false
		}
	}
	return true
}

// weigh runs the test judge and yields share, the link helping a price it
// holds down when helps reports so, given the price with it and without it.
func weigh(t *tier, ia addr.IA, helps func(with, without time.Duration) bool) (decided, idle bool) {
	if t == nil || t.price == 0 {
		return false, false
	}
	ex, ok := t.excluded[ia]
	if !ok || !ex.answered {
		return false, false
	}
	if ex.routes != t.routes || helps(t.price, ex.price) {
		return true, false
	}
	unpriced := false
	for _, m := range t.members {
		price := t.prices[m.ia]
		if m.ia.Equal(ia) {
			price = m.direct
		}
		switch {
		case ex.cutOff[m.ia]:
			return true, false
		case price == 0 && t.cheapest[m.ia] == nil:
		case price == 0, ex.prices[m.ia] == 0:
			unpriced = true
		case helps(price, ex.prices[m.ia]):
			return true, false
		}
	}
	return !unpriced, !unpriced
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

// qualifies reports whether the member's direct round trip, beside its
// upper bound, earns a link under the priced admission cases: a second route
// for a single-route tier within SecondRouteRatio of the tier's price —
// redundancy purchased at a bounded latency price — or a round trip beating
// its own price as beats has it. An unpriced tier qualifies nothing.
func (t *tier) qualifies(ia addr.IA, direct, high time.Duration) bool {
	if t.price == 0 {
		return false
	}
	return t.beats(ia, direct, high) || (t.routes == 1 && direct <= ratioOf(t.price, SecondRouteRatio))
}

// beats reports whether the member's direct round trip beats its own price,
// the tier's when no route prices the member, in one of two ways. On the
// readings alone, by the promotion ratio and by at least the margin floor:
// what the path policy moves a lease for, with room for the readings'
// error. Or confirmed: by what the path policy moves a lease for, on the
// readings and on the bounds, the direct side's upper bound against the
// price's lower bound, where the confidence holds the error. A member whose
// routes none read beats nothing until one is: its price is unknown. An
// unpriced tier beats nothing.
func (t *tier) beats(ia addr.IA, direct, high time.Duration) bool {
	if t.price == 0 {
		return false
	}
	price, low := t.prices[ia], t.lows[ia]
	if price == 0 {
		if t.cheapest[ia] != nil {
			return false
		}
		price, low = t.price, t.low
	}
	if direct < ratioOf(price, PromotionRatio) && price-direct >= MarginFloor {
		return true
	}
	return gains(direct, price) && high > 0 && gains(high, low)
}

// gains reports whether a round trip of to gains on one of from what the
// path policy moves a lease for: it is lower, by the band or more.
func gains(to, from time.Duration) bool {
	return to < from && scion.BeyondBand(to, from)
}

// boundsOf returns the route's bounds at its price — each charged as its
// price charges its cost — zero for a bound its probes do not give.
func boundsOf(c *scion.Candidate) (low, high time.Duration) {
	if c.Low != nil {
		low = *c.Low + c.Charge()
	}
	if c.High != nil {
		high = *c.High + c.Charge()
	}
	return low, high
}

// readRoutes returns the routes whose readings decide: those resting on at
// least scion.ReadingSamples answered probes.
func readRoutes(routes []*scion.Candidate) []*scion.Candidate {
	return slices.DeleteFunc(slices.Clone(routes), func(c *scion.Candidate) bool { return !c.Read })
}

// memberRoute returns the route a member's routes price it by, and that
// price: the cheapest of them, each at its price, the picks' own — its cost
// charged scion.TransitPenalty for every AS it crosses between its ends,
// each way — the first of the cheapest. A route without a cost, or with a
// zero one, prices nothing. Nil and zero when nothing prices the member.
func memberRoute(routes []*scion.Candidate) (*scion.Candidate, time.Duration) {
	var out *scion.Candidate
	var price time.Duration
	for _, c := range routes {
		if p, ok := c.Price(); ok && *c.Cost > 0 && (out == nil || p < price) {
			out, price = c, p
		}
	}
	return out, price
}

// lower returns the smaller of two prices, a zero pricing nothing.
func lower(a, b time.Duration) time.Duration {
	if a == 0 || b > 0 && b < a {
		return b
	}
	return a
}
