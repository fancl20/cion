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
	// price is the cheapest clean route into the tier at its cost. Zero when
	// nothing prices the tier, and no priced rule fires on it.
	price time.Duration
	// prices is each member's own price: the cheapest clean route into the
	// member, priced as memberPrice prices routes. A member no route prices
	// is absent.
	prices map[addr.IA]time.Duration
	// routes is the independent routes into the tier, saturated at two.
	routes int
	// stranded reports that no up link reaches the tier and none of its
	// clean routes is healthy or unknown: the measurements doubt every one.
	stranded bool
	// excluded holds each up member link's excluded measurement.
	excluded map[addr.IA]excludedSample
}

// member is one classed peer with its direct round trip.
type member struct {
	ia     addr.IA
	direct time.Duration
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
	// price is the cheapest survivor at its cost. Zero when nothing prices
	// the survivors.
	price time.Duration
	// routes is the tier's route count without the link: its other up links
	// beside the survivors, saturated at two.
	routes int
	// prices is each member's price over its survivors, priced as
	// memberPrice prices routes. A member no survivor prices is absent.
	prices map[addr.IA]time.Duration
	// cutOff holds the members no survivor reaches that a clean route or
	// the link reaches: the link's own neighbor, which the link reaches
	// whatever composes, is cut off unless a survivor reaches it.
	cutOff map[addr.IA]bool
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
			walk = append(walk, member{ia: ia, direct: s.direct})
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
// as nothing.
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
		t.price = cheapest(routes)
		t.prices = make(map[addr.IA]time.Duration, len(t.members))
		for _, m := range t.members {
			if p := memberPrice(clean[m.ia]); p > 0 {
				t.prices[m.ia] = p
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
// them requested priced over the member it resolves into. The measurement
// crosses the survivors, not the questioned link.
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
	ex.price = cheapest(survivors)
	ex.prices = make(map[addr.IA]time.Duration, len(t.members))
	ex.cutOff = make(map[addr.IA]bool)
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
		if price := memberPrice(own); price > 0 {
			ex.prices[m.ia] = price
		}
	}
	return ex
}

// judge reads an up link's useless test off its tier this window. The
// window decides when the tier is priced and the freshest route avoiding the
// link answered. It decides useless when the link's exclusion leaves the
// tier's route count unchanged and its price within the demotion ratio of
// the tier's, cuts no member off, and leaves every priced member a
// survivor within the demotion ratio of its own price — the link's own
// neighbor of its direct round trip, the sample promotion compares with the
// same price. A priced member the survivors reach but none prices leaves the
// window undecided: its price without the link is unknown, not within the
// ratio. A member no route prices holds nothing against the link. A link no
// answered route avoids decides nothing — the cut-critical link, which no
// useless retirement takes.
func judge(t *tier, ia addr.IA) (decided, useless bool) {
	if t == nil || t.price == 0 {
		return false, false
	}
	ex, ok := t.excluded[ia]
	if !ok || !ex.answered {
		return false, false
	}
	if ex.routes != t.routes || ex.price > ratioOf(t.price, DemotionRatio) {
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
		case price == 0:
		case ex.prices[m.ia] == 0:
			unpriced = true
		case ex.prices[m.ia] > ratioOf(price, DemotionRatio):
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

// qualifies reports whether the member's direct round trip earns a link
// under the priced admission cases: a second route for a single-route tier
// within the demotion ratio of the tier's price — redundancy purchased at a
// bounded latency price — or a round trip beating the member's own price,
// the tier's when no route prices the member, by the promotion ratio and by
// at least the margin floor. An unpriced tier qualifies nothing.
func (t *tier) qualifies(ia addr.IA, direct time.Duration) bool {
	if t.price == 0 {
		return false
	}
	price := t.prices[ia]
	if price == 0 {
		price = t.price
	}
	beats := direct < ratioOf(price, PromotionRatio) && price-direct >= MarginFloor
	return beats || (t.routes == 1 && direct <= ratioOf(t.price, DemotionRatio))
}

// memberPrice prices one member's routes by the cheapest of them, each at
// its price, the picks' own: its cost charged scion.TransitPenalty for every
// AS it crosses between its ends, each way. A route without a cost, or with
// a zero one, prices nothing. Zero when nothing prices the member.
func memberPrice(routes []*scion.Candidate) time.Duration {
	var price time.Duration
	for _, c := range routes {
		if p, ok := c.Price(); ok && *c.Cost > 0 {
			price = lower(price, p)
		}
	}
	return price
}

// lower returns the smaller of two prices, a zero pricing nothing.
func lower(a, b time.Duration) time.Duration {
	if a == 0 || b > 0 && b < a {
		return b
	}
	return a
}
