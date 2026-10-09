package measured

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
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
	// baseline is the fastest answered baseline echo among the members;
	// zero when none answered. The stranded test reads it.
	baseline time.Duration
	// price is the cheapest route into the tier: a route the window probed
	// by its baseline echo, any other clean candidate by its declared sum.
	// Zero when nothing prices the tier, and no priced rule fires on it.
	price time.Duration
	// routes is the independent routes into the tier, saturated at two.
	routes int
	// stranded reports that no up link and no answered composed route reach
	// the tier.
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
// candidates that avoid the link — its survivors — with the freshest of them
// echoed. One measurement answering the useless test, the cut-critical
// reading, and the eviction ranking.
type excludedSample struct {
	// echo is the freshest survivor's round trip, measured each window,
	// never a remembered value. Zero when no survivor resolved or the echo
	// went unanswered: the window decides nothing about the link.
	echo time.Duration
	// price is the cheapest survivor: the echoed one by its echo, a
	// surviving carrier of a baseline echo by that echo, any other by its
	// declared sum. Zero when nothing prices the survivors.
	price time.Duration
	// routes is the tier's route count without the link: its other up links
	// beside the survivors, saturated at two.
	routes int
}

// deriveTiers classes the window's samples by direct round trip: walked
// ascending, a peer joins the current tier while its round trip is at most
// TierGap times the median of that tier's members as walked and opens the
// next when it exceeds it. Unmeasured peers class into none — a peer with
// only a path baseline and no direct answer is not placed.
func deriveTiers(samples map[addr.IA]sample) []tier {
	var walk []member
	for ia, s := range samples {
		if s.m.direct > 0 {
			walk = append(walk, member{ia: ia, direct: s.m.direct})
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
// candidate that crosses a signaled interface or one of the node's down
// links is no route, so it prices nothing and counts as nothing.
func (s *selection) windowTiers(
	ctx context.Context,
	neighbors map[addr.IA]*links.Link,
	entries map[addr.IA]DirectoryEntry,
	samples map[addr.IA]sample,
) []tier {

	ts := deriveTiers(samples)
	for i := range ts {
		t := &ts[i]
		up := make(map[addr.IA]segment.LinkID)
		clean := make(map[addr.IA][]*scion.Candidate)
		var routes []*scion.Candidate
		var echoes []time.Duration
		probed := make(map[*scion.Candidate]bool)
		for _, m := range t.members {
			if l, ok := neighbors[m.ia]; ok && s.linkUp(l.IfID) {
				link := segment.LinkID{IA: s.cfg.IA, IfID: l.IfID}
				up[m.ia] = link
				t.upLinks = append(t.upLinks, link)
			}
			sm := samples[m.ia]
			if sm.m.path > 0 && (t.baseline == 0 || sm.m.path < t.baseline) {
				t.baseline = sm.m.path
			}
			echoes = append(echoes, sm.m.path)
			if sm.carrier != nil {
				probed[sm.carrier] = true
			}
			for j := range sm.candidates {
				if c := &sm.candidates[j]; s.clean(c) {
					clean[m.ia] = append(clean[m.ia], c)
					routes = append(routes, c)
				}
			}
		}
		t.price = cheapest(echoes, routes, probed)
		t.routes = routeCount(t.upLinks, routes)
		t.stranded = len(t.upLinks) == 0 && t.baseline == 0
		t.excluded = make(map[addr.IA]excludedSample, len(up))
		for ia, link := range up {
			t.excluded[ia] = s.measureExcluded(ctx, t, clean, samples, entries, link)
		}
	}
	return ts
}

// measureExcluded runs one up link's excluded measurement over the window's
// candidates: the tier's clean candidates that do not traverse the link —
// either of its two interface IDs sufficing, a hard filter, for a survivor
// crossing the link would answer the question falsely — the freshest of
// them echoed over the member it resolves into. The probe crosses the
// survivors, not the questioned link, at the loop's cadence on its own
// socket, in the evaluation window — measurement stays the selector's
// instrument.
func (s *selection) measureExcluded(
	ctx context.Context,
	t *tier,
	clean map[addr.IA][]*scion.Candidate,
	samples map[addr.IA]sample,
	entries map[addr.IA]DirectoryEntry,
	link segment.LinkID,
) excludedSample {

	excluded := []segment.LinkID{link}
	var survivors []*scion.Candidate
	var freshest *scion.Candidate
	var dst addr.IA
	for _, m := range t.members {
		for _, c := range clean[m.ia] {
			if traverses(c, excluded) {
				continue
			}
			survivors = append(survivors, c)
			if freshest == nil || c.Fresh.After(freshest.Fresh) {
				freshest, dst = c, m.ia
			}
		}
	}
	others := slices.DeleteFunc(slices.Clone(t.upLinks), func(l segment.LinkID) bool {
		return l == link
	})
	ex := excludedSample{routes: routeCount(others, survivors)}
	if freshest == nil {
		return ex
	}
	ex.echo = s.pathEcho(ctx, entries[dst], freshest)
	echoes := []time.Duration{ex.echo}
	probed := map[*scion.Candidate]bool{freshest: true}
	for _, m := range t.members {
		sm := samples[m.ia]
		if c := sm.carrier; c != nil && c != freshest && slices.Contains(survivors, c) {
			echoes = append(echoes, sm.m.path)
			probed[c] = true
		}
	}
	ex.price = cheapest(echoes, survivors, probed)
	return ex
}

// judge reads an up link's useless test off its tier this window. The
// window decides when the tier is priced and the freshest route avoiding the
// link answered its echo; it decides useless when the link's exclusion
// leaves the tier's route count unchanged and its price no worse than the
// demotion ratio above the tier's. A link no answered route avoids decides
// nothing — the cut-critical link, which no useless retirement takes.
func judge(t *tier, ia addr.IA) (decided, useless bool) {
	if t == nil || t.price == 0 {
		return false, false
	}
	ex, ok := t.excluded[ia]
	if !ok || ex.echo == 0 {
		return false, false
	}
	return true, ex.routes == t.routes && ex.price <= ratioOf(t.price, DemotionRatio)
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

// qualifies reports whether a direct round trip earns a link into the tier
// under the priced admission cases: a second route for a single-route tier
// within the demotion ratio of the price — redundancy purchased at a
// bounded latency price — or a round trip beating the price by the
// promotion ratio. An unpriced tier qualifies nothing.
func (t *tier) qualifies(direct time.Duration) bool {
	if t.price == 0 {
		return false
	}
	return direct < ratioOf(t.price, PromotionRatio) ||
		(t.routes == 1 && direct <= ratioOf(t.price, DemotionRatio))
}
