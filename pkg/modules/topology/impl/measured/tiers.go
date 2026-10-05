package measured

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
)

// The window's tiers: the latency classes the sample map falls into, the
// facts the comparator's rules read off them, and each established link's
// excluded measurement.

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
	// up holds the peers of the up links, the cut-critical guard's "no other
	// up link in the tier".
	up map[addr.IA]bool
	// baseline is the fastest composed-path round trip among the members:
	// the minimum of their baseline echoes. Zero when none answered.
	baseline time.Duration
	// price is tierPrice over the baseline and the members' candidates.
	// Zero when nothing prices the tier, and no priced rule fires on it.
	price time.Duration
	// routes is the independent routes into the tier, saturated at two.
	routes int
	// stranded reports no live route: no up links and no clean composed
	// candidate into any member.
	stranded bool
	// excluded holds each established member link's excluded measurement.
	excluded map[addr.IA]excludedSample
}

// member is one classed peer with its direct round trip.
type member struct {
	ia     addr.IA
	direct time.Duration
}

// excludedSample is one established link's excluded measurement: the
// enumeration to its tier's members with the link excluded, the freshest
// clean survivor echoed. One measurement answering three questions — the
// useless test, cut-criticality, and the eviction ranking.
type excludedSample struct {
	// survived reports whether a clean route into the tier survives the
	// exclusion.
	survived bool
	// echo is the freshest survivor's round trip — the excluded baseline,
	// measured each window, never a remembered value. Zero when no survivor
	// resolved or the echo went unanswered.
	echo time.Duration
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
// store, the verdicts, and the per-peer enumerations, and runs each
// established member link's excluded measurement — the enumeration to its
// tier's members with the link excluded, the freshest clean survivor echoed
// over the member it resolves into.
func (s *selection) windowTiers(
	ctx context.Context,
	neighbors map[addr.IA]*links.Link,
	entries map[addr.IA]DirectoryEntry,
	samples map[addr.IA]sample,
) []tier {

	ts := deriveTiers(samples)
	for i := range ts {
		t := &ts[i]
		t.up = make(map[addr.IA]bool)
		var priced, clean []scion.Candidate
		for _, m := range t.members {
			if l, ok := neighbors[m.ia]; ok && s.linkUp(l.IfID) {
				t.up[m.ia] = true
				t.upLinks = append(t.upLinks, segment.LinkID{IA: s.cfg.IA, IfID: l.IfID})
			}
			sm := samples[m.ia]
			if sm.m.path > 0 && (t.baseline == 0 || sm.m.path < t.baseline) {
				t.baseline = sm.m.path
			}
			priced = append(priced, sm.candidates...)
			for j := range sm.candidates {
				if s.clean(&sm.candidates[j]) {
					clean = append(clean, sm.candidates[j])
				}
			}
		}
		t.price = tierPrice(t.baseline, priced)
		t.routes = routeCount(t.upLinks, clean)
		t.stranded = t.routes == 0
		t.excluded = make(map[addr.IA]excludedSample)
		for _, m := range t.members {
			l, ok := neighbors[m.ia]
			if !ok {
				continue
			}
			t.excluded[m.ia] = s.measureExcluded(ctx, t, entries,
				segment.LinkID{IA: s.cfg.IA, IfID: l.IfID})
		}
	}
	return ts
}

// measureExcluded runs one established link's excluded measurement: the
// enumeration to its tier's members with the link excluded — the hard filter
// the path layer defines, never the cache's last resort — echoed over the
// freshest clean survivor. The probes cross the survivors, not the
// questioned link, at the loop's cadence on its own socket, in the
// evaluation window — measurement stays the selector's instrument.
func (s *selection) measureExcluded(
	ctx context.Context,
	t *tier,
	entries map[addr.IA]DirectoryEntry,
	exclude segment.LinkID,
) excludedSample {

	if s.excludedFn != nil {
		members := make([]addr.IA, len(t.members))
		for i, m := range t.members {
			members[i] = m.ia
		}
		return s.excludedFn(ctx, members, exclude)
	}
	probeCtx, cancel := context.WithTimeout(ctx, ProbeWait*ProbeRuns+time.Second)
	defer cancel()
	var best *scion.Candidate
	var dst addr.IA
	for _, m := range t.members {
		if _, ok := entries[m.ia]; !ok {
			continue // no published control address to echo at
		}
		candidates, err := s.cfg.Provider.Enumerate(probeCtx, m.ia, exclude)
		if err != nil {
			continue
		}
		for i := range candidates {
			c := &candidates[i]
			if s.clean(c) && (best == nil || c.Fresh.After(best.Fresh)) {
				best, dst = c, m.ia
			}
		}
	}
	if best == nil {
		return excludedSample{}
	}
	echo := s.echoRTT(&scion.Addr{
		IA:   dst,
		Addr: netip.AddrPortFrom(entries[dst].ControlAddr.Addr(), dataplane.EndhostPort),
		Path: best.Path,
	})
	return excludedSample{survived: true, echo: echo}
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

// soleUp reports whether the peer names the tier's only up link.
func soleUp(t *tier, ia addr.IA) bool {
	for member := range t.up {
		if !member.Equal(ia) {
			return false
		}
	}
	return true
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
