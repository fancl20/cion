package controlplane

import (
	"cmp"
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
)

// maxSetSize bounds a set: a receiver keeps at most storePerInterface
// candidates per interface, so more routes over one link would only evict
// one another.
const maxSetSize = storePerInterface

// route is a qualifying candidate with the facts its rank and the picks
// read.
type route struct {
	Candidate
	// key is the route's identity, the store's.
	key string
	// price is what the route costs, set when priced.
	price  time.Duration
	priced bool
	// links are the links the route crosses, each named by the interface an
	// entry leaves by, the last entry's being the link into the node.
	links []segment.LinkID
}

// rankRoutes returns the candidates in rank order: priced before unpriced,
// the lower price first, then the fewer entries, the newer origination, and
// the lower key and ingress.
func rankRoutes(cands []Candidate) []route {
	routes := make([]route, len(cands))
	for i, c := range cands {
		r := route{Candidate: c, key: routeOf(c.PCB)}
		r.price, r.priced = priceOf(c.PCB)
		for _, e := range c.PCB.Entries {
			r.links = append(r.links, segment.LinkID{IA: e.IA, IfID: e.Hop.ConsEgress})
		}
		routes[i] = r
	}
	slices.SortFunc(routes, func(a, b route) int {
		if a.priced != b.priced {
			if a.priced {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(a.price, b.price); c != 0 {
			return c
		}
		if c := cmp.Compare(len(a.PCB.Entries), len(b.PCB.Entries)); c != 0 {
			return c
		}
		if c := b.PCB.Timestamp().Compare(a.PCB.Timestamp()); c != 0 {
			return c
		}
		if c := cmp.Compare(a.key, b.key); c != 0 {
			return c
		}
		return cmp.Compare(a.Ingress, b.Ingress)
	})
	return routes
}

// priceOf returns what a route costs the node holding it, as the library
// prices paths: twice its declared one-way delay, plus twice
// scion.TransitPenalty for each AS between the node and the origin — every
// entry but the origin's. segment.EdgeDelay prices each edge between
// entries, and the edge into the node carries its sender's declaration
// alone; false when any edge is undeclared.
func priceOf(pcb *segment.PCB) (time.Duration, bool) {
	var oneWay time.Duration
	for i := range pcb.Entries {
		e := &pcb.Entries[i]
		var d time.Duration
		var declared bool
		if i+1 < len(pcb.Entries) {
			d, declared = segment.EdgeDelay(e, &pcb.Entries[i+1])
		} else {
			d, declared = e.Latency[segment.LinkID{IA: e.IA, IfID: e.Hop.ConsEgress}]
		}
		if !declared {
			return 0, false
		}
		oneWay += d
	}
	transits := time.Duration(len(pcb.Entries) - 1)
	return 2*oneWay + 2*scion.TransitPenalty*transits, true
}

// pickSet picks a set among the ranked routes: each origin's cheapest
// route, the founder's first; then, while some link is crossed by every
// route picked and an unpicked route avoids one such link, the cheapest such
// route; then, for each interface with routes of which none was picked, its
// cheapest route. The set keeps its first maxSetSize picks, in pick order.
func pickSet(ranked []route, founder addr.IA) []Candidate {
	picked := make([]bool, len(ranked))
	var picks []int
	pick := func(i int) {
		if len(picks) < maxSetSize {
			picked[i] = true
			picks = append(picks, i)
		}
	}

	if i := slices.IndexFunc(ranked, func(r route) bool {
		return r.PCB.FirstIA().Equal(founder)
	}); i >= 0 {
		pick(i)
	}
	origins := map[addr.IA]bool{founder: true}
	for i, r := range ranked {
		if origin := r.PCB.FirstIA(); !origins[origin] {
			origins[origin] = true
			pick(i)
		}
	}

	for len(picks) > 0 && len(picks) < maxSetSize {
		shared := make(map[segment.LinkID]bool)
		for _, l := range ranked[picks[0]].links {
			shared[l] = true
		}
		for _, p := range picks[1:] {
			for l := range shared {
				if !slices.Contains(ranked[p].links, l) {
					delete(shared, l)
				}
			}
		}
		// Every route picked crosses each shared link, so the cheapest route
		// avoiding one is unpicked.
		next := slices.IndexFunc(ranked, func(r route) bool {
			return avoidsOne(r.links, shared)
		})
		if next < 0 {
			break
		}
		pick(next)
	}

	covered := make(map[uint16]bool)
	for _, p := range picks {
		covered[ranked[p].Ingress] = true
	}
	for i, r := range ranked {
		if !covered[r.Ingress] {
			covered[r.Ingress] = true
			pick(i)
		}
	}

	set := make([]Candidate, len(picks))
	for k, i := range picks {
		set[k] = ranked[i].Candidate
	}
	return set
}

// avoidsOne reports whether a route crossing links avoids at least one of
// the shared links; false when there are none.
func avoidsOne(links []segment.LinkID, shared map[segment.LinkID]bool) bool {
	crossed := 0
	for _, l := range links {
		if shared[l] {
			crossed++
		}
	}
	return crossed < len(shared)
}
