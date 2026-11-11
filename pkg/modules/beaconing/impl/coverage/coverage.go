// Package coverage is the coverage method of the beacon policy module. A
// set holds each origin's cheapest route, the founding core's first; then,
// while some link is crossed by every route picked and another route avoids
// one such link, the cheapest such route; then the cheapest route over each
// interface no picked route arrived over; then, for a receiver in the
// node's group, the cheapest route over each link into the group at another
// member that no picked route entered by. Routes rank by price, as the SCION
// library prices paths.
package coverage

import (
	"cmp"
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/beaconing"
)

// Policy is the coverage method.
type Policy struct {
	ia   addr.IA
	tags *bus.Topic[bus.NodeTags]
}

var _ beaconing.Policy = (*Policy)(nil)

// New returns the coverage method of the node ia, whose group the last event
// on tags names; a nil topic names none.
func New(ia addr.IA, tags *bus.Topic[bus.NodeTags]) *Policy {
	return &Policy{ia: ia, tags: tags}
}

// Select picks the receiver's set among cands. The routes into the node's
// group count for a receiver in the group, the node itself among them.
func (p *Policy) Select(
	receiver, founder addr.IA, cands []beaconing.Candidate) []beaconing.Candidate {

	members := groupOf(p.tags.Latest(), p.ia)
	var into group
	if members.has(receiver) {
		into = members
	}
	return pickSet(rankRoutes(cands), founder, into)
}

// route is a candidate with the facts its rank and the picks read.
type route struct {
	beaconing.Candidate
	// key is the route's identity, the beacon store's.
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
func rankRoutes(cands []beaconing.Candidate) []route {
	routes := make([]route, len(cands))
	for i, c := range cands {
		r := route{Candidate: c, key: c.PCB.RouteKey()}
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

// group is the node's group as the node tags name it: the nodes whose group
// tag is the node's own. The zero group holds no node.
type group struct {
	tags bus.NodeTags
	name string
}

// groupOf returns the node's group in the tags: none while the node carries
// no group tag.
func groupOf(tags bus.NodeTags, ia addr.IA) group {
	return group{tags: tags, name: tags.Tag(ia, bus.TagGroup)}
}

// has reports whether the node is one of the group's.
func (g group) has(ia addr.IA) bool {
	return g.name != "" && g.tags.Tag(ia, bus.TagGroup) == g.name
}

// entry returns the link over which the route entered the node's group at
// another member: the link out of its last entry outside the group. False
// when that entry is the route's last, so the route entered over the node's
// own link, and when every entry lies inside.
func (r route) entry(g group) (segment.LinkID, bool) {
	last := len(r.PCB.Entries) - 1
	for i := last; i >= 0; i-- {
		if !g.has(r.PCB.Entries[i].IA) {
			return r.links[i], i < last
		}
	}
	return segment.LinkID{}, false
}

// pickSet picks a set among the ranked routes, in pick order: each origin's
// cheapest route, the founder's first; then, while some link is crossed by
// every route picked and an unpicked route avoids one such link, the
// cheapest such route; then, for each interface with routes of which none
// was picked, its cheapest route; then, for each link into the node's group
// at another member with routes of which none was picked, its cheapest
// route.
func pickSet(ranked []route, founder addr.IA, g group) []beaconing.Candidate {
	var picks []int
	if i := slices.IndexFunc(ranked, func(r route) bool {
		return r.PCB.FirstIA().Equal(founder)
	}); i >= 0 {
		picks = append(picks, i)
	}
	origins := map[addr.IA]bool{founder: true}
	for i, r := range ranked {
		if origin := r.PCB.FirstIA(); !origins[origin] {
			origins[origin] = true
			picks = append(picks, i)
		}
	}

	for len(picks) > 0 {
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
		// avoiding one is unpicked, and each pick shrinks the shared links.
		next := slices.IndexFunc(ranked, func(r route) bool {
			return avoidsOne(r.links, shared)
		})
		if next < 0 {
			break
		}
		picks = append(picks, next)
	}

	covered := make(map[uint16]bool)
	for _, p := range picks {
		covered[ranked[p].Ingress] = true
	}
	for i, r := range ranked {
		if !covered[r.Ingress] {
			covered[r.Ingress] = true
			picks = append(picks, i)
		}
	}

	entered := make(map[segment.LinkID]bool)
	for _, p := range picks {
		if l, ok := ranked[p].entry(g); ok {
			entered[l] = true
		}
	}
	for i, r := range ranked {
		if l, ok := r.entry(g); ok && !entered[l] {
			entered[l] = true
			picks = append(picks, i)
		}
	}

	set := make([]beaconing.Candidate, len(picks))
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
