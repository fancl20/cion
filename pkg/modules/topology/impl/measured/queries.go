package measured

import (
	"slices"
	"time"

	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
)

// The comparator's queries over the enumerated candidates, answered beside
// the selection loop that owns them: the baseline, the route count into a
// tier, and the price of the cheapest route.

// freshest returns the freshest clean candidate of an enumeration: the
// peer's baseline, the route the window requests priced for it. Freshness
// picks the route, never a freshness value itself. Nil when no clean route
// resolves.
func (s *selection) freshest(candidates []scion.Candidate) *scion.Candidate {
	var best *scion.Candidate
	for i := range candidates {
		if c := &candidates[i]; s.clean(c) && (best == nil || c.Fresh.After(best.Fresh)) {
			best = c
		}
	}
	return best
}

// clean reports whether the candidate is a route the comparator may count:
// not ejected, crossing no signaled interface — the wrapper's last resort,
// never the comparator's route — and over none of the node's down links. A
// dead route, a flagged one, or one over the node's own dead interface is no
// redundancy, and counting it would overcount routes — the one error that
// errs toward under-protection, where every accepted blind spot errs toward
// over-protection. A suspect route counts: what it lacks is evidence, and
// the window's request of it, its baseline or a survivor, decides it.
func (s *selection) clean(c *scion.Candidate) bool {
	return c.Health != scion.HealthEjected && !c.Crossing && !s.overDownLink(c)
}

// overDownLink reports whether the candidate leaves through a link the
// node's own verdicts mark down: the store and the verdicts name the local
// interfaces, and the candidate's Links name what it traverses.
func (s *selection) overDownLink(c *scion.Candidate) bool {
	return slices.ContainsFunc(c.Links, func(link segment.LinkID) bool {
		return link.IA.Equal(s.cfg.IA) && !s.linkUp(link.IfID)
	})
}

// routeCount counts the independent routes into a tier, saturating at two.
// The tier's up links count first, beside the composed candidates into its
// members that traverse none of them — either of a link's two interface IDs
// sufficing — and a second candidate counts only when edge-disjoint from
// the first, checked over all pairs, for a greedy first pick can miss the
// pair a different first would yield. Pairs are few and the miss direction
// is safe either way: undercount errs toward over-protection.
func routeCount(upLinks []segment.LinkID, candidates []*scion.Candidate) int {
	count := min(len(upLinks), 2)
	if count == 2 {
		return 2
	}
	var avoiding []*scion.Candidate
	for _, c := range candidates {
		if !traverses(c, upLinks) {
			avoiding = append(avoiding, c)
		}
	}
	if len(avoiding) == 0 {
		return count
	}
	count++
	if count == 2 {
		return 2
	}
	for i := range avoiding {
		for j := i + 1; j < len(avoiding); j++ {
			if edgeDisjoint(avoiding[i], avoiding[j]) {
				return 2
			}
		}
	}
	return 1
}

// traverses reports whether the candidate's traversed stretch names any of
// the links.
func traverses(c *scion.Candidate, links []segment.LinkID) bool {
	named := make(map[segment.LinkID]bool, len(links))
	for _, link := range links {
		named[link] = true
	}
	for _, link := range c.Links {
		if named[link] {
			return true
		}
	}
	return false
}

// edgeDisjoint reports whether two candidates share no link.
func edgeDisjoint(a, b *scion.Candidate) bool {
	links := make(map[segment.LinkID]bool, len(a.Links))
	for _, link := range a.Links {
		links[link] = true
	}
	for _, link := range b.Links {
		if links[link] {
			return false
		}
	}
	return true
}

// cheapest prices a set of routes by the cheapest of them, each at its cost:
// the measured round trip raised by loss, else its declared one-way sum
// doubled to meet the round trips it is judged against. A route with
// neither prices nothing: an undeclared edge is unknown, not free. Zero when
// nothing prices the set.
func cheapest(routes []*scion.Candidate) time.Duration {
	var price time.Duration
	for _, c := range routes {
		if c.Cost != nil {
			price = lower(price, *c.Cost)
		}
	}
	return price
}
