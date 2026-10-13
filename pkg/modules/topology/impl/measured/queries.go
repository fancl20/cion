package measured

import (
	"time"

	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
)

// The comparator's queries over the enumerated candidates — the questions
// ADR-0017's loop asks of the path layer, answered beside the selection loop
// that owns them: the baseline echo's carrier, the route count into a tier,
// and the price of the cheapest route.

// freshest returns the freshest clean candidate of an enumeration: freshness
// picks the route the baseline echo measures, never a freshness value
// itself. Nil when no clean route resolves: the baseline stays unmeasured
// for the window rather than ride a route the network would not serve.
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
// it crosses no signaled interface — the wrapper's last resort, never the
// comparator's route — and no link the node's own verdicts mark down, the
// store and the verdicts naming the local interfaces and the candidate's
// Links naming what it traverses. A flagged candidate or one over the node's
// own dead interface is last-resort forwarding, not redundancy, and counting
// either would overcount routes — the one error that errs toward
// under-protection, where every accepted blind spot errs toward
// over-protection.
func (s *selection) clean(c *scion.Candidate) bool {
	if c.Crossing {
		return false
	}
	for _, link := range c.Links {
		if link.IA.Equal(s.cfg.IA) && !s.linkUp(link.IfID) {
			return false
		}
	}
	return true
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

// cheapest prices a set of routes by the cheapest of them: the routes the
// window probed by their echoes — the measured authority, an unanswered
// echo, a zero, pricing nothing — and every other route by its declared
// one-way sum, doubled to meet the round trips it is judged against. A
// route whose sum is unknown prices nothing: an undeclared edge is unknown,
// not free. Zero when nothing prices the set.
func cheapest(
	echoes []time.Duration,
	routes []*scion.Candidate,
	probed map[*scion.Candidate]bool,
) time.Duration {

	var price time.Duration
	consider := func(p time.Duration) {
		if p > 0 && (price == 0 || p < price) {
			price = p
		}
	}
	for _, echo := range echoes {
		consider(echo)
	}
	for _, c := range routes {
		if !probed[c] && c.Latency != nil {
			consider(2 * *c.Latency)
		}
	}
	return price
}
