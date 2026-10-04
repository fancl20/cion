package measured

import (
	"context"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
)

// The comparator's queries over the enumerated candidates — the questions
// ADR-0017's loop asks of the path layer, answered beside the selection loop
// that owns them: the baseline echo's carrier, the route count into a tier,
// the excluded baseline, and the promotion estimate's declared prices.

// freshest enumerates the composed routes to a peer — minus an excluded
// link, when one is given — and returns the freshest candidate: freshness
// picks the route the baseline echo measures, never a freshness value
// itself. Nil past an exclusion is the no-route-into-the-tier fact the
// retirement guard reads: the link is cut-critical and never retires,
// whatever its latency. Nil when no route resolves.
func (s *selection) freshest(
	ctx context.Context, ia addr.IA, exclude ...segment.LinkID,
) *scion.Candidate {

	candidates, err := s.cfg.Provider.Enumerate(ctx, ia, exclude...)
	if err != nil {
		return nil
	}
	var best *scion.Candidate
	for i := range candidates {
		if c := &candidates[i]; best == nil || c.Fresh.After(best.Fresh) {
			best = c
		}
	}
	return best
}

// routeCount counts the independent routes into a tier, saturating at two.
// The tier's up links count first, beside the composed candidates into its
// members that traverse none of them — either of a link's two interface IDs
// sufficing — and a second candidate counts only when edge-disjoint from
// the first, checked over all pairs, for a greedy first pick can miss the
// pair a different first would yield. Pairs are few and the miss direction
// is safe either way: undercount errs toward over-protection.
func routeCount(upLinks []segment.LinkID, candidates []scion.Candidate) int {
	count := min(len(upLinks), 2)
	if count == 2 {
		return 2
	}
	var avoiding []*scion.Candidate
	for i := range candidates {
		if !traverses(&candidates[i], upLinks) {
			avoiding = append(avoiding, &candidates[i])
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

// tierPrice prices the routes into a tier for the promotion estimate: the
// measured tier baseline the loop's echoes take — the authority wherever an
// echo exists — beside every composed route's declared one-way sum, doubled
// to meet the round trips it is judged against, each side pricing the same
// quantity. A route no edge of which declares its delay prices nothing: an
// undeclared edge is unknown, not free. Zero when nothing prices the tier.
func tierPrice(baseline time.Duration, candidates []scion.Candidate) time.Duration {
	price := baseline
	for i := range candidates {
		if candidates[i].Latency == nil {
			continue
		}
		declared := 2 * *candidates[i].Latency
		if price == 0 || declared < price {
			price = declared
		}
	}
	return price
}
