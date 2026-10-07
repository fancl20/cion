package wireguard

import (
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
)

// The route pick's hysteresis, code constants per ADR-0017's decision 17 — the
// selection loop's promotion shape scaled to route choice. Two near-equal
// routes trade the lead back and forth as their declared sums move, and every
// trade costs in-flight datagrams their place in line: one ratio a challenger
// must beat, one streak of consecutive windows naming the same challenger.
const (
	// SwitchRatio is the fraction of the incumbent's declared sum a
	// challenger must beat — a challenger a fifth faster.
	SwitchRatio = 0.8
	// SwitchWindows is the consecutive windows the same challenger must
	// lead before the switch lands.
	SwitchWindows = 2
)

// routeChoice is the socket's route state for one peer, beside the send cache:
// the incumbent route's identity and the challenger streak. A route's identity
// is its link set — the (ISD-AS, interface ID) pairs the candidates carry —
// stable across the recompositions of the same stretch where timestamps and
// hop MACs are not. No latency is stored: the incumbent matched among a
// window's candidates carries the route's current declaration.
type routeChoice struct {
	// incumbent names the landed route by its links; nil when no route has
	// landed.
	incumbent []segment.LinkID
	// challenger names the streak's challenger by its links; nil while no
	// streak builds.
	challenger []segment.LinkID
	// streak is the consecutive windows the named challenger has led.
	streak int
}

// pickRoute is the warm loop's pick over one window's candidates: the rank,
// the pools, and the switch's reluctance, pure over its inputs. The
// candidates divide into a clean pool and a crossing one — the flagged last
// resort Path honors — and the pick considers the clean pool, falling back to
// the crossing one only when nothing clean composes. Within the pool a
// declared sum outranks an undeclared one and a smaller declared sum a
// larger, ties and undeclared pairs falling to the path layer's rank. An
// incumbent the pool no longer holds — its route gone, or demoted to the
// crossing pool while clean candidates stand — is a failure, and the pool's
// best replaces it at once. A surviving incumbent switches reluctantly: the
// challenger must beat its declared sum by SwitchRatio, and a window where a
// different candidate leads, where the leader falls back inside the ratio, or
// where a declaration lapses resets the count. The declaration gaps govern
// where no ratio applies: an incumbent without a declared sum yields to a
// declared challenger through the streak alone, and neither declaring is
// today's case — the default rank picks, immediately. It answers the pick —
// nil when nothing composes — the next choice, and whether the pick replaced
// an incumbent.
func pickRoute(candidates []scion.Candidate, choice routeChoice) (pick *scion.Candidate, next routeChoice, switched bool) {
	var pool []*scion.Candidate
	for i := range candidates {
		if !candidates[i].Crossing {
			pool = append(pool, &candidates[i])
		}
	}
	if len(pool) == 0 {
		// Nothing clean composes: the crossing pool is the last resort.
		for i := range candidates {
			pool = append(pool, &candidates[i])
		}
	}
	if len(pool) == 0 {
		return nil, choice, false
	}
	best := pool[0]
	for _, c := range pool[1:] {
		if outranks(c, best) {
			best = c
		}
	}
	if choice.incumbent == nil {
		return best, routeChoice{incumbent: best.Links}, false
	}
	var matched *scion.Candidate
	for _, c := range pool {
		if slices.Equal(c.Links, choice.incumbent) {
			matched = c
			break
		}
	}
	if matched == nil {
		// The window can no longer compose the incumbent's route clean: the
		// failure semantics, the best candidate at once.
		return best, routeChoice{incumbent: best.Links}, true
	}
	if slices.Equal(best.Links, matched.Links) {
		// The incumbent keeps the lead, and whatever was building against it
		// resets.
		return matched, routeChoice{incumbent: matched.Links}, false
	}
	switch {
	case matched.Latency == nil && best.Latency == nil:
		// Neither side declares: the default rank picks, immediately — the
		// hops-first order a non-declaring network has always had.
		return best, routeChoice{incumbent: best.Links}, true
	case best.Latency == nil:
		// Knowledge is not traded for ignorance: a challenger without a
		// declared sum never displaces a declared incumbent — the rank's
		// declared-first order usually keeps it from leading at all — and
		// the streak against it resets.
		return matched, routeChoice{incumbent: matched.Links}, false
	case matched.Latency != nil && *best.Latency >= ratioOf(*matched.Latency, SwitchRatio):
		// The leader fell back inside the ratio: the streak resets.
		return matched, routeChoice{incumbent: matched.Links}, false
	}
	streak := 1
	if slices.Equal(choice.challenger, best.Links) {
		streak = choice.streak + 1
	}
	if streak >= SwitchWindows {
		return best, routeChoice{incumbent: best.Links}, true
	}
	// The challenger's lead is sustained so far; the incumbent serves while
	// the streak builds.
	return matched, routeChoice{
		incumbent:  matched.Links,
		challenger: best.Links,
		streak:     streak,
	}, false
}

// outranks reports whether c outranks o by the pick's rank: a declared sum
// outranks an undeclared one — unknown is not free — a smaller declared sum a
// larger, and ties and undeclared pairs the path layer's own rank, so the
// order a non-declaring network sees is the order it sees today.
func outranks(c, o *scion.Candidate) bool {
	if c.Latency != nil && o.Latency == nil {
		return true
	}
	if c.Latency == nil && o.Latency != nil {
		return false
	}
	if c.Latency != nil && *c.Latency != *o.Latency {
		return *c.Latency < *o.Latency
	}
	return c.Before(o)
}

// ratioOf scales a duration by one of the pick's ratios.
func ratioOf(d time.Duration, r float64) time.Duration {
	return time.Duration(r * float64(d))
}

// landRoute is the warm loop's landing: one critical section that reads the
// peer's route choice, decides over the window's candidates, and writes the
// pick's path, hop expiry, and route state. A pick that keeps the route still
// refreshes the cache — a recomposition of the same stretch carries fresher
// hop expiry — and a pick that replaces an incumbent counts route_switches.
// It answers the pick and whether a switch landed.
func (s *meshSocket) landRoute(ia addr.IA, candidates []scion.Candidate) (*scion.Candidate, bool) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	pick, next, switched := pickRoute(candidates, s.routes[ia])
	if pick == nil {
		return nil, false
	}
	s.paths[ia] = pick.Path
	s.expiry[ia] = scion.PathExpiry(pick.Path)
	s.routes[ia] = next
	if switched {
		s.cnt.routeSwitches.Add(1)
	}
	return pick, switched
}
