package scion

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// A lease's pacing.
const (
	// LeaseEvaluation spaces a lease's evaluations: the reads within it share
	// the last one.
	LeaseEvaluation = time.Second
	// LeaseSwitchHold is how long a lease's verdict that a cheaper path beats
	// its own must stand, a probe of each path answered meanwhile, before the
	// lease moves: a heartbeat of the ping application, so that a probe of
	// each path speaks in between.
	LeaseSwitchHold = 5 * time.Second
	// LeaseExpiryMargin is how close to its hop fields' expiry a path no
	// longer serves: one that lapses within it is left before it fails.
	LeaseExpiryMargin = 30 * time.Second
	// leasesRequester names the leases' entries among the path requests.
	leasesRequester = "leases"
)

// LeaseMoved is the change a lease's records name.
const LeaseMoved = "Lease moved"

// The reasons a lease's record gives for a change of its path.
const (
	whyFirst     = "the first read"
	whyCheaper   = "a cheaper path, confident beyond the band"
	whyIdle      = "a cheaper path, taken at once by an idle lease"
	whyEjected   = "the leased path was ejected"
	whyExpiring  = "the leased path nears its hop fields' expiry"
	whyGone      = "the leased path no longer composes"
	whyBootstrap = "no path composes, so the bootstrap route stands in"
	whyComposes  = "a path composes where the bootstrap route stood"
)

// held is a done context: a lookup given it serves the answers it holds and
// refreshes behind, never waiting.
var held = func() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}()

// Leased is the path a lease holds, its identity, and the stored segments
// it joins; the identity and the segments are empty for the bootstrap route.
type Leased struct {
	Path     *spath.Decoded
	ID       bus.PathID
	Segments []*pathdb.Segment
}

// Lease is the path every flow to one destination rides. It keeps its path
// while the path composes and is not ejected, moves at once when it is
// ejected, no longer composes, or nears its hop fields' expiry, and moves to
// a healthy path cheaper beyond the band once confident of it: the bounds of
// the two paths' prices part by the band, and that verdict stands for
// LeaseSwitchHold across a probe of each path. An idle lease, one no caller
// used for bus.RequestLapse, takes such a path at once. Each change of its
// path appends a record to the provider's journal of changes. Its methods
// are safe for concurrent use.
type Lease struct {
	p   *PathProvider
	dst addr.IA
	// read is when any caller last read the lease, in Unix nanoseconds: the
	// provider's sweep reads it without the lease's lock.
	read atomic.Int64

	mtx sync.Mutex
	// cur is the leased path's candidate, nil while nothing composes.
	cur *Candidate
	// evaluated is when the lease last evaluated.
	evaluated time.Time
	// used is when a caller last read the lease for payload.
	used time.Time
	// hold holds the verdict that a cheaper path beats the leased one.
	hold evidence.Hold
}

// Lease returns the destination's lease, the one every caller shares. Once a
// RequestLapse, it drops the leases nothing read for as long.
func (p *PathProvider) Lease(dst addr.IA) *Lease {
	now := time.Now()
	p.mtx.Lock()
	defer p.mtx.Unlock()
	if p.leases == nil {
		p.leases = make(map[addr.IA]*Lease)
	}
	if now.Sub(p.swept) >= bus.RequestLapse {
		p.swept = now
		for ia, l := range p.leases {
			if now.Sub(time.Unix(0, l.read.Load())) >= bus.RequestLapse {
				delete(p.leases, ia)
			}
		}
	}
	l, ok := p.leases[dst]
	if !ok {
		l = &Lease{p: p, dst: dst}
		l.read.Store(now.UnixNano())
		p.leases[dst] = l
	}
	return l
}

// Path returns the leased path, evaluating the lease when an evaluation is
// due, from local state and the lookups' held answers alone: it never waits,
// so a send or a dial may read it. The read counts as a use of the
// destination.
func (l *Lease) Path() (Leased, error) {
	return l.get(true)
}

// Peek returns the leased path as Path does, but counts as no use: the read
// of a send that carries no payload.
func (l *Lease) Peek() (Leased, error) {
	return l.get(false)
}

// Await returns the leased path as Path does, waiting on the destination's
// lookup while nothing composes, as ctx allows.
func (l *Lease) Await(ctx context.Context) (Leased, error) {
	if leased, err := l.Path(); err == nil {
		return leased, nil
	}
	if l.p.Lookup != nil {
		l.p.Lookup(ctx, l.dst)
	}
	l.mtx.Lock()
	l.evaluated = time.Time{}
	l.mtx.Unlock()
	return l.Path()
}

// Delivered records that a caller's traffic over the path delivered: an
// exchange completed, or a refusal answered it.
func (l *Lease) Delivered(id bus.PathID) {
	l.p.record(id, true, time.Now())
}

// Lost records that a caller's traffic over the path went unanswered.
func (l *Lease) Lost(id bus.PathID) {
	l.p.record(id, false, time.Now())
}

// get reads the lease, evaluating it when an evaluation is due, and counts a
// use when use is set. The lease is idle for the evaluation when no caller
// used it for bus.RequestLapse before the read.
func (l *Lease) get(use bool) (Leased, error) {
	now := time.Now()
	l.read.Store(now.UnixNano())
	l.mtx.Lock()
	defer l.mtx.Unlock()
	idle := now.Sub(l.used) >= bus.RequestLapse
	if use {
		l.used = now
	}
	if now.Sub(l.evaluated) >= LeaseEvaluation {
		if err := l.evaluate(now, idle); err != nil {
			return Leased{}, err
		}
	}
	if l.cur == nil {
		return Leased{}, serrors.New("no path to destination", "isd_as", l.dst)
	}
	return Leased{Path: l.cur.Path, ID: l.cur.ID, Segments: l.cur.Segments}, nil
}

// evaluate composes the destination's candidates and keeps, refreshes, or
// moves the leased path, the bootstrap route standing in while nothing
// composes, and records each change of the path; idle reports the lease
// idle. While the destination is in use, it updates the leases' requests for
// it. The caller holds l.mtx.
func (l *Lease) evaluate(now time.Time, idle bool) error {
	l.evaluated = now
	v := l.p.view()
	candidates, err := l.p.enumerate(held, l.dst, v)
	if err != nil {
		return err
	}
	prev := l.cur
	expiring := false
	candidates = slices.DeleteFunc(candidates, func(c Candidate) bool {
		late := PathExpiry(c.Path).Sub(v.now) < LeaseExpiryMargin
		expiring = expiring || late && prev != nil && prev.ID != "" && c.ID == prev.ID
		return late
	})
	best := bestOf(candidates)
	if best == nil {
		l.cur = l.p.bootstrap(l.dst, v)
		l.hold.Release()
		l.record(prev, whyBootstrap, 0, nil, now)
		return nil
	}
	cur := l.freshest(candidates)
	switch {
	case cur == nil:
		l.cur = best
		l.hold.Release()
		why := whyGone
		switch {
		case prev == nil:
			why = whyFirst
		case prev.ID == "":
			why = whyComposes
		case expiring:
			why = whyExpiring
		}
		l.record(prev, why, 0, nil, now)
	case cur.Health == HealthEjected && best.Health != HealthEjected:
		l.cur = best
		l.hold.Release()
		l.record(prev, whyEjected, 0, nil, now)
	case best.ID != cur.ID && best.Health == HealthHealthy && cheaper(best, cur):
		l.cur = cur
		price, own := best.PriceEstimate(), cur.PriceEstimate()
		pa, _ := best.Price()
		pb, _ := cur.Price()
		line := Band(pa, pb)
		// No flow rides an idle lease to pay for a wrong move, and its
		// lapsed requests left its path unprobed: it moves at once. A lease
		// in use moves once the evidence decides and the verdict stands.
		why := whyIdle
		if !idle {
			if evidence.Beats(price, own, line) != evidence.Better {
				l.hold.Release()
				break
			}
			if !l.hold.Stands(string(best.ID), price, own, LeaseSwitchHold, now) {
				break
			}
			why = whyCheaper
		}
		l.cur = best
		l.hold.Release()
		weighed := []evidence.Weighed{{Name: "from", Estimate: own}, {Name: "to", Estimate: price}}
		l.record(prev, why, line, weighed, now)
	default:
		l.cur = cur
		l.hold.Release()
	}
	if !l.used.IsZero() && now.Sub(l.used) < bus.RequestLapse {
		l.p.request(leasesRequester, l.dst, l.cur, l.used, candidates, v)
	}
	return nil
}

// record appends to the provider's journal of changes the record of the
// lease's move from prev to its path, why, the line, and the estimates it
// weighed; nothing when its path is prev's.
func (l *Lease) record(prev *Candidate, why string, line time.Duration, weighed []evidence.Weighed, now time.Time) {
	from, to := leaseName(prev), leaseName(l.cur)
	if l.p.Changes == nil || from == to {
		return
	}
	l.p.Changes.Append(evidence.Record{At: now, Change: LeaseMoved, Subject: l.dst.String(), From: from, To: to,
		Why: why, Line: line, Weighed: weighed})
}

// leaseName names a leased path in a record: its identity, the bootstrap
// route, or nothing for none.
func leaseName(c *Candidate) string {
	switch {
	case c == nil:
		return ""
	case c.ID == "":
		return "the bootstrap route"
	default:
		return string(c.ID)
	}
}

// freshest returns the freshest composition of the leased path among the
// candidates, nil when none composes it.
func (l *Lease) freshest(candidates []Candidate) *Candidate {
	if l.cur == nil || l.cur.ID == "" {
		return nil
	}
	var out *Candidate
	for i := range candidates {
		if c := &candidates[i]; c.ID == l.cur.ID && (out == nil || c.Before(out)) {
			out = c
		}
	}
	return out
}

// cheaper reports whether a's price beats b's beyond the band.
func cheaper(a, b *Candidate) bool {
	pa, aPriced := a.Price()
	pb, bPriced := b.Price()
	return aPriced && bPriced && pa < pb && BeyondBand(pa, pb)
}
