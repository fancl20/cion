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
)

// A lease's pacing.
const (
	// LeaseEvaluation spaces a lease's evaluations: the reads within it share
	// the last one.
	LeaseEvaluation = time.Second
	// LeaseSwitchHold is how long a cheaper path must stay cheaper beyond the
	// band before a lease moves to it: a heartbeat of the ping application,
	// so a probe of each path speaks in between.
	LeaseSwitchHold = 5 * time.Second
	// LeaseExpiryMargin is how close to its hop fields' expiry a path no
	// longer serves: one that lapses within it is left before it fails.
	LeaseExpiryMargin = 30 * time.Second
	// leasesRequester names the leases' entries among the path requests.
	leasesRequester = "leases"
)

// held is a done context: a lookup given it serves the answers it holds and
// refreshes behind, never waiting.
var held = func() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}()

// Leased is the path a lease holds and its identity, empty for the
// bootstrap route.
type Leased struct {
	Path *spath.Decoded
	ID   bus.PathID
}

// Lease is the path every flow to one destination rides. It keeps its path
// while the path composes and is not ejected, moves at once when it is
// ejected, no longer composes, or nears its hop fields' expiry, and moves to
// a healthy path cheaper beyond the band once that path stayed so for
// LeaseSwitchHold. Its methods are safe for concurrent use.
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
	// challenger names the path cheaper beyond the band than the leased one,
	// and since is when it first was.
	challenger bus.PathID
	since      time.Time
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
// use when use is set.
func (l *Lease) get(use bool) (Leased, error) {
	now := time.Now()
	l.read.Store(now.UnixNano())
	l.mtx.Lock()
	defer l.mtx.Unlock()
	if use {
		l.used = now
	}
	if now.Sub(l.evaluated) >= LeaseEvaluation {
		if err := l.evaluate(now); err != nil {
			return Leased{}, err
		}
	}
	if l.cur == nil {
		return Leased{}, serrors.New("no path to destination", "isd_as", l.dst)
	}
	return Leased{Path: l.cur.Path, ID: l.cur.ID}, nil
}

// evaluate composes the destination's candidates and keeps, refreshes, or
// moves the leased path, the bootstrap route standing in while nothing
// composes. While the destination is in use, it updates the leases' requests
// for it. The caller holds l.mtx.
func (l *Lease) evaluate(now time.Time) error {
	l.evaluated = now
	v := l.p.view()
	candidates, err := l.p.enumerate(held, l.dst, v)
	if err != nil {
		return err
	}
	candidates = slices.DeleteFunc(candidates, func(c Candidate) bool {
		return PathExpiry(c.Path).Sub(v.now) < LeaseExpiryMargin
	})
	best := bestOf(candidates)
	if best == nil {
		l.cur, l.challenger = l.p.bootstrap(l.dst, v), ""
		return nil
	}
	cur := l.freshest(candidates)
	switch {
	case cur == nil || cur.Health == HealthEjected && best.Health != HealthEjected:
		l.cur, l.challenger = best, ""
	case best.ID != cur.ID && best.Health == HealthHealthy && cheaper(best, cur):
		if l.challenger != best.ID {
			l.challenger, l.since = best.ID, now
		}
		l.cur = cur
		if now.Sub(l.since) >= LeaseSwitchHold {
			l.cur, l.challenger = best, ""
		}
	default:
		l.cur, l.challenger = cur, ""
	}
	if !l.used.IsZero() && now.Sub(l.used) < bus.RequestLapse {
		l.p.request(leasesRequester, l.dst, l.cur, l.used, candidates, v)
	}
	return nil
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

// cheaper reports whether a costs less than b beyond the band.
func cheaper(a, b *Candidate) bool {
	return a.Cost != nil && b.Cost != nil && *a.Cost < *b.Cost && beyondBand(*a.Cost, *b.Cost)
}
