// Package ping is CION's SCMP-echo application, the network's probe: its
// resident prober measures the paths the node's picks and leases ask it to,
// and publishes their records on the node bus. The echo mechanics it rides,
// and the client behind `cion ping`, are the ping library's; the responder
// that answers is the node's own, part of the core.
package ping

import (
	"cmp"
	"context"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/loops"
	pinglib "github.com/fancl20/cion/pkg/libs/ping"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
)

// The prober's pacing. A destination is hot for HotWindow after its last
// pick, use, or pricing: its path in use and the path its lease weighs are
// probed every Heartbeat, its priced routes every RouteProbe, and its
// standby and its suspect every SlowProbe, each first at once. Until its
// requests lapse, its path in use and the path its lease weighs are probed
// every SlowProbe, its other paths not at all. A caller's confirmation of a
// path counts as its routine probe.
// A lost probe of a path in use, weighed, priced, or suspect, and a caller's
// doubt newer than a path's last answer, call a burst, which decides the
// path: an answer keeps or clears it, a burst lost whole ejects it.
const (
	// Heartbeat bounds how long a silent failure of a path in use goes
	// unseen, a burst's second beside it.
	Heartbeat = 5 * time.Second
	// RouteProbe spaces the probes of a priced route: a requester that
	// prices its routes each half minute reads a probe from within its last
	// pricing.
	RouteProbe = 30 * time.Second
	// SlowProbe matches the cadence at which registrations and lookups
	// refresh the segments the candidates are composed from.
	SlowProbe = time.Minute
	// HotWindow is how long after its last pick, use, or pricing a
	// destination is hot.
	HotWindow = time.Minute
	// BurstProbes and BurstSpacing shape a burst: five probes over a second.
	BurstProbes  = 5
	BurstSpacing = 200 * time.Millisecond
	// ProbeWait is how long a probe waits for its answer.
	ProbeWait = time.Second
	// Budget is the probes a second the prober sends at most, node-wide.
	Budget = 20
	// resolveRetry spaces the retries of a failed resolution.
	resolveRetry = 5 * time.Second
)

// Echoer sends the prober's echo requests and delivers the replies to them.
type Echoer interface {
	// Send sends an echo request to the host in dst over the path.
	Send(dst addr.IA, host netip.Addr, path *spath.Decoded, seq uint16) error
	// Replies delivers each reply to one of the prober's own requests.
	Replies() <-chan pinglib.Reply
	// ReadReplies reads the replies until ctx ends.
	ReadReplies(ctx context.Context) error
}

// ProberConfig configures a prober.
type ProberConfig struct {
	// Requests is the topic of the paths to measure.
	Requests *bus.Topic[bus.PathRequests]
	// Measurements is the topic the paths' records are published on.
	Measurements *bus.Topic[bus.PathMeasurements]
	// InterfaceDown is the topic whose signals call bursts.
	InterfaceDown *bus.Topic[bus.InterfaceDownState]
	// Echo sends the probes and delivers their replies.
	Echo Echoer
	// Resolve resolves each destination's responder host.
	Resolve pinglib.Resolver
	// Answer hands dst's rate the reply to a probe of its path in use:
	// whether it came back marked, and when the probe was sent.
	Answer func(dst addr.IA, marked bool, sent time.Time)
}

// Prober is the resident ping application: it probes the paths the node's
// requesters ask it to, by SCMP echo to each destination's responder, and
// publishes each path's record. One loop owns its state; the replies and the
// resolutions reach it from loops of their own.
type Prober struct {
	cfg     ProberConfig
	closers []func() error
	close   sync.Once

	paths    map[bus.PathID]*probed
	pending  *pinglib.Pending[probe]
	hosts    *pinglib.Hosts
	signaled map[segment.LinkID]time.Time
	tokens   float64
	refilled time.Time
	changed  bool
}

// probed is one path the prober measures: its latest request, its record,
// and its pacing.
type probed struct {
	req bus.PathRequest
	// requested reports whether the latest requests name the path; a path
	// they no longer name keeps its record until its last pick lapses.
	requested bool
	record    bus.PathRecord
	// lastProbe is when the path's last routine probe went.
	lastProbe time.Time
	// confirmed is when a caller's traffic last confirmed the path, which
	// stands in for a routine probe; doubted is the latest caller's doubt the
	// prober saw.
	confirmed, doubted time.Time
	// burstLeft counts the probes of the path's burst still to send, the
	// next due at burstNext; burstOut counts those sent and unsettled; and
	// burstHit reports whether one of them answered.
	burstLeft int
	burstNext time.Time
	burstOut  int
	burstHit  bool
	// halfOpened is the due time of the half-open burst already sent.
	halfOpened time.Time
}

// routineAfter returns when the path's last routine probe went, or a caller
// confirmed it in its stead, whichever came later.
func (ps *probed) routineAfter() time.Time {
	if ps.confirmed.After(ps.lastProbe) {
		return ps.confirmed
	}
	return ps.lastProbe
}

// probe is one probe awaiting its answer.
type probe struct {
	id    bus.PathID
	dst   addr.IA
	burst bool
	// confirm reports whether the path was in use, weighed, priced, or
	// suspect when the probe went: its routine probe's loss calls a burst.
	confirm bool
	// inUse reports whether the path was in use when the probe went: its
	// reply goes to the destination's rate.
	inUse bool
}

// NewProber returns a prober over the configured topics, echoes, and
// resolutions.
func NewProber(cfg ProberConfig) *Prober {
	return &Prober{
		cfg:      cfg,
		paths:    make(map[bus.PathID]*probed),
		pending:  pinglib.NewPending[probe](ProbeWait),
		hosts:    pinglib.NewHosts(cfg.Resolve, resolveRetry),
		signaled: make(map[segment.LinkID]time.Time),
		tokens:   Budget,
	}
}

// ResidentConfig configures the resident prober over the node's bus and
// conns.
type ResidentConfig struct {
	// Bus is the node's bus.
	Bus *bus.Bus
	// NewConn binds a SCION conn of the node's.
	NewConn func() (*scion.Conn, error)
}

// NewResident binds the prober's two conns, one its echoes ride and one its
// resolutions read alone, and returns the prober over the node's bus. The
// replies to the probes of paths in use go to the echo conn's ECN state.
func NewResident(cfg ResidentConfig) (*Prober, error) {
	echoConn, err := cfg.NewConn()
	if err != nil {
		return nil, err
	}
	resolutionConn, err := cfg.NewConn()
	if err != nil {
		_ = echoConn.Close()
		return nil, err
	}
	p := NewProber(ProberConfig{
		Requests:      cfg.Bus.PathRequests(),
		Measurements:  cfg.Bus.PathMeasurements(),
		InterfaceDown: cfg.Bus.InterfaceDown(),
		Echo:          pinglib.NewConn(echoConn),
		Resolve: func(ctx context.Context, dst addr.IA, path *spath.Decoded) (netip.Addr, error) {
			return pinglib.Resolve(ctx, resolutionConn, dst, path)
		},
		Answer: echoConn.Answer,
	})
	p.closers = []func() error{echoConn.Close, resolutionConn.Close}
	return p, nil
}

// Run probes until ctx ends, then returns nil.
func (p *Prober) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	loops.Go(ctx, &wg, "ping replies", p.readReplies)
	loops.Go(ctx, &wg, "ping resolutions", p.hosts.Resolve)
	loops.Go(ctx, &wg, "ping probes", p.probe)
	<-ctx.Done()
	wg.Wait()
	return nil
}

// Close releases the prober's conns.
func (p *Prober) Close() {
	p.close.Do(func() {
		for _, c := range p.closers {
			_ = c()
		}
	})
}

// readReplies reads the probes' replies until ctx ends or the read fails.
func (p *Prober) readReplies(ctx context.Context) {
	if err := p.cfg.Echo.ReadReplies(ctx); err != nil {
		slog.Warn("Reading the prober's echoes", "err", err)
	}
}

// probe is the loop that owns the prober's state: it takes the requests, the
// signals, the replies, and the resolutions as they come, settles the probes
// whose wait ran out, sends the probes due within the budget, and publishes
// the records that changed.
func (p *Prober) probe(ctx context.Context) {
	requests := p.cfg.Requests.Subscribe(ctx)
	signals := p.cfg.InterfaceDown.Subscribe(ctx)
	timer := time.NewTimer(0)
	defer timer.Stop()
	p.refilled = time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case rs := <-requests:
			p.take(rs, time.Now())
		case s := <-signals:
			p.signal(s, time.Now())
		case r := <-p.cfg.Echo.Replies():
			p.answer(r)
		case r := <-p.hosts.Landed():
			p.resolution(r, time.Now())
		case <-timer.C:
		}
		now := time.Now()
		p.expire(now)
		wait := p.dispatch(now)
		p.publish()
		timer.Reset(wait)
	}
}

// take adopts the latest requests: a path two entries name keeps the most
// demanding role, in the roles' order, the latest pick, and the latest
// confirmation. A caller's doubt newer than the last one seen calls a burst
// for its path, unless the path answered since. A path its last pick lapsed
// for is forgotten.
func (p *Prober) take(rs bus.PathRequests, now time.Time) {
	for _, ps := range p.paths {
		ps.requested = false
	}
	for r := range rs.All() {
		if now.Sub(r.Picked) >= bus.RequestLapse {
			continue
		}
		ps := p.paths[r.ID]
		if ps == nil {
			ps = &probed{record: bus.PathRecord{Dst: r.Dst, Links: r.Links}}
			p.paths[r.ID] = ps
			p.changed = true
		}
		if !ps.requested || r.Role < ps.req.Role || r.Role == ps.req.Role && r.Picked.After(ps.req.Picked) {
			ps.req = r
		}
		ps.requested = true
		if r.Confirmed.After(ps.confirmed) {
			ps.confirmed = r.Confirmed
		}
		if r.Doubted.After(ps.doubted) {
			ps.doubted = r.Doubted
			if r.Doubted.After(ps.record.LastAnswer) {
				p.startBurst(ps, now)
			}
		}
	}
	p.forget(now)
}

// forget drops each path its last pick lapsed for.
func (p *Prober) forget(now time.Time) {
	for id, ps := range p.paths {
		if now.Sub(ps.req.Picked) >= bus.RequestLapse {
			delete(p.paths, id)
			p.changed = true
		}
	}
}

// signal calls a burst for each requested path crossing a link whose
// standing signal arrived after the last one the prober saw on it.
func (p *Prober) signal(s bus.InterfaceDownState, now time.Time) {
	seen := make(map[segment.LinkID]time.Time)
	for _, ps := range p.paths {
		if !ps.requested {
			continue
		}
		for _, l := range ps.req.Links {
			at, ok := s.Arrived(l, now)
			if !ok {
				continue
			}
			seen[l] = at
			if at.After(p.signaled[l]) {
				p.startBurst(ps, now)
			}
		}
	}
	maps.Copy(p.signaled, seen)
}

// answer settles the probe a reply answers, and hands the reply to the
// destination's rate where the path was in use; a reply after the probe's
// wait settles nothing, the probe already lost.
func (p *Prober) answer(r pinglib.Reply) {
	s, ok := p.pending.Answered(r)
	if !ok {
		return
	}
	if ps := p.paths[s.Value.id]; ps != nil {
		p.settle(ps, s.Value, s.Sample, r.At)
	}
	if s.Value.inUse {
		p.cfg.Answer(s.Value.dst, r.Marked, s.Sample.At)
	}
}

// expire settles each probe whose wait ran out as lost.
func (p *Prober) expire(now time.Time) {
	for _, s := range p.pending.Expire(now) {
		if ps := p.paths[s.Value.id]; ps != nil {
			p.settle(ps, s.Value, s.Sample, now)
		}
	}
}

// settle records one probe's outcome. An answer resets the bursts lost, the
// first after a lost burst restarting the samples; a burst that settles
// unanswered counts one more and has its destination's host resolved again;
// and a lost routine probe of a path in use or suspect calls a burst.
func (p *Prober) settle(ps *probed, pr probe, s bus.PathSample, now time.Time) {
	r := ps.record
	lost := s.Lost
	samples := r.Samples
	if !lost && r.LostBursts > 0 {
		samples = nil
	}
	samples = append(slices.Clone(samples), s)
	r.Samples = kept(samples, now)
	if lost {
		r.LastLoss = now
	} else {
		r.LastAnswer = now
		r.LostBursts = 0
	}
	switch {
	case pr.burst:
		ps.burstOut--
		ps.burstHit = ps.burstHit || !lost
		if ps.burstLeft == 0 && ps.burstOut == 0 && !ps.burstHit {
			r.LostBursts++
			p.hosts.Forget(r.Dst)
		}
	case lost && pr.confirm:
		p.startBurst(ps, now)
	}
	ps.record = r
	p.changed = true
}

// kept returns the samples a record keeps: the last bus.PathSamples, and
// every older one sent within scion.BoundSpan of now, the furthest a
// reading's bounds read.
func kept(samples []bus.PathSample, now time.Time) []bus.PathSample {
	cut := len(samples) - bus.PathSamples
	for cut > 0 && now.Sub(samples[cut-1].At) <= scion.BoundSpan {
		cut--
	}
	return samples[max(0, cut):]
}

// startBurst starts a burst for the path unless one runs.
func (p *Prober) startBurst(ps *probed, now time.Time) {
	if ps.burstLeft > 0 || ps.burstOut > 0 {
		return
	}
	ps.burstLeft, ps.burstNext, ps.burstHit = BurstProbes, now, false
}

// resolution adopts a resolved host, or spaces the retry of a failed one.
func (p *Prober) resolution(r pinglib.Resolution, now time.Time) {
	if r.Err != nil {
		slog.Debug("Resolving a probed destination's responder", "isd_as", r.Dst, "err", r.Err)
	}
	p.hosts.Adopt(r, now)
}

// due is one probe the dispatch may send: its path, its class, bursts first,
// then heartbeats, then the slow probes, and when it fell due.
type due struct {
	id    bus.PathID
	ps    *probed
	class int
	at    time.Time
}

// dispatch sends the probes due within the budget and returns how long until
// the loop next has work.
func (p *Prober) dispatch(now time.Time) time.Duration {
	p.tokens = min(Budget, p.tokens+now.Sub(p.refilled).Seconds()*Budget)
	p.refilled = now
	p.forget(now)
	var dues []due
	next := now.Add(time.Minute)
	soonest := func(t time.Time) {
		if t.Before(next) {
			next = t
		}
	}
	for id, ps := range p.paths {
		soonest(ps.req.Picked.Add(bus.RequestLapse))
		if !ps.requested {
			continue
		}
		if r := ps.req; r.Role == bus.PathHalfOpen && !r.Due.IsZero() && !r.Due.Equal(ps.halfOpened) {
			if now.Before(r.Due) {
				soonest(r.Due)
			} else {
				ps.halfOpened = r.Due
				p.startBurst(ps, now)
			}
		}
		if ps.burstLeft > 0 {
			if now.Before(ps.burstNext) {
				soonest(ps.burstNext)
			} else {
				dues = append(dues, due{id: id, ps: ps, class: 0, at: ps.burstNext})
			}
			continue
		}
		interval := p.interval(ps, now)
		if interval == 0 || ps.burstOut > 0 {
			continue
		}
		if at := ps.routineAfter().Add(interval); now.Before(at) {
			soonest(at)
		} else {
			class := 2
			if interval == Heartbeat {
				class = 1
			}
			dues = append(dues, due{id: id, ps: ps, class: class, at: at})
		}
	}
	slices.SortFunc(dues, func(a, b due) int {
		return cmp.Or(cmp.Compare(a.class, b.class), a.at.Compare(b.at))
	})
	for _, d := range dues {
		if p.tokens < 1 {
			soonest(now.Add(time.Second / Budget))
			break
		}
		dst := d.ps.req.Dst
		host, ok := p.hosts.Host(dst)
		if !ok {
			// A resolution in flight wakes the loop as it lands; a failed
			// one is retried when its spacing elapses.
			p.hosts.Ask(dst, p.resolutionPaths(dst), now)
			if retry := p.hosts.RetryAt(dst); retry.After(now) {
				soonest(retry)
			}
			continue
		}
		p.send(d, host, now)
		if d.ps.burstLeft > 0 {
			soonest(d.ps.burstNext)
		} else if interval := p.interval(d.ps, now); interval > 0 {
			soonest(d.ps.routineAfter().Add(interval))
		}
	}
	if at, ok := p.pending.Deadline(); ok {
		soonest(at)
	}
	return max(0, next.Sub(now))
}

// interval returns how often the path's routine probes go by its role and
// its destination's last pick, use, or pricing, zero for none.
func (p *Prober) interval(ps *probed, now time.Time) time.Duration {
	hot := now.Sub(ps.req.Picked) < HotWindow
	switch ps.req.Role {
	case bus.PathInUse, bus.PathWeighed:
		if hot {
			return Heartbeat
		}
		return SlowProbe
	case bus.PathPriced:
		if hot {
			return RouteProbe
		}
	case bus.PathStandby, bus.PathSuspect:
		if hot {
			return SlowProbe
		}
	}
	return 0
}

// resolutionPaths returns the requested paths to the destination in the
// order a resolution tries them: those that lost no burst since their last
// answer first, the latest answer first among them.
func (p *Prober) resolutionPaths(dst addr.IA) []*spath.Decoded {
	var ps []*probed
	for _, s := range p.paths {
		if s.requested && s.req.Dst == dst {
			ps = append(ps, s)
		}
	}
	slices.SortFunc(ps, func(a, b *probed) int {
		return cmp.Or(
			cmp.Compare(min(a.record.LostBursts, 1), min(b.record.LostBursts, 1)),
			b.record.LastAnswer.Compare(a.record.LastAnswer))
	})
	paths := make([]*spath.Decoded, len(ps))
	for i, s := range ps {
		paths[i] = s.req.Path
	}
	return paths
}

// send sends one due probe. A probe the conn refuses to send is lost at
// once.
func (p *Prober) send(d due, host netip.Addr, now time.Time) {
	pr := probe{id: d.id, dst: d.ps.req.Dst, burst: d.class == 0,
		confirm: slices.Contains([]bus.PathRole{bus.PathInUse, bus.PathWeighed, bus.PathPriced, bus.PathSuspect},
			d.ps.req.Role),
		inUse: d.ps.req.Role == bus.PathInUse}
	p.tokens--
	if pr.burst {
		d.ps.burstLeft--
		d.ps.burstOut++
		d.ps.burstNext = now.Add(BurstSpacing)
	} else {
		d.ps.lastProbe = now
	}
	if err := p.pending.Send(now, pr, func(seq uint16) error {
		return p.cfg.Echo.Send(d.ps.req.Dst, host, d.ps.req.Path, seq)
	}); err != nil {
		slog.Debug("Sending a probe", "isd_as", d.ps.req.Dst, "err", err)
		p.settle(d.ps, pr, bus.PathSample{At: now, Lost: true}, now)
	}
}

// publish publishes the records when one changed.
func (p *Prober) publish() {
	if !p.changed {
		return
	}
	records := make(map[bus.PathID]bus.PathRecord, len(p.paths))
	for id, ps := range p.paths {
		records[id] = ps.record
	}
	p.cfg.Measurements.Publish(bus.NewPathMeasurements(records))
	p.changed = false
}
