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
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/libs/underlay"
)

// The prober's pacing. A destination is hot for HotWindow after its last
// pick or use: its path in use is probed every Heartbeat, and its standby and
// its suspect every SlowProbe, each first at once. Until its requests lapse,
// its path in use is probed every SlowProbe, its standby and suspect not at
// all. A caller's confirmation of a path counts as its routine probe. A lost
// probe of a path in use or suspect, and a caller's doubt newer than a path's
// last answer, call a burst, which decides the path: an answer keeps or
// clears it, a burst lost whole ejects it.
const (
	// Heartbeat bounds how long a silent failure of a path in use goes
	// unseen, a burst's second beside it.
	Heartbeat = 5 * time.Second
	// SlowProbe matches the cadence at which registrations and lookups
	// refresh the segments the candidates are composed from.
	SlowProbe = time.Minute
	// HotWindow is how long after its last pick or use a destination is hot.
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
	Replies() <-chan Reply
	// Run delivers the replies until ctx ends.
	Run(ctx context.Context)
}

// Reply is one echo reply to the prober's own request: its sequence number,
// and when it arrived.
type Reply struct {
	Seq uint16
	At  time.Time
}

// Resolver returns a destination's responder host, resolved over the path.
type Resolver func(ctx context.Context, dst addr.IA, path *spath.Decoded) (netip.Addr, error)

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
	Resolve Resolver
}

// Prober is the resident ping application: it probes the paths the node's
// requesters ask it to, by SCMP echo to each destination's responder, and
// publishes each path's record. One loop owns its state; the replies and the
// resolutions reach it from loops of their own.
type Prober struct {
	cfg     ProberConfig
	closers []func() error
	close   sync.Once

	resolveReq chan resolveRequest
	resolved   chan resolution

	paths        map[bus.PathID]*probed
	pending      map[uint16]probe
	seq          uint16
	hosts        map[addr.IA]netip.Addr
	resolving    map[addr.IA]bool
	resolveAfter map[addr.IA]time.Time
	lapses       map[segment.LinkID]time.Time
	tokens       float64
	refilled     time.Time
	changed      bool
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
	sent  time.Time
	burst bool
	// confirm reports whether the path was in use or suspect when the
	// probe went: its routine probe's loss calls a burst.
	confirm bool
}

type resolveRequest struct {
	dst   addr.IA
	paths []*spath.Decoded
}

type resolution struct {
	dst  addr.IA
	host netip.Addr
	err  error
}

// NewProber returns a prober over the configured topics, echoes, and
// resolutions.
func NewProber(cfg ProberConfig) *Prober {
	return &Prober{
		cfg:          cfg,
		resolveReq:   make(chan resolveRequest, 16),
		resolved:     make(chan resolution, 16),
		paths:        make(map[bus.PathID]*probed),
		pending:      make(map[uint16]probe),
		hosts:        make(map[addr.IA]netip.Addr),
		resolving:    make(map[addr.IA]bool),
		resolveAfter: make(map[addr.IA]time.Time),
		lapses:       make(map[segment.LinkID]time.Time),
		tokens:       Budget,
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
// resolutions read alone, and returns the prober over the node's bus.
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
		Echo:          &connEchoer{conn: echoConn, replies: make(chan Reply, 64)},
		Resolve: func(ctx context.Context, dst addr.IA, path *spath.Decoded) (netip.Addr, error) {
			host, err := scionrpc.ResolveService(ctx, resolutionConn,
				&scion.Addr{IA: dst, Service: addr.SvcCS, Path: path})
			return host.Addr(), err
		},
	})
	p.closers = []func() error{echoConn.Close, resolutionConn.Close}
	return p, nil
}

// Run probes until ctx ends, then returns nil.
func (p *Prober) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	loops.Go(ctx, &wg, "ping replies", p.cfg.Echo.Run)
	loops.Go(ctx, &wg, "ping resolutions", p.resolve)
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

// resolve answers the probe loop's resolutions one at a time, each over the
// paths it names in turn until one answers.
func (p *Prober) resolve(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-p.resolveReq:
			r := resolution{dst: req.dst}
			for _, path := range req.paths {
				if r.host, r.err = p.cfg.Resolve(ctx, req.dst, path); r.err == nil {
					break
				}
			}
			select {
			case p.resolved <- r:
			case <-ctx.Done():
				return
			}
		}
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
		case r := <-p.resolved:
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

// signal calls a burst for each requested path crossing a link a newer
// signal holds.
func (p *Prober) signal(s bus.InterfaceDownState, now time.Time) {
	lapses := make(map[segment.LinkID]time.Time)
	for _, ps := range p.paths {
		if !ps.requested {
			continue
		}
		for _, l := range ps.req.Links {
			lapse, ok := s.Lapse(l, now)
			if !ok {
				continue
			}
			lapses[l] = lapse
			if lapse.After(p.lapses[l]) {
				p.startBurst(ps, now)
			}
		}
	}
	maps.Copy(p.lapses, lapses)
}

// answer settles the probe a reply answers; a reply after the probe's wait
// settles nothing, the probe already lost.
func (p *Prober) answer(r Reply) {
	pr, ok := p.pending[r.Seq]
	if !ok {
		return
	}
	delete(p.pending, r.Seq)
	if ps := p.paths[pr.id]; ps != nil {
		p.settle(ps, pr, r.At.Sub(pr.sent), false, r.At)
	}
}

// expire settles each probe whose wait ran out as lost.
func (p *Prober) expire(now time.Time) {
	for seq, pr := range p.pending {
		if now.Sub(pr.sent) < ProbeWait {
			continue
		}
		delete(p.pending, seq)
		if ps := p.paths[pr.id]; ps != nil {
			p.settle(ps, pr, 0, true, now)
		}
	}
}

// settle records one probe's outcome. An answer resets the bursts lost, the
// first after a lost burst restarting the samples; a burst that settles
// unanswered counts one more and has its destination's host resolved again;
// and a lost routine probe of a path in use or suspect calls a burst.
func (p *Prober) settle(ps *probed, pr probe, rtt time.Duration, lost bool, now time.Time) {
	r := ps.record
	samples := r.Samples
	if !lost && r.LostBursts > 0 {
		samples = nil
	}
	samples = append(slices.Clone(samples), bus.PathSample{At: pr.sent, RTT: rtt, Lost: lost})
	r.Samples = samples[max(0, len(samples)-bus.PathSamples):]
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
			delete(p.hosts, r.Dst)
		}
	case lost && pr.confirm:
		p.startBurst(ps, now)
	}
	ps.record = r
	p.changed = true
}

// startBurst starts a burst for the path unless one runs.
func (p *Prober) startBurst(ps *probed, now time.Time) {
	if ps.burstLeft > 0 || ps.burstOut > 0 {
		return
	}
	ps.burstLeft, ps.burstNext, ps.burstHit = BurstProbes, now, false
}

// resolution adopts a resolved host, or spaces the retry of a failed one.
func (p *Prober) resolution(r resolution, now time.Time) {
	delete(p.resolving, r.dst)
	if r.err != nil {
		slog.Debug("Resolving a probed destination's responder", "isd_as", r.dst, "err", r.err)
		p.resolveAfter[r.dst] = now.Add(resolveRetry)
		return
	}
	p.hosts[r.dst] = r.host
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
		host, ok := p.host(d.ps.req.Dst, now)
		if !ok {
			// A resolution in flight wakes the loop as it lands; a failed
			// one is retried when its spacing elapses.
			if retry := p.resolveAfter[d.ps.req.Dst]; retry.After(now) {
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
	for _, pr := range p.pending {
		soonest(pr.sent.Add(ProbeWait))
	}
	return max(0, next.Sub(now))
}

// interval returns how often the path's routine probes go by its role and
// its destination's last pick or use, zero for none.
func (p *Prober) interval(ps *probed, now time.Time) time.Duration {
	hot := now.Sub(ps.req.Picked) < HotWindow
	switch ps.req.Role {
	case bus.PathInUse:
		if hot {
			return Heartbeat
		}
		return SlowProbe
	case bus.PathStandby, bus.PathSuspect:
		if hot {
			return SlowProbe
		}
	}
	return 0
}

// host returns the destination's responder host, asking the resolution loop
// for it while it is unknown.
func (p *Prober) host(dst addr.IA, now time.Time) (netip.Addr, bool) {
	if h, ok := p.hosts[dst]; ok {
		return h, true
	}
	if !p.resolving[dst] && !now.Before(p.resolveAfter[dst]) {
		select {
		case p.resolveReq <- resolveRequest{dst: dst, paths: p.resolutionPaths(dst)}:
			p.resolving[dst] = true
		default:
		}
	}
	return netip.Addr{}, false
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
	p.seq++
	pr := probe{id: d.id, sent: now, burst: d.class == 0,
		confirm: d.ps.req.Role == bus.PathInUse || d.ps.req.Role == bus.PathSuspect}
	p.tokens--
	if pr.burst {
		d.ps.burstLeft--
		d.ps.burstOut++
		d.ps.burstNext = now.Add(BurstSpacing)
	} else {
		d.ps.lastProbe = now
	}
	if err := p.cfg.Echo.Send(d.ps.req.Dst, host, d.ps.req.Path, p.seq); err != nil {
		slog.Debug("Sending a probe", "isd_as", d.ps.req.Dst, "err", err)
		p.settle(d.ps, pr, 0, true, now)
		return
	}
	p.pending[p.seq] = pr
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

// connEchoer sends the prober's echoes on a conn of its own, and reads the
// replies to them there.
type connEchoer struct {
	conn    *scion.Conn
	replies chan Reply
}

func (e *connEchoer) Send(dst addr.IA, host netip.Addr, path *spath.Decoded, seq uint16) error {
	return e.conn.WriteEchoRequestTo(&scion.Addr{
		IA:   dst,
		Addr: netip.AddrPortFrom(host, underlay.EndhostPort),
		Path: path,
	}, seq, nil)
}

func (e *connEchoer) Replies() <-chan Reply {
	return e.replies
}

// Run reads the conn until ctx ends, whose end moves the read deadline to
// the past, or until the conn fails.
func (e *connEchoer) Run(ctx context.Context) {
	stop := context.AfterFunc(ctx, func() { _ = e.conn.SetReadDeadline(time.Now()) })
	defer stop()
	for {
		echo, _, err := e.conn.ReadEchoFrom()
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn("Reading the prober's echoes", "err", err)
			}
			return
		}
		if !echo.Reply || echo.Identifier != e.conn.LocalPort() {
			continue
		}
		select {
		case e.replies <- Reply{Seq: echo.Seq, At: time.Now()}:
		case <-ctx.Done():
			return
		}
	}
}
