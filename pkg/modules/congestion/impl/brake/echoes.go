package brake

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/ping"
	"github.com/fancl20/cion/pkg/libs/scion"
)

// The brake's echoes.
const (
	// echoWait is how long an echo waits for its reply before it counts as
	// lost.
	echoWait = time.Second
	// resolveRetry spaces the retries of a neighbor's failed resolution.
	resolveRetry = 5 * time.Second
	// staleLosses is how many echoes to a neighbor lost in a row have its
	// host resolved again, in case it moved; the echoes keep the host they
	// have meanwhile.
	staleLosses = 8
	// asksQueued is how many of the policy's calls for echoes wait for the
	// loop; a call past them is dropped, as the link calls again with its
	// next grant.
	asksQueued = 64
)

// Brake is the brake method as a node runs it: the policy, and the loop that
// sends each echo the policy calls for across its link to the next hop's
// responder, over the one-hop path out of the link, and hands the policy its
// outcome.
type Brake struct {
	*Policy
	echoes  *linkEchoes
	closers []func() error
	close   sync.Once
}

// ResidentConfig configures the brake over the node's link state and conns.
type ResidentConfig struct {
	// Links is the node's link state topic, whose usable links name each
	// echo's neighbor.
	Links *bus.Topic[bus.LinkState]
	// NewConn binds a SCION conn of the node's.
	NewConn func() (*scion.Conn, error)
}

// NewResident binds the brake's two conns, one its echoes ride and one its
// resolutions read alone, and returns the brake over the node's link state,
// having measured no link.
func NewResident(cfg ResidentConfig) (*Brake, error) {
	echoConn, err := cfg.NewConn()
	if err != nil {
		return nil, err
	}
	resolutionConn, err := cfg.NewConn()
	if err != nil {
		_ = echoConn.Close()
		return nil, err
	}
	b := newBrake(linkEchoesConfig{
		links: cfg.Links,
		echo:  ping.NewConn(echoConn),
		resolve: func(ctx context.Context, dst addr.IA, path *spath.Decoded) (netip.Addr, error) {
			return ping.Resolve(ctx, resolutionConn, dst, path)
		},
	})
	b.closers = []func() error{echoConn.Close, resolutionConn.Close}
	return b, nil
}

// newBrake returns a brake whose policy hands its calls for echoes to the
// echoes configured, which hand it their outcomes.
func newBrake(cfg linkEchoesConfig) *Brake {
	b := &Brake{}
	cfg.sampled = func(ifID uint16, s evidence.Sample) { b.Sampled(ifID, s) }
	b.echoes = newLinkEchoes(cfg)
	b.Policy = New(b.echoes.ask)
	return b
}

// Run sends the echoes the policy calls for until ctx ends, then returns
// nil.
func (b *Brake) Run(ctx context.Context) error {
	b.echoes.run(ctx)
	return nil
}

// Close releases the brake's conns.
func (b *Brake) Close() {
	b.close.Do(func() {
		for _, c := range b.closers {
			_ = c()
		}
	})
}

// echoer sends the brake's echoes and delivers the replies to them.
type echoer interface {
	// SendOver sends an echo request to the host in the neighbor over the
	// one-hop path out of the link.
	SendOver(neighbor addr.IA, host netip.Addr, ifID, seq uint16) error
	// Replies delivers each reply to one of the brake's own requests.
	Replies() <-chan ping.Reply
	// ReadReplies reads the replies until ctx ends.
	ReadReplies(ctx context.Context) error
}

// linkEchoesConfig configures a brake's echoes.
type linkEchoesConfig struct {
	// links is the node's link state topic, whose usable links name each
	// echo's neighbor.
	links *bus.Topic[bus.LinkState]
	// echo sends the echoes and delivers their replies.
	echo echoer
	// resolve resolves each neighbor's responder host.
	resolve ping.Resolver
	// sampled takes each echo's outcome: its round trip, or its loss after
	// echoWait.
	sampled func(ifID uint16, s evidence.Sample)
}

// linkEchoes sends the echoes a policy calls for and hands it their outcomes.
// One loop owns its state; the replies and the resolutions reach it from
// loops of their own.
type linkEchoes struct {
	cfg     linkEchoesConfig
	asks    chan uint16
	pending *ping.Pending[hop]
	hosts   *ping.Hosts
	lostRun map[addr.IA]int
}

// hop is the link an echo crossed and the neighbor it went to.
type hop struct {
	ifID     uint16
	neighbor addr.IA
}

// newLinkEchoes returns link echoes that have sent none.
func newLinkEchoes(cfg linkEchoesConfig) *linkEchoes {
	return &linkEchoes{
		cfg:     cfg,
		asks:    make(chan uint16, asksQueued),
		pending: ping.NewPending[hop](echoWait),
		hosts:   ping.NewHosts(cfg.resolve, resolveRetry),
		lostRun: make(map[addr.IA]int),
	}
}

// ask queues the policy's call for an echo across the link. It never blocks:
// a call past the queue's room is dropped.
func (e *linkEchoes) ask(ifID uint16) {
	select {
	case e.asks <- ifID:
	default:
	}
}

// run sends the echoes called for until ctx ends.
func (e *linkEchoes) run(ctx context.Context) {
	var wg sync.WaitGroup
	loops.Go(ctx, &wg, "brake replies", e.readReplies)
	loops.Go(ctx, &wg, "brake resolutions", e.hosts.Resolve)
	loops.Go(ctx, &wg, "brake echoes", e.loop)
	<-ctx.Done()
	wg.Wait()
}

// readReplies reads the echoes' replies until ctx ends or the read fails.
func (e *linkEchoes) readReplies(ctx context.Context) {
	if err := e.cfg.echo.ReadReplies(ctx); err != nil {
		slog.Warn("Reading the brake's echoes", "err", err)
	}
}

// loop owns the echoes' state: it takes the calls, the replies, and the
// resolutions as they come, and settles the echoes whose wait ran out.
func (e *linkEchoes) loop(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ifID := <-e.asks:
			e.send(ifID, time.Now())
		case r := <-e.cfg.echo.Replies():
			e.answer(r)
		case r := <-e.hosts.Landed():
			e.resolution(r, time.Now())
		case <-timer.C:
		}
		now := time.Now()
		e.expire(now)
		if at, ok := e.pending.Deadline(); ok {
			timer.Reset(max(0, at.Sub(now)))
		} else {
			timer.Stop()
		}
	}
}

// send sends an echo across the link to its neighbor's responder, over the
// one-hop path out of the link, which a resolution over that path names. A
// link no usable entry holds is skipped, and so is one whose neighbor's host
// is unknown, which the call asks for; an echo the conn refuses to send
// tells nothing of the link's queue and is skipped too.
func (e *linkEchoes) send(ifID uint16, now time.Time) {
	neighbor, ok := e.cfg.links.Latest().Usable()[ifID]
	if !ok {
		return
	}
	host, ok := e.hosts.Host(neighbor)
	if !ok {
		e.hosts.Ask(neighbor, []*spath.Decoded{nil}, now)
		return
	}
	if err := e.pending.Send(now, hop{ifID: ifID, neighbor: neighbor}, func(seq uint16) error {
		return e.cfg.echo.SendOver(neighbor, host, ifID, seq)
	}); err != nil {
		slog.Debug("Sending an echo across a link", "if_id", ifID, "err", err)
	}
}

// answer hands the policy the round trip of the echo a reply answers; a
// reply after the echo's wait hands nothing, the echo already lost.
func (e *linkEchoes) answer(r ping.Reply) {
	s, ok := e.pending.Answered(r)
	if !ok {
		return
	}
	e.lostRun[s.Value.neighbor] = 0
	e.cfg.sampled(s.Value.ifID, s.Sample)
}

// expire hands the policy each echo whose wait ran out as lost; staleLosses
// of them lost in a row to one neighbor have its host resolved again, kept
// meanwhile.
func (e *linkEchoes) expire(now time.Time) {
	for _, s := range e.pending.Expire(now) {
		e.cfg.sampled(s.Value.ifID, s.Sample)
		neighbor := s.Value.neighbor
		e.lostRun[neighbor]++
		if e.lostRun[neighbor] >= staleLosses {
			e.lostRun[neighbor] = 0
			e.hosts.Ask(neighbor, []*spath.Decoded{nil}, now)
		}
	}
}

// resolution adopts a neighbor's resolved host, or spaces the retry of a
// failed one.
func (e *linkEchoes) resolution(r ping.Resolution, now time.Time) {
	if r.Err != nil {
		slog.Debug("Resolving a neighbor's responder", "isd_as", r.Dst, "err", r.Err)
	}
	e.hosts.Adopt(r, now)
}
