package measured

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/controlplane"
	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
)

// The selection loop's constants (no operator tuning). A node keeps at least
// NeighborFloor up links no single failure can partition it from, caps the
// count to bound beaconing fan-out, promotes a candidate whose direct link
// earns its place against its tier's price, demotes a neighbor whose
// exclusion serves its tier no worse, and damp both directions to sustained
// evidence — every link change re-shapes segments network-wide.
const (
	// SelectionInterval is the evaluation window.
	SelectionInterval = 30 * time.Second
	// SelectionJitter spreads the windows of a network's nodes.
	SelectionJitter = 3 * time.Second
	// NeighborFloor is the least up links a node keeps.
	NeighborFloor = 2
	// MaxNeighbors caps the neighbor count.
	MaxNeighbors = 8
	// PromotionRatio: a direct link must beat its tier's price by it.
	PromotionRatio = 0.8
	// DemotionRatio: a direct link may lose to its tier's price by it.
	DemotionRatio = 1.25
	// TierGap is the multiple of a tier's median direct round trip at which
	// a peer opens the next tier.
	TierGap = 2.0
	// PromoteWindows is the consecutive good windows a promotion needs.
	PromoteWindows = 2
	// DemoteWindows is the consecutive bad windows a retirement needs.
	DemoteWindows = 3
	// ProbeRuns is the echoes per measurement run; the median is the sample.
	ProbeRuns = 3
	// ProbeWait bounds the wait for each echo reply.
	ProbeWait = time.Second
	// CandidateWindow is how long an unproven candidate lives: a peer that
	// produces no verified beacon or enrollment within it retires.
	CandidateWindow = time.Minute
	// EstablishTimeout bounds one in-band request: a link request, or the
	// read of a candidate's evidence, which can ask the node's core.
	EstablishTimeout = 5 * time.Second
)

// LinkRequester establishes a link over the control endpoint's authenticated
// channel; PeerClient satisfies it.
type LinkRequester interface {
	// Link asks the peer to admit the link, offering the requester's link
	// address and interface ID, and answers the peer's side of it.
	Link(ctx context.Context, peer *scion.Addr,
		local netip.AddrPort, ifID uint16) (*nodev1.LinkReply, error)
}

// SelectionConfig configures the selection loop.
type SelectionConfig struct {
	// IA is the local ISD-AS.
	IA addr.IA
	// Store is the neighbor table — the loop's decisions land in it.
	Store links.DB
	// Directory snapshots the node directory's entries.
	Directory func() []DirectoryEntry
	// Verdicts returns the health monitor's link verdicts by interface ID:
	// an established neighbor whose verdict is down counts as infinitely
	// slow for the window whatever its last sample said, and the redundancy
	// floor counts up links only. Nil treats every link as up.
	Verdicts func() map[uint16]bool
	// Latencies receives the window's per-link one-way delay estimates —
	// each neighbor's echo round trip halved — for the beaconer's entries
	// to declare; nil discards them.
	Latencies *controlplane.LinkLatency
	// Provider resolves the freshest path to a candidate — the baseline.
	Provider *scion.PathProvider
	// Conn carries the SCMP echo probes; its port is the reply address.
	Conn *scion.Conn
	// ControlAddr is the node's own control address, claimed in probes; its
	// host is the scope the loop's own dials leave from, the half of the
	// scope filter the viewer supplies.
	ControlAddr netip.AddrPort
	// LinkHost is the host link addresses are allocated on.
	LinkHost netip.Addr
	// Link establishes a link in-band.
	Link LinkRequester
	// Learn records the external host a rendezvous reply's observed source
	// names for the node, latest observation winning; nil discards it.
	Learn func(netip.Addr)
	// Evidence reports whether a candidate's peer has proven itself — a
	// verified beacon or an enrollment the node has seen, or one its core
	// answers for — or the failure of the read that would tell, which leaves
	// the candidate to the next pass. The context bounds a read that asks
	// the core.
	Evidence func(context.Context, *links.Link) (bool, error)
	// Stranded, when set, records the window's finding that the node holds
	// fewer up links than the floor and no directory candidate answered its
	// probe — the flag the joiner's dial loop reads to re-dial the
	// rendezvous addresses the table already holds, retired entries
	// included. Nil discards the finding.
	Stranded *atomic.Bool
	// MaxLinks caps the neighbor count; zero uses MaxNeighbors.
	MaxLinks int
	// Interval and Window override the evaluation window and the candidate
	// window; zero keeps them. Tests pace the loop with them.
	Interval time.Duration
	Window   time.Duration
}

// RunSelection runs the topology loop until the context is canceled: each
// evaluation window it sweeps the candidates, probes every peer the directory
// names by rendezvous echo against SCMP echo over the freshest clean path,
// classes the samples into tiers with their facts and excluded measurements,
// and lands promotion and retirement decisions in the link store — each
// change a data plane generation swap the node assembly's supervisor
// performs.
func RunSelection(ctx context.Context, cfg SelectionConfig) {
	s := &selection{cfg: cfg}
	interval := cfg.Interval
	if interval == 0 {
		interval = SelectionInterval
	}
	for {
		if !loops.Sleep(ctx, jitter(interval)) {
			return
		}
		s.pass(ctx)
	}
}

// jitter spreads evaluation windows by up to a fraction of the interval;
// a randomness failure runs the window unjittered.
func jitter(interval time.Duration) time.Duration {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		slog.Error("Reading jitter randomness", "err", err)
		return interval
	}
	frac := binary.BigEndian.Uint64(raw) % uint64(SelectionJitter)
	if time.Duration(frac) > interval/4 {
		frac = uint64(interval / 4)
	}
	return interval + time.Duration(frac)
}

type selection struct {
	cfg SelectionConfig
	// streaks damp the decisions: consecutive windows of the same evidence.
	streaks map[addr.IA]*peerStreak
	// upLeft records that an up link left this window, by retirement or
	// eviction: each departure changes the routes every other exclusion was
	// measured against, so one up link leaves per window.
	upLeft bool
	// probeFn, pathEchoFn, aliveFn, and establishFn override the
	// measurement, the excluded measurement's echo, the candidate-grace
	// probe, and the establishment in tests; nil uses the real ones.
	probeFn     func(context.Context, DirectoryEntry, *links.Link) sample
	pathEchoFn  func(addr.IA, *scion.Candidate) time.Duration
	aliveFn     func(*links.Link) bool
	establishFn func(context.Context, DirectoryEntry, string) bool
}

// peerStreak counts a peer's consecutive windows of evidence, one count per
// rule: promote for a candidate's priced admission, down for an
// established link's verdict, and useless for an up link's useless test.
type peerStreak struct {
	promote int
	down    int
	useless int
}

// measurement is one peer's probe sample.
type measurement struct {
	// direct is the direct side's median: the SCMP echo over the one-hop
	// path for an established neighbor, the rendezvous echo for a
	// candidate — one instrument over two carriers, each reaching where
	// the other cannot. Zero when unreachable.
	direct time.Duration
	// path is the baseline: the SCMP echo median over the freshest clean
	// composed route; zero when no path answered.
	path time.Duration
}

// sample is one peer's window record: the probe's measurement — its two
// fields — beside the enumeration the probe already ran, kept rather than
// discarded: the tier's route counts and prices read it. carrier points
// into the enumeration at the candidate the baseline echo rode; nil when no
// clean candidate resolved.
type sample struct {
	m          measurement
	candidates []scion.Candidate
	carrier    *scion.Candidate
}

// pass runs one evaluation window. A context that ends mid-window cuts the
// probes short, and their samples land nothing.
func (s *selection) pass(ctx context.Context) {
	if s.streaks == nil {
		s.streaks = make(map[addr.IA]*peerStreak)
	}
	entries, err := s.cfg.Store.All(ctx)
	if err != nil {
		slog.Error("Selection reading the link store", "err", err)
		return
	}
	s.sweep(ctx, entries)

	neighbors := s.neighbors(entries) // established, by IA
	directory := s.directory()

	// Probe every peer the directory names — neighbor and candidate alike (the
	// comparator never stops at admission) — each by its own carrier: the
	// neighbor's direct side over the one-hop path, the candidate's by rendezvous
	// echo. The scope filter skips what the viewer cannot dial, whoever
	// published it.
	samples := make(map[addr.IA]sample)
	entriesByIA := make(map[addr.IA]DirectoryEntry)
	candidates := make([]DirectoryEntry, 0, len(directory))
	for _, e := range directory {
		if e.IA.Equal(s.cfg.IA) ||
			!probeable(s.cfg.ControlAddr.Addr(), e.RendezvousAddr.Addr()) {
			continue
		}
		entriesByIA[e.IA] = e
		if l, ok := neighbors[e.IA]; ok {
			samples[e.IA] = s.measure(ctx, e, l)
			continue
		}
		candidates = append(candidates, e)
		samples[e.IA] = s.measure(ctx, e, nil)
	}
	ts := s.windowTiers(ctx, neighbors, entriesByIA, samples)
	if ctx.Err() != nil {
		return
	}
	s.declare(neighbors, samples)
	if s.cfg.Stranded != nil {
		reachable := false
		for _, e := range candidates {
			if samples[e.IA].m.direct > 0 {
				reachable = true
				break
			}
		}
		// Below the floor, a node no directory candidate answers dials what
		// it knows.
		s.cfg.Stranded.Store(s.upCount(neighbors) < NeighborFloor && !reachable)
	}
	s.count(neighbors, ts)
	// Damp the promotions: a candidate is promoted on sustained evidence
	// only, a flapping one never.
	for _, e := range candidates {
		if s.qualifies(e.IA, samples, ts) {
			s.streak(e.IA).promote++
		} else {
			s.streak(e.IA).promote = 0
		}
	}
	s.upLeft = false
	s.promote(ctx, entries, neighbors, candidates, samples, ts)
	s.prune(ctx, entries, samples, ts)
}

// sweep settles the candidate entries: proven peers are established, and
// peers that produced no verified beacon or enrollment within the window
// retire — unless this window's probe of the candidate answers, for a peer
// that answers its rendezvous socket is alive and trying, exactly the joiner
// whose enrollment is still in flight; it retires when it goes silent. Push
// became pull: the same UDP round trip to the same rendezvous socket the
// window's measurement already rides is now the grace's only evidence, and
// it is spent on named candidates alone — the unnamed entries the probes
// themselves mint on their targets retire with the window, or the cap they
// bound would fill with them.
func (s *selection) sweep(ctx context.Context, entries []*links.Link) {
	window := s.cfg.Window
	if window == 0 {
		window = CandidateWindow
	}
	now := time.Now()
	for _, l := range entries {
		if l.State != links.StateCandidate {
			continue
		}
		proven, err := s.proven(ctx, l)
		if err != nil {
			slog.Error("Reading a candidate's evidence", "neighbor", l.NeighborIA, "err", err)
			continue
		}
		if proven {
			l.State = links.StateEstablished
			if err := s.cfg.Store.Update(ctx, l); err != nil {
				slog.Error("Establishing a candidate", "neighbor", l.NeighborIA, "err", err)
				continue
			}
			delete(s.streaks, l.NeighborIA)
			slog.Info("Candidate proven; link established",
				"neighbor", l.NeighborIA, "interface", l.IfID)
		} else if now.Sub(l.Created) > window {
			// An echo the context's end cut short is no silence.
			if s.candidateAlive(ctx, l) || ctx.Err() != nil {
				continue
			}
			s.retire(ctx, l, "candidate window elapsed without a proven peer")
		}
	}
}

// proven reads the candidate's evidence, bounded like an in-band request;
// without an evidence source no candidate is proven.
func (s *selection) proven(ctx context.Context, l *links.Link) (bool, error) {
	if s.cfg.Evidence == nil {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, EstablishTimeout)
	defer cancel()
	return s.cfg.Evidence(ctx, l)
}

// candidateAlive runs one rendezvous echo against the candidate's own
// rendezvous socket, through the test seam when set. An answer is a peer
// alive and trying; the echo claims the zero ISD-AS like every probe,
// minting no entry a sweep could mistake for a peer.
func (s *selection) candidateAlive(ctx context.Context, l *links.Link) bool {
	if l.NeighborIA.IsZero() {
		return false
	}
	if s.aliveFn != nil {
		return s.aliveFn(l)
	}
	target := rendezvousTarget(l)
	if !target.IsValid() {
		return false
	}
	_, _, err := s.echo(ctx, s.cfg.ControlAddr.Addr(), target,
		addr.IA(0), s.cfg.ControlAddr)
	return err == nil
}

// rendezvousTarget returns the rendezvous socket of an entry's peer: the
// address the entry records, or else the fixed rendezvous port on the host
// of its recorded remote address, the two sharing the control host. The
// entries the acceptor mints record no rendezvous address. Invalid when the
// entry records neither.
func rendezvousTarget(l *links.Link) netip.AddrPort {
	if l.Rendezvous.IsValid() {
		return l.Rendezvous
	}
	if l.Remote.Addr().IsValid() {
		return netip.AddrPortFrom(l.Remote.Addr(), RendezvousPort)
	}
	return netip.AddrPort{}
}

// echo dials one rendezvous exchange, recording the external host the
// reply's observed source names for the node — every dial teaches the
// dialer its external host.
func (s *selection) echo(
	ctx context.Context,
	bind netip.Addr,
	target netip.AddrPort,
	ia addr.IA,
	linkAddr netip.AddrPort,
) (RendezvousReply, time.Duration, error) {
	reply, rtt, err := RendezvousEcho(ctx, bind, target, ia, linkAddr)
	if err == nil && s.cfg.Learn != nil {
		s.cfg.Learn(reply.Observed.Addr())
	}
	return reply, rtt, err
}

// neighbors maps the established entries by their neighbor ISD-AS.
func (s *selection) neighbors(entries []*links.Link) map[addr.IA]*links.Link {
	out := make(map[addr.IA]*links.Link)
	for _, l := range entries {
		if l.State == links.StateEstablished {
			out[l.NeighborIA] = l
		}
	}
	return out
}

// upCount counts the established neighbors whose verdicts are up — the
// count the floor reads.
func (s *selection) upCount(neighbors map[addr.IA]*links.Link) int {
	up := 0
	for _, l := range neighbors {
		if s.linkUp(l.IfID) {
			up++
		}
	}
	return up
}

// named reports whether the entry is live and names its neighbor — the
// entries the link cap bounds, since only they carry beacons. Unnamed
// candidates, probes and bootstrap claims, retire with the candidate
// window.
func named(l *links.Link) bool {
	return l.Live() && !l.NeighborIA.IsZero()
}

// namedLive counts the entries the link cap bounds.
func namedLive(entries []*links.Link) int {
	n := 0
	for _, l := range entries {
		if named(l) {
			n++
		}
	}
	return n
}

// liveNeighbor reports whether a live entry names the neighbor.
func liveNeighbor(entries []*links.Link, ia addr.IA) bool {
	for _, l := range entries {
		if l.Live() && l.NeighborIA.Equal(ia) {
			return true
		}
	}
	return false
}

// linkUp reports the interface's verdict; a loop without the monitor's
// verdicts treats every link as up.
func (s *selection) linkUp(ifID uint16) bool {
	if s.cfg.Verdicts == nil {
		return true
	}
	up, ok := s.cfg.Verdicts()[ifID]
	return !ok || up
}

// directory snapshots the node directory; nil Directory serves none.
func (s *selection) directory() []DirectoryEntry {
	if s.cfg.Directory == nil {
		return nil
	}
	return s.cfg.Directory()
}

// addrScope is an address's reachability scope: what can route to it.
type addrScope uint8

const (
	scopeGlobal    addrScope = iota // globally routable
	scopeLoopback                   // the host's own addresses
	scopePrivate                    // RFC 1918 and IPv6 unique-local
	scopeShared                     // the CGNAT shared range, RFC 6598
	scopeLinkLocal                  // one link alone
	// scopeNone marks addresses no dial routes to: invalid, unspecified,
	// and multicast ones, which share no viewer's scope.
	scopeNone
)

// cgnat is the shared address range RFC 6598 allocates — carrier-side
// translation, reachable from inside whatever deployment claimed it.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// scopeOf classifies an address by its reachability scope.
func scopeOf(a netip.Addr) addrScope {
	switch {
	case !a.IsValid() || a.IsUnspecified() || a.IsMulticast():
		return scopeNone
	case a.IsLoopback():
		return scopeLoopback
	case a.IsLinkLocalUnicast():
		return scopeLinkLocal
	case a.Is4() && cgnat.Contains(a):
		return scopeShared
	case a.IsPrivate():
		return scopePrivate
	default:
		return scopeGlobal
	}
}

// probeable reports whether a dial from the viewer can route to the entry:
// a globally routable address always, and whatever shares the viewer's own
// scope beside it — the loopback pairing the integration labs run on, one
// host routing its own addresses. Private, shared, and link-local scopes
// answer no dial from a global viewer, whoever published them; both of an
// entry's published addresses sit on the one host, so the rendezvous
// address's test covers the control address beside it.
func probeable(viewer, entry netip.Addr) bool {
	es := scopeOf(entry)
	return es == scopeGlobal || (es != scopeNone && es == scopeOf(viewer))
}

// measure runs the window's probe of one peer — a nil neighbor entry means
// a candidate — through the test seam when set.
func (s *selection) measure(
	ctx context.Context, e DirectoryEntry, l *links.Link,
) sample {
	if s.probeFn != nil {
		return s.probeFn(ctx, e, l)
	}
	return s.probe(ctx, e, l)
}

// establish lands a promotion, through the test seam when set.
func (s *selection) establish(ctx context.Context, e DirectoryEntry, why string) bool {
	if s.establishFn != nil {
		return s.establishFn(ctx, e, why)
	}
	return s.establishLink(ctx, e, why)
}

// probe measures one peer by the directory's own distinction: an
// established neighbor's direct side by SCMP echo over the one-hop path —
// the conn resolving the egress interface from the link table as every
// one-hop write does, the responder in the peer's core answering on the
// reversed arrival path — and a candidate's (a demoted neighbor included)
// by the rendezvous echo that reaches where no path and no interface exist.
// A neighbor whose link the conn cannot send over — its verdict down —
// fails each run's write at once, and the zero sample is what it would
// measure. The baseline is the same SCMP echo instrument over the
// freshest clean composed route of the enumeration the probe keeps beside
// the sample, the route recorded as the sample's carrier: one destination,
// two routes, the same median-of-runs discipline, and no clean route leaves
// the baseline unmeasured for the window rather than measured over a route
// the network would not serve. The rendezvous echo claims the zero ISD-AS —
// a probe mints no entry a candidate sweep could mistake for a peer —
// deduplicated by the control address it claims.
func (s *selection) probe(ctx context.Context, e DirectoryEntry, l *links.Link) sample {
	var m measurement
	if l != nil {
		m.direct = s.echoRTT(ctx, &scion.Addr{
			IA:   e.IA,
			Addr: netip.AddrPortFrom(e.ControlAddr.Addr(), underlay.EndhostPort),
		})
	} else if _, rtt, err := s.echo(ctx, s.cfg.ControlAddr.Addr(),
		e.RendezvousAddr, addr.IA(0), s.cfg.ControlAddr); err == nil {
		m.direct = rtt
	}
	probeCtx, cancel := context.WithTimeout(ctx, ProbeWait*ProbeRuns+time.Second)
	defer cancel()
	sm := sample{m: m}
	candidates, err := s.cfg.Provider.Enumerate(probeCtx, e.IA)
	if err != nil {
		return sm
	}
	sm.candidates = candidates
	// Freshness picks the baseline's route and the echo measures it: the
	// comparator reads the two round trips against each other.
	if c := s.freshest(candidates); c != nil {
		sm.carrier = c
		sm.m.path = s.pathEcho(ctx, e, c)
	}
	return sm
}

// pathEcho takes the median SCMP echo round trip to the peer over the
// candidate's path, through the test seam when set.
func (s *selection) pathEcho(
	ctx context.Context, e DirectoryEntry, c *scion.Candidate,
) time.Duration {
	if s.pathEchoFn != nil {
		return s.pathEchoFn(e.IA, c)
	}
	return s.echoRTT(ctx, &scion.Addr{
		IA:   e.IA,
		Addr: netip.AddrPortFrom(e.ControlAddr.Addr(), underlay.EndhostPort),
		Path: c.Path,
	})
}

// declare lands the window's per-link one-way estimates in the shared table
// the beaconer's entries declare: each neighbor's echo round trip halved —
// half a round trip is the node's estimate of the one-way delay the
// extension defines. A link the window did not measure declares nothing
// again.
func (s *selection) declare(neighbors map[addr.IA]*links.Link, samples map[addr.IA]sample) {
	if s.cfg.Latencies == nil {
		return
	}
	for ia, l := range neighbors {
		s.cfg.Latencies.Record(l.IfID, samples[ia].m.direct/2)
	}
}

// echoRTT takes the median SCMP echo round trip to the destination — over
// the one-hop path the conn resolves for a neighbor, over the supplied path
// for the baseline. Zero without a probe conn. A run whose request a router
// refuses with an interface-down signal is lost at the signal rather than
// at ProbeWait. The context's end moves the read deadline to the past,
// ending a wait in flight; each run reads the context after setting its own
// deadline, so no run overrides the move unseen.
func (s *selection) echoRTT(ctx context.Context, dst *scion.Addr) time.Duration {
	if s.cfg.Conn == nil {
		return 0
	}
	stop := context.AfterFunc(ctx, func() { _ = s.cfg.Conn.SetReadDeadline(time.Now()) })
	defer stop()
	var rtts []time.Duration
	for seq := range uint16(ProbeRuns) {
		if err := s.cfg.Conn.SetReadDeadline(time.Now().Add(ProbeWait)); err != nil {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		sent := time.Now()
		if err := s.cfg.Conn.WriteEchoRequestTo(dst, seq, nil); err != nil {
			continue
		}
		// The wait elapsing, the context ending, or a router refusing the
		// request loses the run.
		if _, _, err := s.cfg.Conn.ReadEchoReply(seq); err == nil {
			rtts = append(rtts, time.Since(sent))
		}
	}
	return median(rtts)
}

// promote applies the four admission cases in order, the first
// that fires establishing one link — every link change reshapes segments
// network-wide, so the window's budget is one establishment, as today.
// Below the floor of up links, reachability alone admits, the fastest
// reachable candidate. A stranded tier admits a reachable member at once,
// no streak — the clause that keeps every cut transient, for no up link and
// no answered composed route reach the tier, and the establishment rides
// the rendezvous exchange that reaches where no path does. A single-route
// tier admits a second member within the demotion ratio of the price, and a
// tier whose price a candidate beats by the promotion ratio admits it — the
// priced cases sustained, the sustained winner the fastest direct sample
// among qualifiers. At the cap every case requires an eviction that
// qualifies under retirement, the floor and stranded cases included.
func (s *selection) promote(
	ctx context.Context,
	entries []*links.Link,
	neighbors map[addr.IA]*links.Link,
	candidates []DirectoryEntry,
	samples map[addr.IA]sample,
	ts []tier,
) {

	live := s.upCount(neighbors)
	// Rank the reachable candidates: fastest first.
	var reachable []DirectoryEntry
	for _, e := range candidates {
		if samples[e.IA].m.direct > 0 {
			reachable = append(reachable, e)
		}
	}
	sort.Slice(reachable, func(i, j int) bool {
		return samples[reachable[i].IA].m.direct < samples[reachable[j].IA].m.direct
	})

	if live < NeighborFloor {
		// Below the floor, reachability outranks latency: any reachable
		// candidate will do, the fastest first.
		if len(reachable) == 0 {
			slog.Warn("Redundancy floor unmet; no reachable candidate",
				"neighbors", live, "floor", NeighborFloor)
			return
		}
		s.admit(ctx, entries, neighbors, ts, samples, reachable[0], "the redundancy floor")
		return
	}

	// A stranded tier: its fastest reachable member, at once. The fastest
	// candidate overall that a stranded tier holds is that member, for the
	// ranking is global.
	var rescue *DirectoryEntry
	for i, e := range reachable {
		if t := tierOf(ts, e.IA); t != nil && t.stranded {
			rescue = &reachable[i]
			break
		}
	}
	if rescue != nil {
		s.admit(ctx, entries, neighbors, ts, samples, *rescue, "its stranded tier")
		return
	}

	// The priced cases, sustained — a second route for a single-route tier
	// first, redundancy purchased at a bounded latency price, then any
	// beaten price — the fastest sustained winner either way.
	for _, e := range reachable {
		t := tierOf(ts, e.IA)
		if t == nil || t.routes != 1 || t.price == 0 {
			continue
		}
		if s.streak(e.IA).promote >= PromoteWindows &&
			samples[e.IA].m.direct <= ratioOf(t.price, DemotionRatio) {
			s.admit(ctx, entries, neighbors, ts, samples, e, "a second route for its tier")
			return
		}
	}
	for _, e := range reachable {
		if s.streak(e.IA).promote < PromoteWindows ||
			!s.qualifies(e.IA, samples, ts) {
			continue
		}
		s.admit(ctx, entries, neighbors, ts, samples, e, "its direct link beats its tier's price")
		return
	}
}

// qualifies reports whether the candidate's sample earns promotion under
// the priced cases of its tier this window. Only a classed, reachable peer
// promotes: an unmeasured peer carries no label to compare and no sample
// to compare with.
func (s *selection) qualifies(ia addr.IA, samples map[addr.IA]sample, ts []tier) bool {
	sm := samples[ia]
	if sm.m.direct == 0 {
		return false
	}
	t := tierOf(ts, ia)
	return t != nil && t.qualifies(sm.m.direct)
}

// admit lands a promotion, evicting at the cap first: the victim is the
// retirement-qualified neighbor whose exclusion moves its tier's price
// least, and none qualifying means no promotion — the cap bounds the set at
// every instant. The cap counts the named live entries, as the acceptor's
// does, so a candidate in flight holds its place.
func (s *selection) admit(
	ctx context.Context,
	entries []*links.Link,
	neighbors map[addr.IA]*links.Link,
	ts []tier,
	samples map[addr.IA]sample,
	e DirectoryEntry,
	why string,
) {

	cap := s.cfg.MaxLinks
	if cap == 0 {
		cap = MaxNeighbors
	}
	if namedLive(entries) >= cap {
		victim := s.evict(neighbors, ts, samples)
		if victim == nil {
			return
		}
		up := s.linkUp(victim.IfID)
		if !s.retire(ctx, victim, "displaced by the least-harm eviction") {
			return
		}
		s.upLeft = s.upLeft || up
	}
	s.establish(ctx, e, why)
}

// evict returns the cap's victim among the retirement-qualified neighbors:
// a down link whose down count reached DemoteWindows, at no harm, and an up
// link this window decides useless while up links exceed the floor. The
// victim is the one whose exclusion moves its tier's price least, ties to
// the slower direct sample. Nil when none qualifies — no promotion happens
// and the cap stands, so displacement cannot evict a link the policy must
// immediately re-recruit: the intra-regional mesh, whose exclusion changes
// nothing, retires first, and the bridge, whose exclusion leaves its tier no
// answered route, decides nothing and is not eligible at all.
func (s *selection) evict(
	neighbors map[addr.IA]*links.Link,
	ts []tier,
	samples map[addr.IA]sample,
) *links.Link {
	up := s.upCount(neighbors)
	var worst *links.Link
	var worstHarm, worstDirect time.Duration
	for ia, l := range neighbors {
		var cost time.Duration
		if !s.linkUp(l.IfID) {
			if s.streak(ia).down < DemoteWindows {
				continue
			}
		} else {
			if up <= NeighborFloor {
				continue // an up link leaves only while up links exceed the floor
			}
			t := tierOf(ts, ia)
			if decided, useless := judge(t, ia); !decided || !useless {
				continue
			}
			cost = harm(t, ia)
		}
		direct := samples[ia].m.direct
		if worst == nil || cost < worstHarm ||
			cost == worstHarm && slower(direct, worstDirect) {
			worst, worstHarm, worstDirect = l, cost, direct
		}
	}
	return worst
}

// slower ranks two direct samples for the least-harm ties of eviction and
// retirement: no sample counts as infinitely slow — an unmeasured link is
// the slower one, however recent its last answer was.
func slower(a, b time.Duration) bool {
	if a == 0 {
		return b != 0
	}
	if b == 0 {
		return false
	}
	return a > b
}

// count advances each established link's retirement counts by the window's
// evidence. The down count grows in a window whose verdict is down and
// resets in one whose verdict is up. The useless count grows in a window
// that decides the link useless, resets in one that decides it useful, and
// holds in a window that decides nothing — a down one included: no
// evidence, no change.
func (s *selection) count(neighbors map[addr.IA]*links.Link, ts []tier) {
	for ia, l := range neighbors {
		st := s.streak(ia)
		if !s.linkUp(l.IfID) {
			st.down++
			continue
		}
		st.down = 0
		switch decided, useless := judge(tierOf(ts, ia), ia); {
		case decided && useless:
			st.useless++
		case decided:
			st.useless = 0
		}
	}
}

// prune applies the two retirement rules, each on its own count. A link
// whose verdict stayed down for DemoteWindows windows retires, with no
// guard: a down link carries no route and is no redundancy. Then at most
// one up link retires as useless — none in a window whose eviction took an
// up link, for each departure changes the routes every other exclusion was
// measured against — and only while up links exceed the floor: of the up
// links whose useless count reached DemoteWindows and whose window decides
// them useless, the one whose exclusion moves its tier's price least, ties
// to the slower direct sample. The useless test is measured each window and
// decides only when a route avoiding the link answered, so a cut-critical
// link never retires as useless; it and promotion's priced cases read the
// same price with hysteresis between the thresholds — one test serving both
// directions, each correcting the other's estimation error.
func (s *selection) prune(
	ctx context.Context,
	entries []*links.Link,
	samples map[addr.IA]sample,
	ts []tier,
) {

	up := 0
	for _, l := range entries {
		if l.State != links.StateEstablished {
			continue
		}
		if s.linkUp(l.IfID) {
			up++
			continue
		}
		if s.streak(l.NeighborIA).down >= DemoteWindows {
			s.retire(ctx, l, "its verdict stayed down")
		}
	}
	if s.upLeft || up <= NeighborFloor {
		return
	}
	var worst *links.Link
	var worstHarm, worstDirect time.Duration
	for _, l := range entries {
		if l.State != links.StateEstablished || !s.linkUp(l.IfID) ||
			s.streak(l.NeighborIA).useless < DemoteWindows {
			continue
		}
		t := tierOf(ts, l.NeighborIA)
		if decided, useless := judge(t, l.NeighborIA); !decided || !useless {
			continue
		}
		cost := harm(t, l.NeighborIA)
		direct := samples[l.NeighborIA].m.direct
		if worst == nil || cost < worstHarm ||
			cost == worstHarm && slower(direct, worstDirect) {
			worst, worstHarm, worstDirect = l, cost, direct
		}
	}
	if worst != nil && s.retire(ctx, worst, "its tier served no worse without it") {
		s.upLeft = true
	}
}

// streak returns the peer's damping counters.
func (s *selection) streak(ia addr.IA) *peerStreak {
	st, ok := s.streaks[ia]
	if !ok {
		st = &peerStreak{}
		s.streaks[ia] = st
	}
	return st
}

// retire withdraws a link: its entry goes to retired, the interface ID held
// back until no unexpired segment can reference it.
func (s *selection) retire(ctx context.Context, l *links.Link, why string) bool {
	l.State = links.StateRetired
	l.Retired = time.Now()
	if err := s.cfg.Store.Update(ctx, l); err != nil {
		slog.Error("Retiring a link", "neighbor", l.NeighborIA, "err", err)
		return false
	}
	// The damping starts over: a retired peer re-earns promotion from
	// scratch, and its demotion evidence is spent.
	delete(s.streaks, l.NeighborIA)
	slog.Info("Link retired", "neighbor", l.NeighborIA, "interface", l.IfID, "why", why)
	return true
}

// establish lands a promoted candidate: in-band over the composed path when
// one resolves and answers — the authenticated request — else the rendezvous
// exchange a joiner with no paths uses, whose entries the candidate sweep
// settles on the peer's evidence. A path that resolves but carries nothing —
// the composed route crossing the very link that went down — fails the
// in-band request, and the rendezvous establishment takes over.
func (s *selection) establishLink(ctx context.Context, e DirectoryEntry, why string) bool {
	entry, err := s.ownEntry(ctx, e)
	if err != nil {
		slog.Error("Recording the local side of a promoted candidate",
			"neighbor", e.IA, "err", err)
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, EstablishTimeout)
	defer cancel()
	if path, err := s.cfg.Provider.Path(probeCtx, e.IA); err == nil {
		peer := &scion.Addr{
			IA:   e.IA,
			Addr: netip.AddrPortFrom(e.ControlAddr.Addr(), controlplane.EndpointPort),
			Path: path,
		}
		rpcCtx, rpcCancel := context.WithTimeout(ctx, EstablishTimeout)
		defer rpcCancel()
		reply, err := s.cfg.Link.Link(rpcCtx, peer, entry.Local, entry.IfID)
		if err != nil {
			// The path resolved but did not answer; the rendezvous exchange
			// below is the establishment that reaches the peer regardless.
			slog.Warn("The in-band link request failed", "neighbor", e.IA, "err", err)
		} else if remote, err := netip.ParseAddrPort(reply.LocalAddr); err != nil {
			slog.Error("The link reply carries a malformed address", "err", err)
			return false
		} else {
			entry.Remote = remote
			entry.RemoteIfID = uint16(reply.IfId)
			entry.State = links.StateEstablished
			if err := s.cfg.Store.Update(ctx, entry); err != nil {
				slog.Error("Establishing a link", "neighbor", e.IA, "err", err)
				return false
			}
			s.streak(e.IA).promote = 0
			slog.Info("Link established", "neighbor", e.IA, "why", why,
				"interface", entry.IfID, "local", entry.Local, "remote", entry.Remote)
			return true
		}
	}
	// No composed path, or one that did not answer: the rendezvous exchange
	// is the establishment, the entries starting as candidates the peer's
	// evidence settles.
	if !s.establishByRendezvous(ctx, e, entry) {
		return false
	}
	s.streak(e.IA).promote = 0
	slog.Info("Link joined by rendezvous", "neighbor", e.IA, "why", why,
		"interface", entry.IfID, "local", entry.Local, "remote", entry.Remote)
	return true
}

// establishByRendezvous lands a promotion through the rendezvous exchange —
// the establishment a joiner with no paths uses. The reply must name the
// entry's ISD-AS: the published address can be a learned public host, and an
// answer arriving from a different node — a colliding subnet's real peer —
// must not mint an entry naming one ISD-AS at another's address.
func (s *selection) establishByRendezvous(
	ctx context.Context, e DirectoryEntry, entry *links.Link,
) bool {
	reply, _, err := s.echo(ctx, s.cfg.LinkHost, e.RendezvousAddr, s.cfg.IA, entry.Local)
	if err != nil {
		slog.Warn("The rendezvous establishment failed", "neighbor", e.IA, "err", err)
		return false
	}
	if !reply.IA.Equal(e.IA) {
		slog.Warn("The rendezvous reply names another ISD-AS than the entry",
			"neighbor", e.IA, "answered", reply.IA)
		return false
	}
	entry.Remote = reply.LinkAddr
	entry.RemoteIfID = reply.IfID
	if err := s.cfg.Store.Update(ctx, entry); err != nil {
		slog.Error("Recording the rendezvous establishment", "neighbor", e.IA, "err", err)
		return false
	}
	return true
}

// ownEntry returns the local side of a promoted candidate, recording a new
// one when the table holds none. The rendezvous acceptor and the in-band
// link service record entries too; the store refuses a neighbor's second
// live entry and a second live entry on one local address, and a promotion
// that loses either race looks again: it proceeds on the winner's entry, or
// records its own on a fresh address.
func (s *selection) ownEntry(ctx context.Context, e DirectoryEntry) (*links.Link, error) {
	entry, err := s.recordEntry(ctx, e)
	if errors.Is(err, links.ErrDuplicateNeighbor) || errors.Is(err, links.ErrDuplicateLocal) {
		entry, err = s.recordEntry(ctx, e)
	}
	return entry, err
}

// recordEntry returns the neighbor's live entry, inserting a candidate
// when the table holds none. The candidate takes the local address of the
// neighbor's latest retired entry while no live entry holds it, else a
// fresh one: the neighbor's side of a link this node retired stays
// established until the neighbor's own verdict retires it, its socket
// connected to that address, and its acceptor answers a rendezvous claim
// with that side unchanged.
func (s *selection) recordEntry(ctx context.Context, e DirectoryEntry) (*links.Link, error) {
	entry, err := s.cfg.Store.ByNeighbor(ctx, e.IA)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		return entry, nil
	}
	entries, err := s.cfg.Store.All(ctx)
	if err != nil {
		return nil, err
	}
	local, ok := retiredLocal(entries, e.IA)
	if !ok {
		if local, err = AllocateLinkAddr(s.cfg.LinkHost, entries); err != nil {
			return nil, err
		}
	}
	entry = &links.Link{
		NeighborIA: e.IA,
		Local:      local,
		Rendezvous: e.RendezvousAddr,
		State:      links.StateCandidate,
	}
	if err := s.cfg.Store.Insert(ctx, entry); err != nil {
		return nil, err
	}
	return entry, nil
}

// retiredLocal returns the local address of the neighbor's latest retired
// entry, unless a live entry holds it.
func retiredLocal(entries []*links.Link, ia addr.IA) (netip.AddrPort, bool) {
	var latest *links.Link
	for _, l := range entries {
		if l.Live() || !l.NeighborIA.Equal(ia) {
			continue
		}
		if latest == nil || l.Retired.After(latest.Retired) {
			latest = l
		}
	}
	if latest == nil || localHeld(entries, latest) {
		return netip.AddrPort{}, false
	}
	return latest.Local, true
}

// ratioOf scales a duration by one of the loop's ratios.
func ratioOf(d time.Duration, r float64) time.Duration {
	return time.Duration(r * float64(d))
}

// median returns the middle sample, zero for none.
func median(xs []time.Duration) time.Duration {
	if len(xs) == 0 {
		return 0
	}
	slices.Sort(xs)
	return xs[len(xs)/2]
}
