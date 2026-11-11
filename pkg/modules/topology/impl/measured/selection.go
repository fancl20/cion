package measured

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
)

// The selection loop's constants (no operator tuning). A node keeps at least
// NeighborFloor up links no single failure can partition it from, caps the
// count to bound beaconing fan-out, promotes a candidate whose direct link
// beats its own price, with confidence, by what the path policy moves a
// lease for, demotes a neighbor whose exclusion serves its tier and every
// member no worse, with confidence — a pair between the two keeps what it
// has — and holds both directions through windows of fresh evidence: every
// link change re-shapes segments network-wide.
const (
	// SelectionInterval is the evaluation window.
	SelectionInterval = 30 * time.Second
	// SelectionJitter spreads the windows of a network's nodes.
	SelectionJitter = 3 * time.Second
	// NeighborFloor is the least up links a node keeps.
	NeighborFloor = 2
	// MaxNeighbors caps the neighbor count.
	MaxNeighbors = 8
	// PromotionRatio and MarginFloor are what the coordination reads another
	// node's pair by on the round trips the nodes report: a direct link
	// beats the path between its ends by the ratio and by at least the
	// floor, a smaller gain being jitter on a fast link.
	PromotionRatio = 0.8
	// SecondRouteRatio: a second route for a single-route tier may lose to
	// the tier's price by it — redundancy purchased at a bounded latency
	// price.
	SecondRouteRatio = 1.25
	MarginFloor      = 2 * time.Millisecond
	// TierGap is the multiple of a tier's median direct round trip at which
	// a peer opens the next tier.
	TierGap = 2.0
	// PromoteWindows is the windows a beaten price's verdict stands through
	// before its promotion, the first counted.
	PromoteWindows = 2
	// PromoteJitter is the most windows a second-route promotion waits
	// beyond PromoteWindows: scion.StaleAfter's worth, the horizon in which
	// a link change plays out in every node's segments. Each pair of ends
	// draws its own share, so the nodes one change moves promote in turn,
	// and most see the first link's routes before their holds stand.
	PromoteJitter = int(scion.StaleAfter / SelectionInterval)
	// DemoteWindows is the windows a retirement's verdict stands through,
	// the first counted: a useless link's hold, a down verdict's count.
	DemoteWindows = 3
	// ProbeRuns is the probes per measurement run, each answered one a
	// sample of the instrument that sent it.
	ProbeRuns = 3
	// ProbeWait bounds the wait for each echo reply.
	ProbeWait = time.Second
	// SparseProbe is how often the window probes a candidate the clustering
	// holds in reserve: a third of scion.ReadingSpan, so that each reading
	// span holds two runs or more, past scion.ReadingSamples round trips,
	// and each bound span the fourteen an upper bound needs, while a window
	// lasts under a sixth of the reading span.
	SparseProbe = scion.ReadingSpan / 3
	// CandidateWindow is how long an unproven candidate lives: a peer whose
	// confirm never lands within it retires.
	CandidateWindow = time.Minute
	// EstablishTimeout bounds one in-band request: the link request of an
	// establishment or a confirm pass.
	EstablishTimeout = 5 * time.Second
	// ConfirmRetryPause spaces one confirm's retries: the first attempt can
	// race the generation swap the entry's own store write signals, and the
	// pause is the milliseconds the swap takes.
	ConfirmRetryPause = 100 * time.Millisecond
)

// LinkRequester establishes a link over the control endpoint's authenticated
// channel.
type LinkRequester interface {
	// Link asks the peer to admit the entry's link, offering the
	// requester's link address and interface ID, and answers the peer's
	// side of it.
	Link(ctx context.Context, peer *scion.Addr, l *links.Link) (*nodev1.LinkReply, error)
}

// SelectionPaths is the path resolution the selection loop calls: the
// composed paths with their facts, each one's health and reading among them.
type SelectionPaths interface {
	Enumerate(ctx context.Context, dst addr.IA) ([]scion.Candidate, error)
}

// SelectionConfig configures the selection loop.
type SelectionConfig struct {
	// IA is the local ISD-AS.
	IA addr.IA
	// Store is the neighbor table — the loop's decisions land in it.
	Store links.DB
	// Directory is the node directory topic, whose last event's views each
	// window draws its candidates from, every address the entries of every
	// directory name; nil draws none.
	Directory *bus.Topic[bus.Directory]
	// Links is the node's link state topic. An established neighbor whose
	// verdict is down counts as infinitely slow for the window whatever its
	// last sample said, and the redundancy floor counts up links only; a
	// confirm records the observed source of the link its reply arrived
	// over, where the peer's packets come from, else the reply's claim. A
	// nil topic treats every link as up and observes nothing.
	Links *bus.Topic[bus.LinkState]
	// Latencies is the node's link latency topic, which the selection
	// publishes each window's per-link one-way delay estimates on — each
	// neighbor's echo round trip halved — for the beaconer's entries to
	// declare; nil publishes none.
	Latencies *bus.Topic[bus.LinkLatencies]
	// NodeTags is the node tags topic, on which each window applies every
	// node's group — the members of a cluster share its name — for the
	// beaconer to carry the routes into it; nil applies none.
	NodeTags *bus.Topic[bus.NodeTags]
	// Paths composes the routes to each peer, with each one's health and
	// reading.
	Paths SelectionPaths
	// Requests is the node's path requests topic, on which each window
	// requests the routes it prices measured; nil requests nothing, and the
	// routes no other requester names stay unmeasured.
	Requests *bus.Topic[bus.PathRequests]
	// Conn carries the neighbors' SCMP echo probes and the service
	// resolution that names each neighbor's host for them; its port is the
	// reply address.
	Conn *scion.Conn
	// Sockets is the socket source the dials and the band probes construct
	// through; the zero value is the kernel's.
	Sockets underlay.Sockets
	// ControlHost is the control address's host: the host the loop's
	// probes leave from.
	ControlHost netip.Addr
	// LinkHost is the host link addresses are allocated on.
	LinkHost netip.Addr
	// Link establishes a link in-band.
	Link LinkRequester
	// Punch reaches the candidates whose published rendezvous address
	// answers nothing, by probe and by establishment; nil reaches none.
	Punch Puncher
	// Stranded, when set, records the window's finding that the node holds
	// fewer up links than the floor and no directory candidate answered its
	// probe — the flag the joiner's dial loop reads to re-dial the
	// rendezvous addresses the table already holds, retired entries
	// included. Nil discards the finding.
	Stranded *atomic.Bool
	// MaxLinks caps the neighbor count; zero uses MaxNeighbors.
	MaxLinks int
	// Report publishes each window's reports for the node's directory
	// entries: the cluster the node joined, and by directory every peer
	// measured there, with the round trip's bounds, and the changes the
	// node announced, naming no link; nil reports nothing.
	Report func(cluster addr.IA, peers map[bus.DirectoryID][]bus.PeerReport)
	// Changes is the node's journal of changes, to which the loop appends
	// the record of each link it promotes or retires, each promotion and
	// retirement it announces or withdraws, and each change of the cluster
	// it joined; nil records nothing.
	Changes *bus.Journal[bus.Change]
	// Interval and Window override the evaluation window and the candidate
	// window; zero keeps them. Tests pace the loop with them.
	Interval time.Duration
	Window   time.Duration
}

// RunSelection runs the topology loop until the context is canceled: each
// evaluation window it sweeps the candidates, measures every peer the
// directory names by its direct side — a candidate the clustering holds in
// reserve once per SparseProbe, from its history between — prices the
// routes into it by their health and reading, requests the routes it prices
// measured, classes the samples into tiers with their facts and excluded
// measurements, and lands promotion and retirement decisions in the link
// store — each change a data plane generation swap the node assembly's
// supervisor performs.
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
	// streaks count each established link's consecutive windows whose
	// verdict is down.
	streaks map[addr.IA]*peerStreak
	// windows counts the evaluation windows run: the clock the holds read,
	// one SelectionInterval a window.
	windows int
	// promotionHolds hold each candidate's priced promotion, and
	// retirementHolds each link's useless retirement, until the verdict has
	// stood for its windows with a fresh sample of both sides.
	promotionHolds  map[addr.IA]*evidence.Hold
	retirementHolds map[addr.IA]*evidence.Hold
	// promotions is what this window found of each candidate's priced
	// cases, and useless of each established link's useless test.
	promotions map[addr.IA]promotion
	useless    map[addr.IA]uselessness
	// tiers holds the last window's tiers as its walk classed them, their
	// members alone, from which the next walk keeps each peer's side.
	tiers []tier
	// upLeft records that an up link left this window, by retirement or
	// eviction: each departure changes the routes every other exclusion was
	// measured against, so one up link leaves per window.
	upLeft bool
	// hosts are the hosts the neighbors' own resolution named this window,
	// the ones their echoes address; each window asks anew.
	hosts map[addr.IA]netip.Addr
	// coord is the coordination's state across windows.
	coord coordState
	// cluster names the cluster the node joined, zero for none.
	cluster addr.IA
	// history holds the outcomes of each instrument's probes of its peer
	// within scion.BoundSpan, oldest first, and last names the instrument
	// that read each peer last.
	history map[instrument][]heard
	last    map[addr.IA]instrument
	// reserve holds the peers the last window's clustering holds in reserve
	// — the node links them only for the floor or a stranded tier — and
	// runs each candidate's last answered run.
	reserve map[addr.IA]bool
	runs    map[addr.IA]run
	// failed holds each candidate's last establishment failure, so a
	// failure repeating window after window warns once.
	failed map[addr.IA]string
	// probeFn, aliveFn, establishFn, and rendezvousFn override the
	// measurement, the candidate-grace probe, the establishment, and the
	// binding request to a rendezvous socket in tests; nil uses the real
	// ones.
	probeFn      func(context.Context, target, *links.Link) sample
	aliveFn      func(*links.Link) bool
	establishFn  func(context.Context, target, string) *links.Link
	rendezvousFn func(context.Context, netip.AddrPort) (time.Duration, error)
}

// instrument names what probes a peer: the echoes over the link of the
// interface, the punch probe, or the binding requests to an address. Each
// keeps its own samples, so no reading mixes instruments but across a
// change of instrument.
type instrument struct {
	ia      addr.IA
	ifID    uint16
	punched bool
	at      netip.AddrPort
}

// heard is one probe's outcome, beside when: the round trip it took, or
// lost when no answer came.
type heard struct {
	at   time.Time
	rtt  time.Duration
	lost bool
}

// outcomes is what one window's probes of a peer heard: the round trips
// answered, and how many probes no answer came for.
type outcomes struct {
	rtts []time.Duration
	lost int
}

// run is a candidate's answered run: when it went, and the address it
// probed.
type run struct {
	at time.Time
	to target
}

// target is a peer as the window probes and dials it: its ISD-AS, and one
// of the addresses its entries name, beside the directory whose entry names
// it.
type target struct {
	IA addr.IA
	// Scope is the directory whose entry names the address.
	Scope bus.DirectoryID
	bus.Address
}

// peer is one peer the views name: its ISD-AS, and each address its entries
// name.
type peer struct {
	IA      addr.IA
	targets []target
}

// peerStreak counts an established link's consecutive windows whose verdict
// is down: liveness judges its protocol's silence, which a count of windows
// weighs.
type peerStreak struct {
	down int
}

// promotion is what a window found of a candidate's priced cases: the
// beaten price's verdict and the price it weighed, and whether the hold of
// each case stands.
type promotion struct {
	beaten     evidence.Verdict
	price      evidence.Estimate
	beatenHeld bool
	secondHeld bool
}

// uselessness is what a window found of an established link's useless test:
// its verdict, and whether its hold stands.
type uselessness struct {
	verdict evidence.Verdict
	held    bool
}

// sample is one peer's window record: its direct side beside the routes to
// it, whose health and readings the tier's route counts and prices read.
type sample struct {
	// direct is the direct side's reading: the reading of the probes of
	// the instrument that probed the peer this window within
	// scion.ReadingSpan, divided by their delivery — the SCMP echo over the
	// one-hop path for an established neighbor, the binding request for a
	// candidate, the punch probe for a candidate no binding request
	// reaches. Zero when none of the window's probes answered.
	direct time.Duration
	// lo and hi bound the direct side's round trip over the instrument's
	// last scion.BoundSamples probes within scion.BoundSpan; zero where they
	// give no bound, and when none of the window's probes answered.
	lo, hi time.Duration
	// reading and bounds are the estimates the direct side's reading and
	// its bounds come from, as scion.ReadingEstimate and
	// scion.BoundsEstimate read the instrument's probes; zero when none of
	// the window's probes answered.
	reading, bounds evidence.Estimate
	// candidates are the routes to the peer, each one's cost its reading.
	candidates []scion.Candidate
	// baseline points into candidates at the peer's freshest clean route,
	// which the window requests priced; nil when no clean route resolves.
	baseline *scion.Candidate
}

// pass runs one evaluation window. A context that ends mid-window cuts the
// probes short, and their samples land nothing.
func (s *selection) pass(ctx context.Context) {
	if s.streaks == nil {
		s.streaks = make(map[addr.IA]*peerStreak)
	}
	s.windows++
	s.hosts = nil
	s.forget(time.Now())
	entries, err := s.cfg.Store.All(ctx)
	if err != nil {
		slog.Error("Selection reading the link store", "err", err)
		return
	}
	s.sweep(ctx, entries)

	neighbors := s.neighbors(entries) // established, by IA
	peers := s.peers()
	belowFloor := s.upCount(neighbors) < NeighborFloor

	// Probe every peer the views name — neighbor and candidate alike (the
	// comparator never stops at admission) — each by its own carrier: the
	// neighbor's direct side over the one-hop path, the candidate's by
	// rendezvous echo at the address chosen among the ones its entries name.
	// A candidate the window probes sparsely is read from its history
	// between its runs.
	samples := make(map[addr.IA]sample)
	candidates := make([]target, 0, len(peers))
	for _, p := range peers {
		if p.IA.Equal(s.cfg.IA) {
			continue
		}
		if l, ok := neighbors[p.IA]; ok {
			delete(s.runs, p.IA)
			samples[p.IA] = s.measure(ctx, p.targets[0], l)
			continue
		}
		if t, ok := s.sparse(p, belowFloor); ok {
			candidates = append(candidates, t)
			samples[p.IA] = s.held(ctx, t)
			continue
		}
		t := s.choose(ctx, p)
		candidates = append(candidates, t)
		samples[p.IA] = s.measure(ctx, t, nil)
		s.ran(t, samples[p.IA])
	}
	ts := s.windowTiers(neighbors, samples)
	if ctx.Err() != nil {
		return
	}
	s.request(samples, ts)
	s.declare(neighbors, samples)
	if s.cfg.Stranded != nil {
		reachable := false
		for _, e := range candidates {
			if samples[e.IA].direct > 0 {
				reachable = true
				break
			}
		}
		// Below the floor, a node no directory candidate answers dials what
		// it knows.
		s.cfg.Stranded.Store(s.upCount(neighbors) < NeighborFloor && !reachable)
	}
	var directory bus.Directory
	if s.cfg.Directory != nil {
		directory = s.cfg.Directory.Latest()
	}
	v := newCoordView(directory)
	if joined, why := joinCluster(v, s.cfg.IA, s.cluster); joined != s.cluster {
		change := ClusterJoined
		if joined == 0 {
			change = ClusterLeft
		}
		s.record(change, s.cfg.IA.String(), clusterLabel(s.cluster), clusterLabel(joined), why)
		s.cluster = joined
	}
	v.units = newUnits(v, s.cfg.IA, s.cluster)
	s.reserve = s.reserved(v, samples)
	s.tagGroups(v)
	s.count(v, neighbors, samples, ts)
	s.promotions = make(map[addr.IA]promotion, len(candidates))
	for _, e := range candidates {
		s.weighPromotion(e.IA, samples, ts)
	}
	s.coord.observe(v, time.Now())
	s.upLeft = false
	s.promote(ctx, entries, neighbors, candidates, samples, ts, v)
	s.prune(ctx, entries, samples, ts, v)
	s.report(directory, peers, neighbors, candidates, samples)
}

// sweep settles the candidate entries: a peer that produced no confirmed
// link within the window retires — unless this window's probe of the
// candidate answers, for a peer that answers its rendezvous socket is alive
// and trying, exactly the joiner whose confirm is still in flight; it
// retires when it goes silent. Push became pull: the same UDP round trip to
// the same rendezvous socket the window's measurement already rides is now
// the grace's only evidence, and it is spent on named candidates alone —
// an unnamed entry, a joiner's first claim no named dial followed, retires
// with the window, or the cap the unnamed entries count toward would fill
// with them. A candidate establishes by the authenticated link request
// alone — the confirm the establishment or the returning node's pass sends
// — never by the sweep's own reading.
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
		if now.Sub(l.Created) <= window {
			continue
		}
		// An echo the context's end cut short is no silence.
		if s.candidateAlive(ctx, l) || ctx.Err() != nil {
			continue
		}
		s.retire(ctx, l, verdict{why: "candidate window elapsed without a confirmed link"})
	}
}

// candidateAlive sends one binding request to the candidate's own
// rendezvous socket, through the test seam when set. An answer is a peer
// alive and trying; the request records nothing at the peer.
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
	_, err := s.probeRendezvous(ctx, target)
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

// probeRendezvous sends a binding request to a peer's rendezvous socket from
// an ephemeral port on the control host and returns the round trip, through
// the test seam when set: the acceptor answers it as it answers a dial, and
// records nothing.
func (s *selection) probeRendezvous(ctx context.Context, socket netip.AddrPort) (time.Duration, error) {
	if s.rendezvousFn != nil {
		return s.rendezvousFn(ctx, socket)
	}
	_, rtt, err := bindingEcho(ctx, s.cfg.Sockets, s.cfg.ControlHost, socket)
	return rtt, err
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
// candidates, the joiners' first claims, retire with the candidate window.
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

// linkUp reports the interface's verdict; a loop without the link state
// treats every link as up.
func (s *selection) linkUp(ifID uint16) bool {
	return s.cfg.Links.Latest().Up(ifID)
}

// peers returns each peer the directories' views name, ordered by ISD-AS,
// each with every address its entries name, ordered by directory ID and
// then as its entry orders them. A node holds only the addresses its
// directories' peers observed, so every one is the scope's to dial.
func (s *selection) peers() []peer {
	byIA := make(map[addr.IA]*peer)
	for _, sc := range s.cfg.Directory.Latest().Scopes() {
		for _, e := range sc.Entries() {
			for _, a := range e.Addresses {
				p, ok := byIA[e.IA]
				if !ok {
					p = &peer{IA: e.IA}
					byIA[e.IA] = p
				}
				p.targets = append(p.targets, target{IA: e.IA, Scope: sc.ID(), Address: a})
			}
		}
	}
	out := make([]peer, 0, len(byIA))
	for _, ia := range slices.Sorted(maps.Keys(byIA)) {
		out = append(out, *byIA[ia])
	}
	return out
}

// choose returns the address the window measures a candidate at: its only
// one; else, of those whose report says their rendezvous answers, the one
// whose binding request answers fastest; else the first whose report says
// it answers nothing, which the punch reaches; else the first.
func (s *selection) choose(ctx context.Context, p peer) target {
	if len(p.targets) == 1 {
		return p.targets[0]
	}
	var best target
	var bestRTT time.Duration
	found := false
	for _, t := range p.targets {
		if t.Reach.RendezvousUnanswered {
			continue
		}
		if rtt, err := s.probeRendezvous(ctx, t.RendezvousAddr); err == nil && (!found || rtt < bestRTT) {
			best, bestRTT, found = t, rtt, true
		}
	}
	if found {
		return best
	}
	if s.cfg.Punch != nil {
		for _, t := range p.targets {
			if t.Reach.RendezvousUnanswered {
				return t
			}
		}
	}
	return p.targets[0]
}

// measure runs the window's probe of one peer — a nil neighbor entry means
// a candidate — through the test seam when set, and reads and bounds its
// direct side over the samples of the instrument that probed it. The seam's
// direct side is one probe, of the link's echoes for a neighbor and of the
// binding requests to the target's address for a candidate: answered at the
// seam's round trip, lost where it is zero; a seam that reads the direct
// side's estimates itself sets them instead.
func (s *selection) measure(
	ctx context.Context, e target, l *links.Link,
) sample {
	if s.probeFn == nil {
		sm, by, got := s.probe(ctx, e, l)
		sm.readDirect(s.read(by, got, time.Now()))
		return sm
	}
	sm, by := s.probeFn(ctx, e, l), instrument{ia: e.IA, at: e.RendezvousAddr}
	if l != nil {
		by = instrument{ia: e.IA, ifID: l.IfID}
	}
	got := outcomes{lost: 1}
	if sm.direct > 0 {
		got = outcomes{rtts: []time.Duration{sm.direct}}
	}
	reading, bounds := s.read(by, got, time.Now())
	if sm.bounds.Answered > 0 {
		reading, bounds = sm.reading, sm.bounds
	}
	sm.readDirect(reading, bounds)
	return sm
}

// sparse returns the address of a candidate the window probes sparsely and
// reads from its history now, and whether it is one: the last window's
// clustering held the candidate in reserve, the node's up links meet the
// floor, and the candidate's last run answered, less than SparseProbe ago,
// at an address its entries still name.
func (s *selection) sparse(p peer, belowFloor bool) (target, bool) {
	r, ok := s.runs[p.IA]
	if !ok || belowFloor || !s.reserve[p.IA] || time.Since(r.at) >= SparseProbe ||
		!slices.Contains(p.targets, r.to) {
		return target{}, false
	}
	return r.to, true
}

// ran records a candidate's run: an answered one starts its wait for the
// next, and an unanswered one leaves it none, so the next window probes it
// again.
func (s *selection) ran(t target, sm sample) {
	if sm.direct == 0 {
		delete(s.runs, t.IA)
		return
	}
	if s.runs == nil {
		s.runs = make(map[addr.IA]run)
	}
	s.runs[t.IA] = run{at: time.Now(), to: t}
}

// held reads a candidate the window does not probe now: the reading and
// bounds of the probes its last instrument holds, beside the routes to it
// as a probe enumerates them.
func (s *selection) held(ctx context.Context, t target) sample {
	sm := s.routes(ctx, t.IA)
	sm.readDirect(readingOf(s.history[s.last[t.IA]], time.Now()))
	return sm
}

// read adds the window's outcomes to the instrument's samples, its round
// trips and its losses, drops those taken more than scion.BoundSpan before
// now, and returns their estimates as readingOf returns them; zeros when
// none of the window's probes answered. An instrument holding no sample
// within the reading's span starts from those of the instrument that read
// the peer last, samples of the same peer: a link reads on from the binding
// requests that promoted it, and a retired link's peer from the link's
// echoes, rather than from one window's samples alone.
func (s *selection) read(by instrument, got outcomes, now time.Time) (reading, bounds evidence.Estimate) {
	if s.history == nil {
		s.history = make(map[instrument][]heard)
		s.last = make(map[addr.IA]instrument)
	}
	stale := func(h heard) bool { return now.Sub(h.at) > scion.BoundSpan }
	recent := func(h heard) bool { return now.Sub(h.at) <= scion.ReadingSpan }
	kept := slices.DeleteFunc(slices.Clone(s.history[by]), stale)
	if !slices.ContainsFunc(kept, recent) {
		kept = slices.DeleteFunc(slices.Clone(s.history[s.last[by.ia]]), stale)
	}
	s.last[by.ia] = by
	for _, rtt := range got.rtts {
		kept = append(kept, heard{at: now, rtt: rtt})
	}
	for range got.lost {
		kept = append(kept, heard{at: now, lost: true})
	}
	if len(kept) == 0 {
		delete(s.history, by)
	} else {
		s.history[by] = kept
	}
	if len(got.rtts) == 0 {
		return evidence.Estimate{}, evidence.Estimate{}
	}
	return readingOf(kept, now)
}

// readingOf returns the estimates the direct side's reading and bounds come
// from over the outcomes heard before now, each divided by the delivery of
// its samples: the reading's, over those within scion.ReadingSpan, and the
// bounds', over the last scion.BoundSamples within scion.BoundSpan; zeros
// when no round trip lies within the reading's span.
func readingOf(hs []heard, now time.Time) (reading, bounds evidence.Estimate) {
	samples := make([]bus.PathSample, len(hs))
	for i, h := range hs {
		samples[i] = bus.PathSample{At: h.at, RTT: h.rtt, Lost: h.lost}
	}
	if reading = scion.ReadingEstimate(samples, now); reading.Answered == 0 {
		return evidence.Estimate{}, evidence.Estimate{}
	}
	return reading, scion.BoundsEstimate(samples, now)
}

// readDirect sets the direct side's estimates, and the reading and bounds
// they give.
func (sm *sample) readDirect(reading, bounds evidence.Estimate) {
	sm.reading, sm.bounds = reading, bounds
	sm.direct, sm.lo, sm.hi = 0, 0, 0
	if reading.Answered == 0 {
		return
	}
	sm.direct = reading.Value
	if bounds.HasLo {
		sm.lo = bounds.Lo
	}
	if bounds.HasHi {
		sm.hi = bounds.Hi
	}
}

// forget drops the instruments whose samples all lie more than
// scion.BoundSpan before now — the instruments of retired links and of
// addresses no longer probed — and the peers whose last instrument went,
// with their last establishment failure and their last run.
func (s *selection) forget(now time.Time) {
	for by, hs := range s.history {
		if now.Sub(hs[len(hs)-1].at) > scion.BoundSpan {
			delete(s.history, by)
		}
	}
	for ia, by := range s.last {
		if _, ok := s.history[by]; !ok {
			delete(s.last, ia)
		}
	}
	for ia := range s.failed {
		if _, ok := s.last[ia]; !ok {
			delete(s.failed, ia)
		}
	}
	for ia := range s.runs {
		if _, ok := s.last[ia]; !ok {
			delete(s.runs, ia)
		}
	}
}

// establishFailed logs a candidate's failed establishment: a warning when
// the failure differs from the candidate's last, a debug line while it
// repeats.
func (s *selection) establishFailed(ia addr.IA, msg string, err error) {
	failure := msg + ": " + err.Error()
	if s.failed[ia] == failure {
		slog.Debug(msg, "neighbor", ia, "err", err)
		return
	}
	if s.failed == nil {
		s.failed = make(map[addr.IA]string)
	}
	s.failed[ia] = failure
	slog.Warn(msg, "neighbor", ia, "err", err)
}

// establish lands a promotion, through the test seam when set, and returns
// the entry it seeded; nil when the promotion did not land.
func (s *selection) establish(ctx context.Context, e target, why string) *links.Link {
	if s.establishFn != nil {
		return s.establishFn(ctx, e, why)
	}
	return s.establishLink(ctx, e, why)
}

// probe measures one peer by the directory's own distinction: an established
// neighbor's direct side by SCMP echoes over the one-hop path — the conn
// resolving the egress interface from the link table as every one-hop write
// does, the responder in the peer's core answering on the reversed arrival
// path — a candidate's (a demoted neighbor included) by binding requests to
// its rendezvous socket, which reach where no path and no interface exist,
// and a candidate whose published rendezvous address answers nothing by the
// punch that opens both NATs between. A neighbor whose link the conn cannot
// send over — its verdict down — fails its writes at once, and answers
// nothing. The binding requests record nothing at the candidate. It returns
// the probes' outcomes and the instrument that took them, beside the routes
// to the peer; a punch probe that failed heard nothing, and one that ran
// lost the echoes of its ProbeRuns that never came.
func (s *selection) probe(ctx context.Context, e target, l *links.Link) (sample, instrument, outcomes) {
	var by instrument
	var got outcomes
	switch {
	case l != nil:
		by, got = instrument{ia: e.IA, ifID: l.IfID}, s.peerEchoes(ctx, e.IA)
	case s.punched(e):
		by = instrument{ia: e.IA, punched: true}
		rtts, err := s.cfg.Punch.Probe(ctx, e.IA, e.Scope)
		if err != nil {
			slog.Debug("The punch probe did not answer", "peer", e.IA, "err", err)
			break
		}
		got = outcomes{rtts: rtts, lost: ProbeRuns - len(rtts)}
	default:
		by, got = instrument{ia: e.IA, at: e.RendezvousAddr}, s.rendezvousSamples(ctx, e.RendezvousAddr)
	}
	return s.routes(ctx, e.IA), by, got
}

// routes enumerates the routes to the peer, each priced by its reading, its
// baseline the freshest clean one; none when the enumeration fails.
func (s *selection) routes(ctx context.Context, ia addr.IA) sample {
	var sm sample
	lookupCtx, cancel := context.WithTimeout(ctx, ProbeWait*ProbeRuns+time.Second)
	defer cancel()
	candidates, err := s.cfg.Paths.Enumerate(lookupCtx, ia)
	if err != nil {
		return sm
	}
	for i := range candidates {
		candidates[i].Cost = candidates[i].Reading
	}
	sm.candidates = candidates
	sm.baseline = s.freshest(candidates)
	return sm
}

// rendezvousSamples takes up to ProbeRuns binding requests to the
// rendezvous socket, the first unanswered one ending them, and returns their
// outcomes: the round trips answered, and the unanswered one lost. A request
// that failed before an answer could come ends them unrecorded.
func (s *selection) rendezvousSamples(ctx context.Context, socket netip.AddrPort) outcomes {
	var got outcomes
	for range ProbeRuns {
		rtt, err := s.probeRendezvous(ctx, socket)
		if errors.Is(err, errUnanswered) {
			got.lost++
		}
		if err != nil {
			break
		}
		got.rtts = append(got.rtts, rtt)
	}
	return got
}

// peerEchoes takes the SCMP echoes to the neighbor over the one-hop path
// the conn resolves, addressed to the host the neighbor's own resolution
// names, at the endhost port its responder binds beside the endpoint. A
// neighbor whose resolution goes unanswered measures nothing.
func (s *selection) peerEchoes(ctx context.Context, ia addr.IA) outcomes {
	if s.cfg.Conn == nil {
		return outcomes{}
	}
	host, ok := s.peerHost(ctx, ia)
	if !ok {
		return outcomes{}
	}
	return s.echoes(ctx, &scion.Addr{
		IA:   ia,
		Addr: netip.AddrPortFrom(host, underlay.EndhostPort),
	})
}

// peerHost returns the host the neighbor's own resolution names — the
// drafts' service resolution of its control service over the one-hop path
// the echo is about to ride, answered with the host its router delivers to —
// memoized for the window. The directory's published host is the peer as the
// network sees it, which behind a NAT no socket of the peer's holds. A
// resolution that goes unanswered memoizes nothing.
func (s *selection) peerHost(ctx context.Context, ia addr.IA) (netip.Addr, bool) {
	if host, ok := s.hosts[ia]; ok {
		return host, true
	}
	resolved, err := scionrpc.ResolveService(ctx, s.cfg.Conn,
		&scion.Addr{IA: ia, Service: addr.SvcCS})
	if err != nil {
		return netip.Addr{}, false
	}
	if s.hosts == nil {
		s.hosts = make(map[addr.IA]netip.Addr)
	}
	s.hosts[ia] = resolved.Addr()
	return resolved.Addr(), true
}

// selectionRequester names the selection's entries among the path requests.
const selectionRequester = "selection"

// request replaces the selection's path requests with the window's: each
// peer's baseline, the route each member is priced by with every link and
// without each up link, and each up link's freshest clean survivor, priced;
// and each peer's freshest ejected route fresher than its baseline,
// half-open at its retry, so a route that recovers counts again.
func (s *selection) request(samples map[addr.IA]sample, ts []tier) {
	if s.cfg.Requests == nil {
		return
	}
	now := time.Now()
	entries := make(map[addr.IA][]bus.PathRequest)
	add := func(dst addr.IA, c *scion.Candidate, role bus.PathRole, due time.Time) {
		if slices.ContainsFunc(entries[dst], func(r bus.PathRequest) bool { return r.ID == c.ID }) {
			return
		}
		entries[dst] = append(entries[dst], bus.PathRequest{
			ID: c.ID, Dst: dst, Links: c.Crossed, Path: c.Path, Role: role, Due: due, Picked: now,
		})
	}
	for ia, sm := range samples {
		if sm.baseline != nil {
			add(ia, sm.baseline, bus.PathPriced, time.Time{})
		}
	}
	for _, t := range ts {
		for _, m := range t.members {
			if c := t.cheapest[m.ia]; c != nil {
				add(m.ia, c, bus.PathPriced, time.Time{})
			}
		}
		for _, ex := range t.excluded {
			if ex.survivor != nil {
				add(ex.dst, ex.survivor, bus.PathPriced, time.Time{})
			}
			for _, m := range t.members {
				if c := ex.cheapest[m.ia]; c != nil {
					add(m.ia, c, bus.PathPriced, time.Time{})
				}
			}
		}
	}
	for ia, sm := range samples {
		if c := s.recovering(sm); c != nil {
			add(ia, c, bus.PathHalfOpen, c.Retry)
		}
	}
	s.cfg.Requests.Update(func(r bus.PathRequests) bus.PathRequests {
		return r.Replaced(selectionRequester, entries)
	})
}

// recovering returns the peer's freshest ejected route fresher than its
// baseline over none of the node's down links, nil when none is.
func (s *selection) recovering(sm sample) *scion.Candidate {
	var out *scion.Candidate
	for i := range sm.candidates {
		c := &sm.candidates[i]
		if c.Health != scion.HealthEjected || s.overDownLink(c) ||
			sm.baseline != nil && !c.Fresh.After(sm.baseline.Fresh) {
			continue
		}
		if out == nil || c.Fresh.After(out.Fresh) {
			out = c
		}
	}
	return out
}

// tagGroups applies the window's groups to the node tags: each node the view
// holds, and the node itself, by the cluster it names — the node's own by
// the window's naming, every other by its entry — a node naming none in no
// group.
func (s *selection) tagGroups(v *coordView) {
	if s.cfg.NodeTags == nil {
		return
	}
	groups := make(map[addr.IA]string, len(v.index)+1)
	for ia := range v.index {
		if c := v.clusters[ia]; c != 0 {
			groups[ia] = c.String()
		}
	}
	delete(groups, s.cfg.IA)
	if s.cluster != 0 {
		groups[s.cfg.IA] = s.cluster.String()
	}
	s.cfg.NodeTags.Update(func(t bus.NodeTags) bus.NodeTags { return t.With(bus.TagGroup, groups) })
}

// declare publishes the window's per-link one-way estimates, which the
// beaconer's entries declare: each neighbor's echo round trip halved — half
// a round trip is the node's estimate of the one-way delay the extension
// defines. A link the window did not measure declares nothing.
func (s *selection) declare(neighbors map[addr.IA]*links.Link, samples map[addr.IA]sample) {
	if s.cfg.Latencies == nil {
		return
	}
	estimates := make(map[uint16]time.Duration, len(neighbors))
	for ia, l := range neighbors {
		estimates[l.IfID] = samples[ia].direct / 2
	}
	s.cfg.Latencies.Publish(bus.NewLinkLatencies(estimates))
}

// echoes takes ProbeRuns SCMP echoes to the destination over the one-hop
// path the conn resolves and returns their outcomes; none without a probe
// conn. A run whose request the conn cannot send, as over a link whose
// verdict is down, is lost at once, and one whose request a router refuses
// with an interface-down signal at the signal rather than at ProbeWait. The
// context's end moves the read deadline to the past, ending a wait in
// flight; each run reads the context after setting its own deadline, so no
// run overrides the move unseen.
func (s *selection) echoes(ctx context.Context, dst *scion.Addr) outcomes {
	var got outcomes
	if s.cfg.Conn == nil {
		return got
	}
	stop := context.AfterFunc(ctx, func() { _ = s.cfg.Conn.SetReadDeadline(time.Now()) })
	defer stop()
	for seq := range uint16(ProbeRuns) {
		if err := s.cfg.Conn.SetReadDeadline(time.Now().Add(ProbeWait)); err != nil {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		sent := time.Now()
		if err := s.cfg.Conn.WriteEchoRequestTo(dst, seq, nil); err != nil {
			got.lost++
			continue
		}
		// The wait elapsing, the context ending, or a router refusing the
		// request loses the run.
		if _, _, err := s.cfg.Conn.ReadEchoReply(seq); err != nil {
			got.lost++
			continue
		}
		got.rtts = append(got.rtts, time.Since(sent))
	}
	return got
}

// promote applies the four admission cases in order, the first
// that fires establishing one link — every link change reshapes segments
// network-wide, so the window's budget is one establishment, as today.
// Below the floor of up links, reachability alone admits, the fastest
// reachable candidate the clustering allows, else the fastest. A stranded
// tier admits a reachable member at once, no hold, by the same
// preference — the clause that keeps every cut transient, for no up link
// reaches the tier and the measurements doubt every route into it, and the
// establishment rides the rendezvous exchange that reaches where no path
// does. A single-route tier admits a second member whose direct side beats
// the price by the room the second-route ratio leaves, and a candidate
// whose direct side beats its own price by the band is admitted — each
// priced case once its hold stands, the winner the fastest direct sample
// among those, and only among the candidates the clustering allows. At the
// cap every case requires an eviction that qualifies against the candidate,
// the floor and stranded cases included.
func (s *selection) promote(
	ctx context.Context,
	entries []*links.Link,
	neighbors map[addr.IA]*links.Link,
	candidates []target,
	samples map[addr.IA]sample,
	ts []tier,
	v *coordView,
) {

	live := s.upCount(neighbors)
	// Rank the reachable candidates: fastest first.
	var reachable []target
	for _, e := range candidates {
		if samples[e.IA].direct > 0 {
			reachable = append(reachable, e)
		}
	}
	sort.Slice(reachable, func(i, j int) bool {
		return samples[reachable[i].IA].direct < samples[reachable[j].IA].direct
	})

	if live < NeighborFloor {
		// Below the floor, reachability outranks latency: any reachable
		// candidate will do, the fastest first. With none, the shortfall is
		// reported against the floor capped at the peers the views name, one
		// sample each: a node linked to every peer they name has none.
		if len(reachable) == 0 {
			if live < min(NeighborFloor, len(samples)) {
				slog.Warn("Redundancy floor unmet; no reachable candidate",
					"neighbors", live, "floor", NeighborFloor, "named", len(samples))
			}
			return
		}
		e := s.preferAllowed(v, reachable, nil)
		s.admit(ctx, entries, neighbors, ts, samples, v, e, reachedVerdict("the redundancy floor", samples[e.IA]))
		return
	}

	// A stranded tier: its fastest reachable member, at once — the fastest
	// the clustering allows, else the fastest. The fastest candidate
	// overall that a stranded tier holds is that member, for the ranking is
	// global.
	stranded := func(e target) bool {
		t := tierOf(ts, e.IA)
		return t != nil && t.stranded
	}
	if slices.ContainsFunc(reachable, stranded) {
		e := s.preferAllowed(v, reachable, stranded)
		s.admit(ctx, entries, neighbors, ts, samples, v, e, reachedVerdict("its stranded tier", samples[e.IA]))
		return
	}

	// The priced cases, among the candidates the clustering allows — a
	// second route for a single-route tier first, redundancy purchased at a
	// bounded latency price, held for the pair's drawn windows, then any
	// beaten price — the fastest winner either way.
	for _, e := range reachable {
		t := tierOf(ts, e.IA)
		if t == nil || !s.allowed(v, e.IA) || !s.promotions[e.IA].secondHeld {
			continue
		}
		s.admit(ctx, entries, neighbors, ts, samples, v, e, secondRouteVerdict(t, samples[e.IA]))
		return
	}
	// The beaten prices: the fastest candidate whose direct side beats its
	// price and that waits on no other node's change is announced, and
	// promoted at a later window once its hold stands — every node reading
	// the announcement first.
	for _, e := range reachable {
		p := s.promotions[e.IA]
		if !s.allowed(v, e.IA) || p.beaten != evidence.Better {
			continue
		}
		if s.coord.waitsToPromote(v, s.cfg.IA, e.IA, samples[e.IA].candidates, time.Now()) {
			slog.Debug("Promotion waits on another node's change", "neighbor", e.IA)
			continue
		}
		beaten := beatenVerdict(samples[e.IA], p.price)
		if s.coord.promote != e.IA {
			s.withdrawPromotion(neighbors, reachable, samples, v, e.IA)
			s.coord.promote = e.IA
			s.record(PromotionAnnounced, e.IA.String(), "", "", beaten)
			return
		}
		if p.beatenHeld {
			s.admit(ctx, entries, neighbors, ts, samples, v, e, beaten)
		}
		return
	}
	s.withdrawPromotion(neighbors, reachable, samples, v, 0)
	s.coord.promote = 0
}

// weighPromotion weighs a candidate's priced cases this window: its direct
// side against its own price by the band, and against a single-route tier's
// price by the second-route room. A verdict better holds the candidate's
// promotion — the beaten price's for PromoteWindows windows, the second
// route's for the pair's drawn windows — on the direct side and the price
// it weighed; a window better in neither case releases it. An unmeasured or
// unclassed candidate weighs nothing.
func (s *selection) weighPromotion(ia addr.IA, samples map[addr.IA]sample, ts []tier) {
	sm, t := samples[ia], tierOf(ts, ia)
	var p promotion
	second := evidence.Undecided
	if sm.direct > 0 && t != nil {
		p.beaten, p.price = t.beats(ia, sm.bounds)
		second = t.secondRoute(sm.bounds)
	}
	defer func() { s.promotions[ia] = p }()
	if p.beaten != evidence.Better && second != evidence.Better {
		delete(s.promotionHolds, ia)
		return
	}
	price := p.price
	if price.Answered == 0 {
		price = t.estimate
	}
	h := hold(&s.promotionHolds, ia)
	if p.beaten == evidence.Better {
		p.beatenHeld = h.Stands(ia.String(), sm.bounds, price, windowsOf(PromoteWindows-1), s.clock())
	}
	if second == evidence.Better {
		p.secondHeld = h.Stands(ia.String(), sm.bounds, price, windowsOf(promoteWindows(s.cfg.IA, ia)-1), s.clock())
	}
}

// hold returns the hold a map keeps for the peer, made on first use.
func hold(holds *map[addr.IA]*evidence.Hold, ia addr.IA) *evidence.Hold {
	if *holds == nil {
		*holds = make(map[addr.IA]*evidence.Hold)
	}
	h, ok := (*holds)[ia]
	if !ok {
		h = new(evidence.Hold)
		(*holds)[ia] = h
	}
	return h
}

// clock returns the instant the holds read: the windows run, each one
// SelectionInterval, so that a hold counts windows however long each takes.
func (s *selection) clock() time.Time {
	return time.Time{}.Add(windowsOf(s.windows))
}

// windowsOf returns the span of n windows on the holds' clock.
func windowsOf(n int) time.Duration {
	return time.Duration(n) * SelectionInterval
}

// withdrawPromotion records the withdrawal of the promotion the node
// announced, for one of next or for none, beside what ended it: its peer no
// longer a reachable candidate, its link no longer allowed, its price no
// longer beaten, a wait on another node's change, or a faster candidate. A
// promotion that landed, its peer now a neighbor, ends without a record.
func (s *selection) withdrawPromotion(
	neighbors map[addr.IA]*links.Link,
	reachable []target,
	samples map[addr.IA]sample,
	v *coordView,
	next addr.IA,
) {

	old := s.coord.promote
	if old == 0 || old == next {
		return
	}
	if _, ok := neighbors[old]; ok {
		return
	}
	var why string
	switch {
	case !slices.ContainsFunc(reachable, func(e target) bool { return e.IA == old }):
		why = "its peer is no longer a reachable candidate"
	case !s.allowed(v, old):
		why = "the clusters no longer allow its link"
	case s.promotions[old].beaten != evidence.Better:
		why = "its direct link no longer beats its own price"
	case s.coord.waitsToPromote(v, s.cfg.IA, old, samples[old].candidates, time.Now()):
		why = "it waits on another node's change"
	default:
		why = "a faster candidate beats its own price"
	}
	s.record(PromotionWithdrawn, old.String(), "", "", verdict{why: why})
}

// allowed reports whether the window's clustering allows a link to the
// peer.
func (s *selection) allowed(v *coordView, ia addr.IA) bool {
	return v.units.allowed(v, s.cfg.IA, ia)
}

// reserved returns the peers the window measured that its clustering holds
// in reserve: the ones it does not let the node link.
func (s *selection) reserved(v *coordView, samples map[addr.IA]sample) map[addr.IA]bool {
	out := make(map[addr.IA]bool)
	for ia := range samples {
		if !s.allowed(v, ia) {
			out[ia] = true
		}
	}
	return out
}

// preferAllowed returns the first candidate that takes, among those the
// clustering allows, else among all; nil takes every candidate. The
// candidates are ranked and at least one takes.
func (s *selection) preferAllowed(v *coordView, ranked []target, takes func(target) bool) target {
	first := -1
	for i, e := range ranked {
		if takes != nil && !takes(e) {
			continue
		}
		if s.allowed(v, e.IA) {
			return e
		}
		if first < 0 {
			first = i
		}
	}
	return ranked[first]
}

// judge reads an up link's useless test, the neighbor's direct side given:
// the clustering's for a link it does not allow — better once it decides the
// link useless, not better once it decides otherwise — else the priced test.
func (s *selection) judge(v *coordView, t *tier, ia addr.IA, direct evidence.Estimate) evidence.Verdict {
	if s.allowed(v, ia) {
		return judge(t, ia, direct)
	}
	switch decided, useless := judgeOutside(t, ia, v.units.joined(v, s.cfg.IA, ia)); {
	case !decided:
		return evidence.Undecided
	case useless:
		return evidence.Better
	default:
		return evidence.NotBetter
	}
}

// yields reads whether an up link yields its slot to a candidate gaining
// gain on its price, the neighbor's direct side given: for a link the
// clustering does not allow, its useless test; for any other, a link that
// would not earn its place today, or one the gain outgains.
func (s *selection) yields(v *coordView, t *tier, ia addr.IA, direct, gain evidence.Estimate) bool {
	if !s.allowed(v, ia) {
		decided, useless := judgeOutside(t, ia, v.units.joined(v, s.cfg.IA, ia))
		return decided && useless
	}
	return yields(t, ia, direct) || outgained(t, ia, direct, gain)
}

// promoteWindows returns the windows the node's second-route promotion of
// the peer stands through: PromoteWindows plus the pair's draw of up to
// PromoteJitter, from SHA-256 over both ends' ISD-ASes. The draw never
// changes; the ISD-ASes' own random draws spread it across pairs.
func promoteWindows(self, peer addr.IA) int {
	b := binary.BigEndian.AppendUint64(nil, uint64(self))
	b = binary.BigEndian.AppendUint64(b, uint64(peer))
	sum := sha256.Sum256(b)
	return PromoteWindows + int(binary.BigEndian.Uint64(sum[:8])%uint64(PromoteJitter+1))
}

// admit lands a promotion, evicting at the cap first: the victim is the
// neighbor qualifying against what the candidate's direct round trip gains
// on its price, whose exclusion moves its tier's price least, and none
// qualifying means no promotion: the cap bounds the set at every instant.
// The cap counts the named live entries, as the acceptor's does, so a
// candidate in flight holds its place — the candidate's own included: an
// establishment its far end has not answered yet evicts nothing more when
// it runs again. A promotion that lands is recorded beside its verdict.
func (s *selection) admit(
	ctx context.Context,
	entries []*links.Link,
	neighbors map[addr.IA]*links.Link,
	ts []tier,
	samples map[addr.IA]sample,
	v *coordView,
	e target,
	admitted verdict,
) {

	cap := s.cfg.MaxLinks
	if cap == 0 {
		cap = MaxNeighbors
	}
	if namedLive(entries) >= cap && !liveNeighbor(entries, e.IA) {
		gain := tierOf(ts, e.IA).gain(e.IA, samples[e.IA].bounds)
		victim := s.evict(neighbors, ts, samples, v, gain)
		if victim == nil {
			return
		}
		up := s.linkUp(victim.IfID)
		if !s.retire(ctx, victim, evictedVerdict(e, admitted, victim, ts)) {
			return
		}
		s.upLeft = s.upLeft || up
	}
	if l := s.establish(ctx, e, admitted.why); l != nil {
		s.record(LinkPromoted, e.IA.String(), "", linkName(l.IfID), admitted)
	}
}

// evict returns the cap's victim among the qualifying neighbors: a down
// link whose down count reached DemoteWindows, at no harm, and, while up
// links exceed the floor, an up link this window decides yields to a
// candidate gaining gain on its price — one that would not earn its place
// today, one whose every saving the gain beats by the band, and one the
// clustering does not allow that the clustering's test judges useless.
// The victim is the one whose exclusion moves its tier's price least, ties
// to the slower direct sample. Nil when none qualifies — no promotion
// happens and the cap stands, so displacement cannot evict a link the
// policy must immediately re-recruit: the intra-regional mesh, whose
// exclusion changes nothing, retires first, and the bridge, whose exclusion
// leaves its tier no answered route, decides nothing and is not eligible at
// all.
func (s *selection) evict(
	neighbors map[addr.IA]*links.Link,
	ts []tier,
	samples map[addr.IA]sample,
	v *coordView,
	gain evidence.Estimate,
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
			if !s.yields(v, t, ia, samples[ia].bounds, gain) {
				continue
			}
			cost = harm(t, ia)
		}
		direct := samples[ia].direct
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

// count weighs each established link's retirement by the window's
// evidence. The down count grows in a window whose verdict is down and
// resets in one whose verdict is up. The useless test's verdict better
// holds the link's useless retirement for DemoteWindows windows, on the
// direct side and the survivors; any other window releases the hold, a down
// one included, which weighs nothing.
func (s *selection) count(v *coordView, neighbors map[addr.IA]*links.Link, samples map[addr.IA]sample, ts []tier) {
	s.useless = make(map[addr.IA]uselessness, len(neighbors))
	for ia, l := range neighbors {
		st := s.streak(ia)
		if !s.linkUp(l.IfID) {
			st.down++
			delete(s.retirementHolds, ia)
			continue
		}
		st.down = 0
		t, direct := tierOf(ts, ia), samples[ia].bounds
		u := uselessness{verdict: s.judge(v, t, ia, direct)}
		if u.verdict != evidence.Better {
			delete(s.retirementHolds, ia)
			s.useless[ia] = u
			continue
		}
		u.held = hold(&s.retirementHolds, ia).Stands(ia.String(), direct, t.excluded[ia].seen(ia),
			windowsOf(DemoteWindows-1), s.clock())
		s.useless[ia] = u
	}
}

// prune applies the two retirement rules. A link whose verdict stayed down
// for DemoteWindows windows retires, with no guard: a down link carries no
// route and is no redundancy. Then at most one up link retires as useless —
// none in a window whose eviction took an up link, for each departure
// changes the routes every other exclusion was measured against — and only
// while the up links this node dialed exceed the floor. Meanwhile each
// dialed link a window found useless is announced until a window finds it
// useful, with the links the routes its last useless window judged it by
// cross. Of the links announced since an earlier window whose useless hold
// stands, and whose judgment no other node's announced retirement would
// undo, the one whose exclusion moves its tier's price least retires, ties
// to the slower direct sample. A link a peer dialed is the peer's to judge,
// so the two ends' tiers never disagree over one link: at this end only its
// verdict or the cap's eviction retires it, and it never counts toward the
// floor this retirement guards, so a link a node accepted cannot free it to
// shed a link it dialed for its own floor. The useless test is measured
// each window and decides only when a route avoiding the link answered, so
// a cut-critical link never retires as useless; it weighs the prices
// promotion's priced cases weigh, against the line to keep rather than the
// line to buy. A link the clustering does not allow is judged by the
// clustering's test instead, whatever its prices.
func (s *selection) prune(
	ctx context.Context,
	entries []*links.Link,
	samples map[addr.IA]sample,
	ts []tier,
	v *coordView,
) {

	dialedUp := 0
	for _, l := range entries {
		if l.State != links.StateEstablished {
			continue
		}
		if s.linkUp(l.IfID) {
			if dialed(l) {
				dialedUp++
			}
			continue
		}
		if s.streak(l.NeighborIA).down >= DemoteWindows {
			s.retire(ctx, l, verdict{why: "its verdict stayed down"})
		}
	}
	if dialedUp <= NeighborFloor {
		s.withdrawRetirements(entries, nil, "the dialed links stand at the floor")
		clear(s.coord.retiring)
		return
	}
	announced := make(map[addr.IA]ownRetirement)
	var worst *links.Link
	var worstHarm, worstDirect time.Duration
	for _, l := range entries {
		ia := l.NeighborIA
		if l.State != links.StateEstablished || !dialed(l) {
			continue
		}
		u := s.useless[ia]
		r, ok := s.coord.retiring[ia]
		if u.verdict != evidence.Better && (!ok || u.verdict == evidence.NotBetter) {
			continue
		}
		t := tierOf(ts, ia)
		if !ok {
			r.since = s.coord.window
		}
		if u.verdict == evidence.Better {
			r.relies = reliance(t.excluded[ia])
		}
		if !ok {
			s.record(RetirementAnnounced, ia.String(), "", "",
				verdict{why: "a window found its link useless", weighed: uselessWeighed(t, ia, samples[ia])})
		}
		announced[ia] = r
		if s.upLeft || !u.held {
			continue
		}
		if r.since == s.coord.window || s.coord.waitsToRetire(v, s.cfg.IA, ia, r.relies) {
			slog.Debug("Retirement waits on another node's change", "neighbor", ia)
			continue
		}
		cost := harm(t, ia)
		direct := samples[ia].direct
		if worst == nil || cost < worstHarm ||
			cost == worstHarm && slower(direct, worstDirect) {
			worst, worstHarm, worstDirect = l, cost, direct
		}
	}
	if worst != nil {
		ia := worst.NeighborIA
		retired := verdict{
			why:     "its tier served no worse without it",
			weighed: uselessWeighed(tierOf(ts, ia), ia, samples[ia]),
		}
		if !s.allowed(v, ia) {
			retired = verdict{why: "the clusters link its units elsewhere"}
		}
		if s.retire(ctx, worst, retired) {
			s.upLeft = true
			delete(announced, ia)
		}
	}
	s.withdrawRetirements(entries, announced, "a window found its link useful")
	s.coord.retiring = announced
}

// withdrawRetirements records the withdrawal of each retirement the node
// announced that kept leaves out, beside why it ended; a link retired
// meanwhile, its entry no longer established, ends without a record.
func (s *selection) withdrawRetirements(entries []*links.Link, kept map[addr.IA]ownRetirement, why string) {
	for _, ia := range slices.Sorted(maps.Keys(s.coord.retiring)) {
		if _, ok := kept[ia]; ok {
			continue
		}
		if !slices.ContainsFunc(entries, func(l *links.Link) bool {
			return l.NeighborIA == ia && l.State == links.StateEstablished
		}) {
			continue
		}
		s.record(RetirementWithdrawn, ia.String(), "", "", verdict{why: why})
	}
}

// report publishes the window's reports, by directory: every peer the
// window measured, under the directory its link joins — else the one whose
// entry named the address the window probed — at its direct side's bounds
// estimate, each of the value and the bounds the one last reported unless
// the measurement moved past the step, beside the changes the node
// announced there. The reports name no link: the provider names each from
// the link state at the signing.
func (s *selection) report(
	directory bus.Directory,
	peers []peer,
	neighbors map[addr.IA]*links.Link,
	candidates []target,
	samples map[addr.IA]sample,
) {
	if s.cfg.Report == nil {
		return
	}
	scopes := make(map[addr.IA]bus.DirectoryID, len(peers))
	for _, p := range peers {
		if len(p.targets) > 0 {
			scopes[p.IA] = p.targets[0].Scope
		}
	}
	for _, t := range candidates {
		scopes[t.IA] = t.Scope
	}
	out := make(map[bus.DirectoryID][]bus.PeerReport)
	for ia, sm := range samples {
		if sm.direct == 0 {
			continue
		}
		r := bus.PeerReport{IA: ia, RTT: s.coord.reportRTT(ia, sm.bounds.Value), Promoting: ia == s.coord.promote}
		r.Low, r.High = s.coord.reportBounds(ia, sm.lo, sm.hi)
		if a, ok := s.coord.retiring[ia]; ok {
			r.Retiring, r.Relies = true, a.relies
		}
		scope := scopes[ia]
		if l, ok := neighbors[ia]; ok {
			if id, ok := directory.LinkScope(l.IfID); ok {
				scope = id
			}
		}
		out[scope] = append(out[scope], r)
	}
	for id := range out {
		slices.SortFunc(out[id], func(a, b bus.PeerReport) int { return cmp.Compare(a.IA, b.IA) })
	}
	s.cfg.Report(s.cluster, out)
}

// dialed reports whether this node dialed the link: the entries it dials
// record the peer's rendezvous address, and the ones a peer's dial lands on
// record none.
func dialed(l *links.Link) bool {
	return l.Rendezvous.IsValid()
}

// streak returns the peer's down count.
func (s *selection) streak(ia addr.IA) *peerStreak {
	st, ok := s.streaks[ia]
	if !ok {
		st = &peerStreak{}
		s.streaks[ia] = st
	}
	return st
}

// retire withdraws a link: its entry goes to retired, the interface ID held
// back until no unexpired segment can reference it, and the retirement is
// recorded beside its verdict.
func (s *selection) retire(ctx context.Context, l *links.Link, v verdict) bool {
	l.State = links.StateRetired
	l.Retired = time.Now()
	if err := s.cfg.Store.Update(ctx, l); err != nil {
		slog.Error("Retiring a link", "neighbor", l.NeighborIA, "err", err)
		return false
	}
	// The holds start over: a retired peer re-earns promotion from scratch,
	// and its demotion evidence is spent.
	delete(s.streaks, l.NeighborIA)
	delete(s.promotionHolds, l.NeighborIA)
	delete(s.retirementHolds, l.NeighborIA)
	s.record(LinkRetired, l.NeighborIA.String(), linkName(l.IfID), "", v)
	return true
}

// establishLink lands a promoted candidate: the rendezvous exchange seeds and
// names — the plaintext exchange beneath every path and every identity, the
// state it leaves the candidate the confirm waits on — or, for a candidate
// whose published rendezvous address answers nothing, the punch opens both
// NATs and seeds both sides; the authenticated link request over the seeded
// entry's one-hop path then establishes both sides, the peer's entry when the
// request lands and this one when the reply answers. An entry already holding
// its remote — seeded by an earlier window or the joiner's own dial — skips
// the exchange: the seed taught both sides already. It returns the entry it
// seeded; nil where no seed landed.
func (s *selection) establishLink(ctx context.Context, e target, why string) *links.Link {
	entry, err := s.ownEntry(ctx, e)
	if err != nil {
		slog.Error("Recording the local side of a promoted candidate",
			"neighbor", e.IA, "err", err)
		return nil
	}
	punched := s.punched(e)
	if !entry.Remote.IsValid() {
		seed := s.establishByRendezvous
		if punched {
			seed = s.establishByPunch
		}
		if !seed(ctx, e, entry) {
			return nil
		}
	}
	delete(s.promotionHolds, e.IA)
	delete(s.failed, e.IA)
	slog.Debug("Link seeded", "neighbor", e.IA, "why", why, "punched", punched,
		"interface", entry.IfID, "local", entry.Local, "remote", entry.Remote)
	s.confirm(ctx, e, entry, why)
	return entry
}

// establishByRendezvous seeds a promotion through the rendezvous exchange —
// the establishment a joiner with no paths uses, whose dial leaves from the
// entry's own link address so the mapping the acceptor observes is the
// socket that will serve. The reply must name the entry's ISD-AS: the
// published address can be a NAT's public host, and an answer arriving
// from a different node — a colliding subnet's real peer — must not seed an
// entry naming one ISD-AS at another's address. The reply's link address
// records under the claim rule, its port on the reply's observed source
// host when the answer names none; the entry stays the candidate the
// confirm waits on.
func (s *selection) establishByRendezvous(
	ctx context.Context, e target, entry *links.Link,
) bool {
	reply, observed, _, err := RendezvousEcho(ctx, s.cfg.Sockets, entry.Local, e.RendezvousAddr,
		s.cfg.IA, entry.Local)
	if err != nil {
		s.establishFailed(e.IA, "The rendezvous establishment failed", err)
		return false
	}
	if !reply.IA.Equal(e.IA) {
		slog.Warn("The rendezvous reply names another ISD-AS than the entry",
			"neighbor", e.IA, "answered", reply.IA)
		return false
	}
	entry.Remote = recordedLinkAddr(reply.LinkAddr, observed)
	entry.RemoteIfID = reply.IfID
	if err := s.cfg.Store.Update(ctx, entry); err != nil {
		slog.Error("Recording the rendezvous establishment", "neighbor", e.IA, "err", err)
		return false
	}
	return true
}

// establishByPunch seeds a promotion through the punch: the dial leaves from
// the entry's own link address, released before the entry records the peer's
// reflexive address, so the mapping each NAT opened is the one the link
// keeps. The entry stays the candidate the confirm waits on.
func (s *selection) establishByPunch(ctx context.Context, e target, entry *links.Link) bool {
	theirs, ifID, err := s.cfg.Punch.Establish(ctx, e.IA, e.Scope, entry)
	if err != nil {
		s.establishFailed(e.IA, "The punch establishment failed", err)
		return false
	}
	entry.Remote = theirs
	entry.RemoteIfID = ifID
	if err := s.cfg.Store.Update(ctx, entry); err != nil {
		slog.Error("Recording the punch establishment", "neighbor", e.IA, "err", err)
		return false
	}
	return true
}

// punched reports whether the loop reaches the candidate by punch: its own
// report says its published rendezvous address answers nothing.
func (s *selection) punched(e target) bool {
	return s.cfg.Punch != nil && e.Reach.RendezvousUnanswered
}

// confirm sends the entry's link request over the one-hop path of the link
// it confirms — the dial naming the entry's own interface, the egress the
// peer's own replies already take, so the link's verdict gates nothing: the
// confirm is the authenticated instrument that restores the locator a down
// verdict waits on, and the request's underlay source, the channel observes,
// is the peer's link socket and not a transit's address. The destination is
// the peer's control service: the receiving AS's own resolution names the
// endpoint, so the dial names no host of the peer it could spell wrong. The
// generation serves the seeded entry once the store write's signal has
// swapped it in, so the dial retries inside the establishment's bound; a
// confirm that never lands leaves the candidate to the window, the next
// window's promotion re-running it.
func (s *selection) confirm(
	ctx context.Context, e target, entry *links.Link, why string,
) bool {

	rpcCtx, cancel := context.WithTimeout(ctx, EstablishTimeout)
	defer cancel()
	peer := &scion.Addr{IA: e.IA, Service: addr.SvcCS}
	for {
		reply, err := s.cfg.Link.Link(rpcCtx, peer, entry)
		if err == nil {
			return s.landConfirm(rpcCtx, e.IA, entry, reply, e.ControlAddr.Addr(), why)
		}
		if rpcCtx.Err() != nil {
			s.establishFailed(e.IA, "The link request did not answer", err)
			return false
		}
		if !loops.Sleep(rpcCtx, ConfirmRetryPause) {
			return false
		}
	}
}

// landConfirm records the reply's side: the address the entry's own link
// observes the acceptor at — the reply rode that link, the authenticated
// channel proving who sent it — else the acceptor's claimed link address
// under the claim rule, beside the established state, the requester's
// answer to the possession the acceptor just recorded.
func (s *selection) landConfirm(
	ctx context.Context,
	ia addr.IA,
	entry *links.Link,
	reply *nodev1.LinkReply,
	published netip.Addr,
	why string,
) bool {

	remote, err := netip.ParseAddrPort(reply.LocalAddr)
	if err != nil {
		slog.Error("The link reply carries a malformed address", "err", err)
		return false
	}
	entry.Remote = observedOr(s.cfg.Links.Latest(), entry.IfID,
		recordedLinkAddr(remote, netip.AddrPortFrom(published, remote.Port())))
	entry.RemoteIfID = uint16(reply.IfId)
	entry.State = links.StateEstablished
	if err := s.cfg.Store.Update(ctx, entry); err != nil {
		slog.Error("Establishing a link", "neighbor", ia, "err", err)
		return false
	}
	slog.Info("Link established", "neighbor", ia, "why", why,
		"interface", entry.IfID, "local", entry.Local, "remote", entry.Remote)
	return true
}

// ownEntry returns the local side of a promoted candidate, recording a new
// one when the table holds none. The rendezvous acceptor and the in-band
// link service record entries too; the store refuses a neighbor's second
// live entry and a second live entry on one local address, and a promotion
// that loses either race looks again: it proceeds on the winner's entry, or
// records its own on a fresh address.
func (s *selection) ownEntry(ctx context.Context, e target) (*links.Link, error) {
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
// still aimed at that address, and its acceptor answers a rendezvous claim
// with that side unchanged.
func (s *selection) recordEntry(ctx context.Context, e target) (*links.Link, error) {
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
		if local, err = AllocateLinkAddr(s.cfg.Sockets, s.cfg.LinkHost, entries); err != nil {
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
