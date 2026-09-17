package topology

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	"math"
	"net/netip"
	"sort"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/scion"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
)

// The selection loop's constants (ADR-0006: no operator tuning). A node keeps
// at least NeighborFloor neighbors no single failure can partition it from,
// caps the count to bound beaconing fan-out, promotes a candidate whose
// direct link is meaningfully faster than its composed paths, demotes a
// neighbor durably slower than its paths, and damp both directions to
// sustained evidence — every link change re-shapes segments network-wide.
const (
	// SelectionInterval is the evaluation window.
	SelectionInterval = 30 * time.Second
	// SelectionJitter spreads the windows of a network's nodes.
	SelectionJitter = 3 * time.Second
	// NeighborFloor is the least neighbors a node keeps.
	NeighborFloor = 2
	// MaxNeighbors caps the neighbor count.
	MaxNeighbors = 8
	// PromotionRatio: a direct link must beat the path baseline by it.
	PromotionRatio = 0.8
	// DemotionRatio: a direct link must lose to the path baseline by it.
	DemotionRatio = 1.25
	// PromoteWindows is the consecutive good windows a promotion needs.
	PromoteWindows = 2
	// DemoteWindows is the consecutive bad windows a demotion needs.
	DemoteWindows = 3
	// ProbeRuns is the echoes per measurement run; the median is the sample.
	ProbeRuns = 3
	// ProbeWait bounds the wait for each echo reply.
	ProbeWait = time.Second
	// CandidateWindow is how long an unproven candidate lives: a peer that
	// produces no verified beacon or enrollment within it retires.
	CandidateWindow = time.Minute
	// EstablishTimeout bounds one in-band link request.
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
	// Neighbors returns the neighbors learned from greetings by interface
	// ID, with their LastSeen — identity, however stale the arrivals. The
	// one recency derivation the loop makes of it is the candidate sweep's
	// grace, which reads LastSeen directly.
	Neighbors func() map[uint16]controlplane.Neighbor
	// Verdicts returns the health monitor's link verdicts by interface ID:
	// an established neighbor whose verdict is down counts as infinitely
	// slow for the window whatever its last sample said, and the redundancy
	// floor counts up links only. Nil treats every link as up.
	Verdicts func() map[uint16]bool
	// Provider resolves the freshest path to a candidate — the baseline.
	Provider *scion.PathProvider
	// Conn carries the SCMP echo probes; its port is the reply address.
	Conn *scion.Conn
	// ControlAddr is the node's own control address, claimed in probes.
	ControlAddr netip.AddrPort
	// LinkHost is the host link addresses are allocated on.
	LinkHost netip.Addr
	// Link establishes a link in-band.
	Link LinkRequester
	// Evidence reports whether a candidate's peer has proven itself — a
	// verified beacon or an enrollment the node has seen.
	Evidence func(*links.Link) bool
	// Changed is called once per pass that changed the table.
	Changed func()
	// MaxLinks caps the neighbor count; zero uses MaxNeighbors.
	MaxLinks int
	// Interval and Window override the evaluation window and the candidate
	// window; zero keeps them. Tests pace the loop with them.
	Interval time.Duration
	Window   time.Duration
}

// RunSelection runs the topology loop until the context is canceled: each
// evaluation window it sweeps the candidates, probes every peer the directory
// names by rendezvous echo against SCMP echo over the freshest path, and
// lands promotion and demotion decisions in the link store — each change a
// data plane generation swap the node assembly's supervisor performs.
func RunSelection(ctx context.Context, cfg SelectionConfig) {
	s := &selection{cfg: cfg}
	interval := cfg.Interval
	if interval == 0 {
		interval = SelectionInterval
	}
	for {
		if !sleepCtx(ctx, jitter(interval)) {
			return
		}
		s.pass(ctx)
	}
}

// jitter spreads evaluation windows by up to a fraction of the interval.
func jitter(interval time.Duration) time.Duration {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
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
	// probeFn and establishFn override the measurement and the
	// establishment in tests; nil uses the real ones.
	probeFn     func(context.Context, DirectoryEntry, *links.Link) measurement
	establishFn func(context.Context, DirectoryEntry, string) bool
}

type peerStreak struct {
	promote int
	demote  int
}

// measurement is one peer's probe sample.
type measurement struct {
	// direct is the direct side's median: the SCMP echo over the one-hop
	// path for an established neighbor, the rendezvous echo for a
	// candidate — one instrument over two carriers, each reaching where
	// the other cannot. Zero when unreachable.
	direct time.Duration
	// path is the baseline: the SCMP echo median over the freshest
	// resolved path; zero when no path answered.
	path time.Duration
}

// pass runs one evaluation window.
func (s *selection) pass(ctx context.Context) {
	if s.streaks == nil {
		s.streaks = make(map[addr.IA]*peerStreak)
	}
	entries, err := s.cfg.Store.All(ctx)
	if err != nil {
		slog.Error("Selection reading the link store", "err", err)
		return
	}
	changed := s.sweep(ctx, entries)

	neighbors := s.neighbors(entries) // established, by IA
	directory := s.directory()

	// Probe every peer the directory names — neighbor and candidate alike
	// (ADR-0006: the comparator never stops at admission) — each by its own
	// carrier: the neighbor's direct side over the one-hop path, the
	// candidate's by rendezvous echo.
	samples := make(map[addr.IA]measurement)
	candidates := make([]DirectoryEntry, 0, len(directory))
	for _, e := range directory {
		if e.IA.Equal(s.cfg.IA) || e.Private {
			continue
		}
		if l, ok := neighbors[e.IA]; ok {
			samples[e.IA] = s.measure(ctx, e, l)
			continue
		}
		candidates = append(candidates, e)
		samples[e.IA] = s.measure(ctx, e, nil)
	}
	// Damp the promotions: a candidate is promoted on sustained evidence
	// only, a flapping one never.
	for _, e := range candidates {
		if s.good(e.IA, samples[e.IA]) {
			s.streak(e.IA).promote++
		} else {
			s.streak(e.IA).promote = 0
		}
	}
	changed = s.promote(ctx, neighbors, candidates, samples) || changed
	changed = s.demote(ctx, entries, samples) || changed
	if changed && s.cfg.Changed != nil {
		s.cfg.Changed()
	}
}

// sweep settles the candidate entries: proven peers are established, and
// peers that produced no verified beacon or enrollment within the window
// retire — unless their greetings still arrive, for a peer that keeps
// greeting is alive and trying, exactly the joiner whose enrollment is
// still in flight; it retires when it goes silent. The grace reads LastSeen
// directly — a candidate has no serving link and no session, and the
// greeting stream is the one evidence of trying it offers.
func (s *selection) sweep(ctx context.Context, entries []*links.Link) bool {
	window := s.cfg.Window
	if window == 0 {
		window = CandidateWindow
	}
	changed := false
	now := time.Now()
	neighbors := s.freshNeighbors()
	greeted := func(l *links.Link) bool {
		n, ok := neighbors[l.IfID]
		return ok && now.Sub(n.LastSeen) < window
	}
	for _, l := range entries {
		if l.State != links.StateCandidate {
			continue
		}
		if s.cfg.Evidence != nil && s.cfg.Evidence(l) {
			l.State = links.StateEstablished
			if err := s.cfg.Store.Update(ctx, l); err != nil {
				slog.Error("Establishing a candidate", "neighbor", l.NeighborIA, "err", err)
				continue
			}
			delete(s.streaks, l.NeighborIA)
			slog.Info("Candidate proven; link established",
				"neighbor", l.NeighborIA, "interface", l.IfID)
			changed = true
		} else if now.Sub(l.Created) > window {
			if greeted(l) {
				continue
			}
			s.retire(ctx, l, "candidate window elapsed without a proven peer")
			changed = true
		}
	}
	return changed
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

// liveNeighbors counts the established entries whose verdict is up — the
// redundancy floor counts up links only, so established-but-down entries
// satisfy no floor and a node whose every neighbor went down promotes from
// the directory rather than resting on verdicts.
func (s *selection) liveNeighbors(entries []*links.Link) int {
	n := 0
	for _, l := range entries {
		if l.State == links.StateEstablished && s.linkUp(l.IfID) {
			n++
		}
	}
	return n
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

// measure runs the window's probe of one peer — a nil neighbor entry means
// a candidate — through the test seam when set.
func (s *selection) measure(
	ctx context.Context, e DirectoryEntry, l *links.Link,
) measurement {
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
// The baseline is the same SCMP echo instrument over the freshest resolved
// path: one destination, two routes, the same median-of-runs discipline.
// The echo claims the zero ISD-AS — a probe mints no entry a candidate
// sweep could mistake for a peer, and no identity the acceptor would admit
// against an allowlist — deduplicated by the control address it claims.
func (s *selection) probe(ctx context.Context, e DirectoryEntry, l *links.Link) measurement {
	var m measurement
	if l != nil {
		m.direct = s.echoRTT(&scion.Addr{
			IA:   e.IA,
			Addr: netip.AddrPortFrom(e.ControlAddr.Addr(), dataplane.EndhostPort),
		})
	} else if _, rtt, err := RendezvousEcho(ctx, s.cfg.ControlAddr.Addr(),
		e.RendezvousAddr, addr.IA(0), s.cfg.ControlAddr); err == nil {
		m.direct = rtt
	}
	probeCtx, cancel := context.WithTimeout(ctx, ProbeWait*ProbeRuns+time.Second)
	defer cancel()
	if path, err := s.cfg.Provider.Path(probeCtx, e.IA); err == nil {
		m.path = s.echoRTT(&scion.Addr{
			IA:   e.IA,
			Addr: netip.AddrPortFrom(e.ControlAddr.Addr(), dataplane.EndhostPort),
			Path: path,
		})
	}
	return m
}

// echoRTT takes the median SCMP echo round trip to the destination — over
// the one-hop path the conn resolves for a neighbor, over the supplied path
// for the baseline. Zero without a probe conn.
func (s *selection) echoRTT(dst *scion.Addr) time.Duration {
	if s.cfg.Conn == nil {
		return 0
	}
	var rtts []time.Duration
	for seq := uint16(0); seq < ProbeRuns; seq++ {
		sent := time.Now()
		if err := s.cfg.Conn.WriteEchoRequestTo(dst, seq, nil); err != nil {
			continue
		}
		if err := s.cfg.Conn.SetReadDeadline(time.Now().Add(ProbeWait)); err != nil {
			continue
		}
		for {
			echo, _, err := s.cfg.Conn.ReadEchoFrom()
			if err != nil {
				break // the wait elapsed: lost
			}
			if !echo.Reply || echo.Identifier != s.cfg.Conn.LocalPort() || echo.Seq != seq {
				continue
			}
			rtts = append(rtts, time.Since(sent))
			break
		}
	}
	return median(rtts)
}

// promote applies the promotion rules: below the floor — counting up links
// only — any reachable candidate is promoted outright; above it a candidate
// must beat its path baseline by the promotion ratio across consecutive
// windows; at the cap it must also beat the worst neighbor by the same
// ratio to displace it.
func (s *selection) promote(
	ctx context.Context,
	neighbors map[addr.IA]*links.Link,
	candidates []DirectoryEntry,
	samples map[addr.IA]measurement,
) bool {

	cap := s.cfg.MaxLinks
	if cap == 0 {
		cap = MaxNeighbors
	}
	live := 0
	for _, l := range neighbors {
		if s.linkUp(l.IfID) {
			live++
		}
	}
	// Rank the candidates: reachable first, fastest first.
	var reachable []DirectoryEntry
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
		// candidate will do, the fastest first.
		if len(reachable) == 0 {
			slog.Warn("Redundancy floor unmet; no reachable candidate",
				"neighbors", live, "floor", NeighborFloor)
			return false
		}
		return s.establish(ctx, reachable[0], "the redundancy floor")
	}
	if live >= cap {
		// At the cap, a candidate displaces the worst neighbor when it beats
		// it by the promotion ratio with sustained evidence.
		var best *DirectoryEntry
		for i, e := range reachable {
			if s.streak(e.IA).promote >= PromoteWindows {
				best = &reachable[i]
				break
			}
		}
		if best == nil {
			return false
		}
		worst := s.worstNeighbor(neighbors, samples)
		if worst == nil || samples[best.IA].direct >= ratioOf(samples[worst.NeighborIA].direct, PromotionRatio) {
			return false
		}
		if !s.retire(ctx, worst, "displaced by a faster candidate") {
			return false
		}
		return s.establish(ctx, *best, "displacing the slowest neighbor")
	}

	// Between floor and cap: promote sustained winners.
	promoted := false
	for _, e := range reachable {
		if !s.good(e.IA, samples[e.IA]) {
			continue
		}
		streak := s.streak(e.IA)
		if streak.promote < PromoteWindows {
			continue
		}
		if s.establish(ctx, e, "its direct link beats the path baseline") {
			promoted = true
		}
		// One promotion per window keeps the generation swaps bounded.
		break
	}
	return promoted
}

// demote applies the demotion rules: a neighbor whose verdict is down —
// infinitely slow whatever its last sample said — or whose direct link
// durably loses to its path baseline retires, never below the floor. The
// floor here counts established entries — a bad link is still a link, held
// for its reversible verdict to recover — while the promotion floor counts
// up links only; the two readings are each honored for their own question.
func (s *selection) demote(
	ctx context.Context,
	entries []*links.Link,
	samples map[addr.IA]measurement,
) bool {

	live := 0
	neighbors := make(map[addr.IA]*links.Link)
	for _, l := range entries {
		if l.State == links.StateEstablished {
			live++
			neighbors[l.NeighborIA] = l
		}
	}
	if live <= NeighborFloor {
		// The floor holds: a bad link is still a link.
		for ia := range neighbors {
			s.streak(ia).demote = 0
		}
		return false
	}
	demoted := false
	for _, l := range entries {
		if l.State != links.StateEstablished {
			continue
		}
		if live <= NeighborFloor {
			// The floor holds at every instant: retire no further this
			// window, however many neighbors went bad in it.
			break
		}
		m := samples[l.NeighborIA]
		bad := false
		if !s.linkUp(l.IfID) {
			bad = true // the verdict is down: infinitely slow
		} else if m.direct > 0 && m.path > 0 && m.direct > ratioOf(m.path, DemotionRatio) {
			bad = true
		}
		streak := s.streak(l.NeighborIA)
		if bad {
			streak.demote++
		} else {
			streak.demote = 0
			continue
		}
		if streak.demote >= DemoteWindows {
			if s.retire(ctx, l, "its direct link durably loses to the path baseline") {
				demoted = true
				live--
			}
		}
	}
	return demoted
}

// good reports whether a candidate's sample beats its path baseline by the
// promotion ratio.
func (s *selection) good(ia addr.IA, m measurement) bool {
	return m.direct > 0 && m.path > 0 && m.direct < ratioOf(m.path, PromotionRatio)
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

// worstNeighbor returns the neighbor with the slowest direct sample — no
// sample counts as infinitely slow, and a down neighbor more so: the
// verdict outranks however recent its last sample was.
func (s *selection) worstNeighbor(
	neighbors map[addr.IA]*links.Link,
	samples map[addr.IA]measurement,
) *links.Link {

	slow := func(l *links.Link) time.Duration {
		if !s.linkUp(l.IfID) {
			return time.Duration(math.MaxInt64)
		}
		if d := samples[l.NeighborIA].direct; d > 0 {
			return d
		}
		return time.Duration(math.MaxInt64)
	}
	var worst *links.Link
	for _, l := range neighbors {
		if worst == nil || slow(l) > slow(worst) {
			worst = l
		}
	}
	return worst
}

// freshNeighbors returns the neighbors learned from greetings by interface
// ID, with their LastSeen — identity for whoever asks.
func (s *selection) freshNeighbors() map[uint16]controlplane.Neighbor {
	if s.cfg.Neighbors == nil {
		return nil
	}
	return s.cfg.Neighbors()
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
	reply, _, err := RendezvousEcho(ctx, s.cfg.LinkHost, e.RendezvousAddr,
		s.cfg.IA, entry.Local)
	if err != nil {
		slog.Warn("The rendezvous establishment failed", "neighbor", e.IA, "err", err)
		return false
	}
	entry.Remote = reply.LinkAddr
	entry.RemoteIfID = reply.IfID
	if err := s.cfg.Store.Update(ctx, entry); err != nil {
		slog.Error("Recording the rendezvous establishment", "neighbor", e.IA, "err", err)
		return false
	}
	s.streak(e.IA).promote = 0
	slog.Info("Link joined by rendezvous", "neighbor", e.IA, "why", why,
		"interface", entry.IfID, "local", entry.Local, "remote", entry.Remote)
	return true
}

// ownEntry returns the local side of a promoted candidate, allocating the
// link address and interface ID of a new one.
func (s *selection) ownEntry(ctx context.Context, e DirectoryEntry) (*links.Link, error) {
	entry, err := s.cfg.Store.ByNeighbor(ctx, e.IA)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		return entry, nil
	}
	local, err := AllocateLinkAddr(s.cfg.LinkHost)
	if err != nil {
		return nil, err
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

// ratioOf scales a duration by one of the loop's ratios.
func ratioOf(d time.Duration, r float64) time.Duration {
	return time.Duration(r * float64(d))
}

// median returns the middle sample, zero for none.
func median(xs []time.Duration) time.Duration {
	if len(xs) == 0 {
		return 0
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	return xs[len(xs)/2]
}
