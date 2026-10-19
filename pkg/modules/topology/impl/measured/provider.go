// Package measured is the topology source's measured implementation: the
// rendezvous acceptor, the joiner's dials, the node directory, the in-band
// link service, and the selection loop. The node's assembly loads it by
// default — loading it is what makes a node zero-conf.
package measured

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/topology"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
	nodev1connect "github.com/fancl20/cion/proto/node/v1/nodev1connect"
)

// joinDialInterval paces the joiner's rendezvous dials: entries whose
// rendezvous has not answered yet are re-dialed until it does or the
// candidate window retires them.
const joinDialInterval = 5 * time.Second

// Config configures the measured provider with the pieces the node's
// identity completion and run arguments own; Wire delivers the rest, the
// products of the node's phases, before Seed, Mounts, and Run.
type Config struct {
	// Core marks the founding core: its draw is its network's name already,
	// and it serves the node directory from its own store.
	Core bool
	// Neighbors are the --topology.neighbor rendezvous addresses; a
	// non-core's first start needs at least one, later starts seed
	// additional entries, idempotent by remote address.
	Neighbors []string
	// Domain is the founding core's own identity — a domain the published
	// host resolves from, an address the published host is; the non-cores
	// learn theirs from the rendezvous exchange instead.
	Domain string
	// StateDir persists the learned external host beside the identity;
	// empty keeps it in memory alone.
	StateDir string
	// ControlHost is the control address's host: every socket binds it,
	// the rendezvous port and the probe claims among them.
	ControlHost netip.Addr
	// NewConn binds a SCION connection on an ephemeral port: the socket the
	// directory's publish and fetch ride on non-core nodes and the selection
	// probe's socket.
	NewConn func() (*scion.Conn, error)
	// CoreRoute resolves the core's endpoint, which the directory's client
	// rides on non-core nodes.
	CoreRoute func() *scion.Addr
	// Sockets is the socket source the acceptor's bind, the dials, and the
	// band probes construct through; the zero value is the kernel's.
	Sockets underlay.Sockets

	// Pacing shortens the loops' periods; zero values keep the production
	// constants. The daemon never sets it — the integration tests do.
	Pacing Pacing
}

// Pacing carries the test pacing of the provider's loops.
type Pacing struct {
	RendezvousRate  time.Duration // admission rate caps
	Directory       time.Duration // directory publish, its retry, and fetch
	Selection       time.Duration // selection evaluation window
	CandidateWindow time.Duration // unproven candidate lifetime
}

// Provider is the measured provider, the node's configuration source by
// default: loading it is what makes a node zero-conf.
type Provider struct {
	cfg Config
	env topology.Environment

	// external is the learned external host, persisted beside the identity
	// so a restart republishes it; domain resolves the founding core's own
	// published host from its identity.
	external externalHost
	domain   *domainHost

	// bootstrap is the first start's completed rendezvous, the seed it
	// taught both sides landing complete.
	bootstrap *bootstrapped

	// stranded records the selection loop's finding that no directory
	// candidate answered the window's probe: the joiner's dial loop then
	// re-dials the rendezvous addresses the table already holds, retired
	// entries included — the one address a stranded node independently
	// holds is worth more than an empty or expired directory snapshot.
	stranded atomic.Bool

	// mtx guards the one-time assembly of the serving machinery.
	mtx sync.Mutex
	// rendezvous, links, linker, directoryStore, directory, and the two
	// conns drawn through NewConn are the assembled machinery, built by
	// Mounts before Run.
	rendezvous     *Rendezvous
	links          *LinkService
	linker         *linkClient
	directoryStore *DirectoryStore
	directory      *NodeDirectory
	directoryConn  *scion.Conn
	probeConn      *scion.Conn
	assembled      bool
}

// New builds the measured provider, loading the learned external host a
// previous run persisted.
func New(cfg Config) (*Provider, error) {
	host, err := loadExternalHost(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	return &Provider{
		cfg: cfg,
		external: externalHost{
			path:    externalHostPath(cfg.StateDir),
			current: host,
		},
		domain: newDomainHost(cfg.Domain, cfg.ControlHost),
	}, nil
}

// externalHostPath returns the learned external host's file, empty for a
// stateless provider.
func externalHostPath(stateDir string) string {
	if stateDir == "" {
		return ""
	}
	return filepath.Join(stateDir, ExternalHostFile)
}

// learn records the external host a rendezvous reply observed for the node,
// logging a persistence failure — the loops that learn have no error to
// return.
func (z *Provider) learn(host netip.Addr) {
	if err := z.external.observe(host); err != nil {
		slog.Error("Persisting the learned external host", "err", err)
	}
}

// publishedHost resolves the host the node's own entry publishes: the
// learned external host when one is recorded, else the control host when it
// names one — under the wildcard bind the zero address, which publishes
// nothing until a host is learned. The founding core — which dials no
// rendezvous — resolves its own identity, its last good answer held through
// a failed resolution; before any has landed the zero address, which
// publishes nothing.
func (z *Provider) publishedHost(ctx context.Context) netip.Addr {
	if z.cfg.Core {
		return z.domain.resolve(ctx)
	}
	if host := z.external.host(); host.IsValid() {
		return host
	}
	if z.cfg.ControlHost.IsUnspecified() {
		return netip.Addr{}
	}
	return z.cfg.ControlHost
}

// PublishedHost resolves the host the node's publications carry — the node
// directory's entry and the applications' own — so every publication answers
// with one host: the learned one, else the bind host when it names one, the
// zero address publishing nothing.
func (z *Provider) PublishedHost(ctx context.Context) netip.Addr {
	return z.publishedHost(ctx)
}

// bootstrapped is what a first-start joiner's rendezvous taught it: the
// network's ISD, the neighbor's ISD-AS, and the link's addresses — the seed
// lands complete.
type bootstrapped struct {
	target netip.AddrPort
	reply  RendezvousReply
	local  netip.AddrPort
	// remote is the acceptor's link address under the claim rule, the side
	// the seed records.
	remote netip.AddrPort
}

// CompleteIdentity completes a first-start joiner's identity: the ISD of its
// draw is provisional, replaced by the network's — the answering neighbor's
// — so the enrollment's chains verify against the ISD's TRC. The first dial
// claims the zero ISD-AS — the identity is not final yet — and the second,
// with the completed one, names the acceptor's entry with it: identity
// adoption is the exchange's own act, both sides named before the link
// serves. The founding core's draw is its network's name already.
func (z *Provider) CompleteIdentity(ctx context.Context, ia addr.IA) (addr.IA, error) {
	if z.cfg.Core {
		return ia, nil
	}
	if len(z.cfg.Neighbors) == 0 {
		// Unreachable: a non-core's first start carries a neighbor.
		return ia, fmt.Errorf("a non-core's first start needs at least one --topology.neighbor")
	}
	// The store opens after the completed identity persists, and a first
	// start's table holds nothing: no entry holds a port yet.
	local, err := AllocateLinkAddr(z.cfg.Sockets, z.cfg.ControlHost, nil)
	if err != nil {
		return ia, err
	}
	for _, s := range z.cfg.Neighbors {
		target, err := ParseRendezvousAddr(s)
		if err != nil {
			return ia, fmt.Errorf("parsing --topology.neighbor %q: %w", s, err)
		}
		// Both dials bind the link address the seed will claim — the socket
		// that will serve — so the mapping the acceptor observes is the one
		// the link keeps; the socket is held for each round trip alone.
		reply, _, _, err := RendezvousEcho(ctx, z.cfg.Sockets, local, target, addr.IA(0), local)
		if err != nil {
			slog.Warn("The bootstrap neighbor's rendezvous did not answer",
				"rendezvous", target, "err", err)
			continue
		}
		if reply.IA.ISD() != ia.ISD() {
			if completed, err := addr.IAFrom(reply.IA.ISD(), ia.AS()); err != nil {
				return ia, err
			} else {
				slog.Info("Completed the identity with the network's ISD",
					"isd_as", completed, "provisional", ia)
				ia = completed
			}
		}
		// The named dial again, so the acceptor's entry carries the identity
		// the first claimed zero: a link whose entry names no neighbor
		// serves no beacons, and the exchange is the one place left to name
		// it. The reply re-answers the same entry's addresses.
		reply, observed, _, err := RendezvousEcho(ctx, z.cfg.Sockets, local, target, ia, local)
		if err != nil {
			return ia, fmt.Errorf("naming the bootstrap neighbor's entry: %w", err)
		}
		z.learn(reply.Observed.Addr())
		z.bootstrap = &bootstrapped{
			target: target,
			reply:  reply,
			local:  local,
			remote: recordedLinkAddr(reply.LinkAddr, observed),
		}
		return ia, nil
	}
	return ia, fmt.Errorf("no bootstrap neighbor answered its rendezvous; " +
		"retry once one does")
}

// Wire stores the phases' products for the machinery's assembly.
func (z *Provider) Wire(env topology.Environment) {
	z.env = env
}

// Seed seeds the store with an entry per --topology.neighbor, aimed at
// the given rendezvous address and idempotent by it: the joiner's dial loop retargets
// the entry when the reply arrives. Each seed's link address is drawn
// against the table as the earlier seeds left it. A non-core that holds no
// entry and names no neighbor could never link; it refuses to start.
func (z *Provider) Seed(ctx context.Context) error {
	entries, err := z.env.Store.All(ctx)
	if err != nil {
		return err
	}
	if !z.cfg.Core && len(z.cfg.Neighbors) == 0 && len(entries) == 0 {
		return fmt.Errorf("a non-core's first start needs at least one --topology.neighbor")
	}
	if len(z.cfg.Neighbors) == 0 {
		return nil
	}
	for _, s := range z.cfg.Neighbors {
		rendezvous, err := ParseRendezvousAddr(s)
		if err != nil {
			return fmt.Errorf("parsing --topology.neighbor %q: %w", s, err)
		}
		existing, err := z.env.Store.ByRemote(ctx, rendezvous)
		if err != nil {
			return err
		}
		if existing != nil {
			continue
		}
		if b := z.bootstrap; b != nil && b.target == rendezvous {
			// The bootstrap's dial already taught both sides: the seed lands
			// retargeted, the data plane's first generation serving it.
			seed := &links.Link{
				NeighborIA: b.reply.IA,
				Local:      b.local,
				Remote:     b.remote,
				RemoteIfID: b.reply.IfID,
				Rendezvous: rendezvous,
				State:      links.StateCandidate,
			}
			if err := z.env.Store.Insert(ctx, seed); err != nil {
				return err
			}
			entries = append(entries, seed)
			slog.Info("Seeded the bootstrapped neighbor", "neighbor", b.reply.IA,
				"rendezvous", rendezvous)
			continue
		}
		local, err := AllocateLinkAddr(z.cfg.Sockets, z.cfg.ControlHost, entries)
		if err != nil {
			return err
		}
		seed := &links.Link{
			Local:      local,
			Rendezvous: rendezvous,
			State:      links.StateCandidate,
		}
		if err := z.env.Store.Insert(ctx, seed); err != nil {
			return err
		}
		entries = append(entries, seed)
		slog.Info("Seeded a bootstrap neighbor", "rendezvous", rendezvous)
	}
	return nil
}

// assemble builds the serving machinery once: the acceptor every node
// serves, the in-band link service, the directory — the core's store and
// service beside every node's publish and fetch — and the selection probe
// socket.
func (z *Provider) assemble() error {
	z.mtx.Lock()
	defer z.mtx.Unlock()
	if z.assembled {
		return nil
	}
	rendezvous, err := NewRendezvous(RendezvousConfig{
		Bind:        netip.AddrPortFrom(z.cfg.ControlHost, RendezvousPort).String(),
		IA:          z.env.IA,
		MinInterval: z.cfg.Pacing.RendezvousRate,
		Store:       z.env.Store,
		MaxLinks:    MaxNeighbors,
		LinkHost:    z.cfg.ControlHost,
		Sockets:     z.cfg.Sockets,
	})
	if err != nil {
		return err
	}
	z.rendezvous = rendezvous
	z.links = &LinkService{
		Store:       z.env.Store,
		MaxLinks:    MaxNeighbors,
		LinkHost:    z.cfg.ControlHost,
		MinInterval: z.cfg.Pacing.RendezvousRate,
		Sockets:     z.cfg.Sockets,
		Observed:    z.env.Observed,
	}
	z.linker = &linkClient{peer: z.env.Peer}
	directoryCfg := NodeDirectoryConfig{
		IA:              z.env.IA,
		Host:            z.publishedHost,
		Engine:          z.env.Engine,
		Paths:           z.env.Paths,
		PublishInterval: z.cfg.Pacing.Directory,
		PublishRetry:    z.cfg.Pacing.Directory,
		FetchInterval:   z.cfg.Pacing.Directory,
	}
	if z.cfg.Core {
		z.directoryStore = NewDirectoryStore()
		directoryCfg.Store = z.directoryStore
	} else {
		conn, err := z.cfg.NewConn()
		if err != nil {
			return err
		}
		z.directoryConn = conn
		directoryCfg.Conn = conn
		directoryCfg.CoreRoute = z.cfg.CoreRoute
	}
	z.directory = NewNodeDirectory(directoryCfg)
	if z.cfg.NewConn != nil {
		// The probe socket is the comparator's to lose: a bind that fails
		// logs and leaves the loop path-less, the rendezvous echoes still
		// measuring.
		if conn, err := z.cfg.NewConn(); err != nil {
			slog.Error("Binding the selection probe socket", "err", err)
		} else {
			z.probeConn = conn
		}
	}
	z.assembled = true
	return nil
}

// Mounts returns the measured provider's services: the in-band link service
// on every node, the node directory's beside it on the core.
func (z *Provider) Mounts() ([]scionrpc.Mount, error) {
	if err := z.assemble(); err != nil {
		return nil, err
	}
	path, handler := nodev1connect.NewLinkServiceHandler(z.links)
	mounts := []scionrpc.Mount{{Pattern: path, Handler: handler}}
	if z.directoryStore != nil {
		path, handler := nodev1connect.NewDirectoryServiceHandler(
			&DirectoryService{Store: z.directoryStore})
		mounts = append(mounts, scionrpc.Mount{Pattern: path, Handler: handler})
	}
	return mounts, nil
}

// Run owns the measured provider's loops until the context is canceled — the
// rendezvous acceptor, the joiner's dials, the node directory's publish and
// fetch, the selection sweep, and the confirm pass over the entries the node
// holds — and returns once every one has returned. Mounts assembled what the
// loops serve.
func (z *Provider) Run(ctx context.Context) {
	var wg sync.WaitGroup
	loops.Go(ctx, &wg, "rendezvous", z.rendezvous.Run)
	loops.Go(ctx, &wg, "join dials", z.runJoinDials)
	loops.Go(ctx, &wg, "node directory", z.directory.Run)
	loops.Go(ctx, &wg, "selection", func(ctx context.Context) {
		RunSelection(ctx, z.selectionConfig())
	})
	loops.Go(ctx, &wg, "confirm pass", z.runConfirmPass)
	wg.Wait()
}

// Close releases what Mounts bound, once Run has returned: the directory's
// transport, the two conns drawn through NewConn beneath it, and the
// acceptor's socket. A provider never assembled releases nothing.
func (z *Provider) Close() error {
	var errs []error
	if z.directory != nil {
		errs = append(errs, z.directory.Close())
	}
	for _, conn := range []*scion.Conn{z.directoryConn, z.probeConn} {
		if conn != nil {
			errs = append(errs, conn.Close())
		}
	}
	if z.rendezvous != nil {
		// Run closes the acceptor's socket before it returns.
		if err := z.rendezvous.Close(); !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// selectionConfig builds the topology loop's configuration from the
// provider's own pieces: the link store its decisions land in, the directory
// its candidates come from, the paths and conn its probes ride, and the
// monitor's verdicts its demotions read.
func (z *Provider) selectionConfig() SelectionConfig {
	return SelectionConfig{
		IA:          z.env.IA,
		Store:       z.env.Store,
		Directory:   z.directory.Entries,
		Verdicts:    z.env.Verdicts,
		Latencies:   z.env.Latencies,
		Paths:       z.env.Paths,
		Conn:        z.probeConn,
		ControlAddr: netip.AddrPortFrom(z.cfg.ControlHost, scionrpc.EndpointPort),
		LinkHost:    z.cfg.ControlHost,
		Sockets:     z.cfg.Sockets,
		Link:        z.linker,
		Learn:       z.learn,
		Stranded:    &z.stranded,
		Interval:    z.cfg.Pacing.Selection,
		Window:      z.cfg.Pacing.CandidateWindow,
	}
}

// runJoinDials dials the rendezvous of every entry still aimed at one: the
// reply retargets the entry to the acceptor's link address under the claim
// rule, and the first generation serves it.
func (z *Provider) runJoinDials(ctx context.Context) {
	for {
		z.dialJoins(ctx)
		if !loops.Sleep(ctx, joinDialInterval) {
			return
		}
	}
}

// dialJoins runs one pass of the joiner's dials. The reply names the
// joiner's own entry — the acceptor's ISD-AS — beside retargeting it, so
// both sides of the establishment are named before the link serves. A
// stranded node — the selection loop's window found it below the floor with
// no reachable candidate from the directory — dials what it knows: each
// retired entry revivable admits re-dials its peer's rendezvous socket too,
// and an answered re-dial revives the entry as a candidate, the state flip
// and the recorded sides, for the sweep to settle by the peer's evidence,
// exactly as it settles a joiner's. A revival keeps the entry's local
// address unless a live entry now holds it — a later allocation drew the
// retired entry's port — and then claims a fresh one, the address the
// revived entry serves. An answer naming a neighbor the table holds live
// revives nothing, and the store refuses to name a live entry after it:
// that entry retires, for its re-dials would retarget the peer's unproven
// entry for this node to an address no generation serves. A revival the
// store refuses — its neighbor or its address recorded live meanwhile —
// waits for the next pass. Each check reads the table as the pass's earlier
// revivals left it. An unanswered re-dial costs a UDP round trip and
// changes nothing.
func (z *Provider) dialJoins(ctx context.Context) {
	entries, err := z.env.Store.All(ctx)
	if err != nil {
		slog.Error("Reading the link store", "err", err)
		return
	}
	stranded := z.stranded.Load()
	for _, l := range entries {
		target := rendezvousTarget(l)
		if !target.IsValid() {
			continue
		}
		revival := !l.Live()
		if !revival {
			if l.Remote.IsValid() {
				continue // retargeted already: waiting on the peer's evidence
			}
		} else if !stranded || !revivable(entries, l) {
			continue
		}
		local := l.Local
		if revival && localHeld(entries, l) {
			fresh, err := AllocateLinkAddr(z.cfg.Sockets, z.cfg.ControlHost, entries)
			if err != nil {
				slog.Error("Allocating a revived entry's link address", "err", err)
				continue
			}
			local = fresh
		}
		// The dial binds the entry's link address — the socket that will
		// serve — held for the round trip alone: the mapping the acceptor
		// observes is the one the entry keeps.
		reply, observed, _, err := RendezvousEcho(ctx, z.cfg.Sockets, local, target, z.env.IA, local)
		if err != nil {
			slog.Debug("Rendezvous dial", "rendezvous", target, "err", err)
			continue
		}
		z.learn(reply.Observed.Addr())
		if revival && liveNeighbor(entries, reply.IA) {
			slog.Debug("Rendezvous revival answered by a live neighbor",
				"rendezvous", target, "neighbor", reply.IA)
			continue
		}
		l.Local = local
		l.NeighborIA = reply.IA
		l.Remote = recordedLinkAddr(reply.LinkAddr, observed)
		l.RemoteIfID = reply.IfID
		if revival {
			l.State = links.StateCandidate
		}
		err = z.env.Store.Update(ctx, l)
		if revival && (errors.Is(err, links.ErrDuplicateNeighbor) ||
			errors.Is(err, links.ErrDuplicateLocal)) {
			continue
		}
		if errors.Is(err, links.ErrDuplicateNeighbor) {
			l.State = links.StateRetired
			l.Retired = time.Now()
			if err := z.env.Store.Update(ctx, l); err != nil {
				slog.Error("Retiring a redundant entry", "err", err)
				continue
			}
			slog.Info("Retired an entry whose rendezvous answered for a live neighbor",
				"neighbor", l.NeighborIA, "interface", l.IfID)
			continue
		}
		if err != nil {
			slog.Error("Retargeting a seeded neighbor", "err", err)
			continue
		}
		slog.Info("Joined a neighbor by rendezvous",
			"neighbor", l.NeighborIA, "local", l.Local, "remote", l.Remote,
			"interface", l.IfID)
	}
}

// runConfirmPass re-reaches the entries the node holds: a returning node's
// start and a first start's identity completion confirm every entry over its
// one-hop path, the dial the establishment already makes, and each answered
// request leaves a confirm behind it — the far side polls nothing. Entries
// the pass cannot yet reach retry on the selection's cadence until they
// answer or retire, and the pass ends once every held entry has answered.
// The exchange's replies retarget the returning node's own entries on the
// way, as the join dials already do, and the enrollment is never re-run.
func (z *Provider) runConfirmPass(ctx context.Context) {
	interval := z.cfg.Pacing.Selection
	if interval == 0 {
		interval = SelectionInterval
	}
	// started marks the pass's first run, when every held entry is confirmed;
	// pending holds the interfaces whose confirm is still to land.
	started := false
	pending := make(map[uint16]bool)
	for {
		entries, err := z.env.Store.All(ctx)
		if err != nil {
			slog.Error("Reading the link store", "err", err)
		} else {
			for _, l := range entries {
				if !l.Live() || !l.Remote.IsValid() || l.NeighborIA.IsZero() {
					delete(pending, l.IfID)
					continue
				}
				if !started || pending[l.IfID] {
					if z.confirmEntry(ctx, l) {
						delete(pending, l.IfID)
					} else {
						pending[l.IfID] = true
					}
				}
			}
			started = true
		}
		if started && len(pending) == 0 {
			return
		}
		if !loops.Sleep(ctx, interval) {
			return
		}
	}
}

// confirmEntry sends one held entry's link request over the link's one-hop
// path — the peer's control service addressed by it, the channel resolving
// the egress from the link table — and lands the reply's side: the peer's
// recorded addresses, the claim rule's record, and the established state a
// candidate was waiting on.
func (z *Provider) confirmEntry(ctx context.Context, l *links.Link) bool {
	rpcCtx, cancel := context.WithTimeout(ctx, EstablishTimeout)
	defer cancel()
	peer := &scion.Addr{IA: l.NeighborIA, Service: addr.SvcCS}
	reply, err := z.linker.Link(rpcCtx, peer, l.Local, l.IfID)
	if err != nil {
		slog.Debug("The confirm pass did not answer", "neighbor", l.NeighborIA, "err", err)
		return false
	}
	remote, err := netip.ParseAddrPort(reply.LocalAddr)
	if err != nil {
		slog.Error("The link reply carries a malformed address", "err", err)
		return false
	}
	// The reply refreshes only what changed: an answered confirm of an
	// established entry whose side already matches writes nothing.
	if recorded := recordedLinkAddr(remote, claimFallback(l)); recorded != l.Remote ||
		uint16(reply.IfId) != l.RemoteIfID || l.State != links.StateEstablished {

		l.Remote = recorded
		l.RemoteIfID = uint16(reply.IfId)
		l.State = links.StateEstablished
		if err := z.env.Store.Update(ctx, l); err != nil {
			slog.Error("Recording a confirmed entry", "neighbor", l.NeighborIA, "err", err)
			return false
		}
	}
	slog.Info("Confirmed a held entry", "neighbor", l.NeighborIA,
		"local", l.Local, "remote", l.Remote, "interface", l.IfID)
	return true
}

// claimFallback returns the address a wildcard reply's record falls back
// to: the rendezvous the entry dialed, the address the entry itself proved
// answering, else the recorded remote.
func claimFallback(l *links.Link) netip.AddrPort {
	if l.Rendezvous.IsValid() {
		return l.Rendezvous
	}
	return l.Remote
}

// revivable reports whether a stranded node re-dials a retired entry. A
// named entry is re-dialed while no live entry names its neighbor, so a
// revival never doubles a live neighbor. An unnamed entry is re-dialed only
// when it records the rendezvous address it was seeded with: the entries a
// probe mints on the acceptor name no peer. Either waits while the named
// live entries fill the cap.
func revivable(entries []*links.Link, l *links.Link) bool {
	if namedLive(entries) >= MaxNeighbors {
		return false
	}
	if l.NeighborIA.IsZero() {
		return l.Rendezvous.IsValid()
	}
	return !liveNeighbor(entries, l.NeighborIA)
}

// localHeld reports whether a live entry other than l holds l's local
// address.
func localHeld(entries []*links.Link, l *links.Link) bool {
	for _, e := range entries {
		if e.IfID != l.IfID && e.Live() && e.Local == l.Local {
			return true
		}
	}
	return false
}

// linkClient establishes links in-band over the peer client's mutually
// verified one-hop channel — the drafts' client machinery consumed as a
// library, a client per peer keyed by its encoded authority so the transport
// reuses the connection. The one-hop dial is the point: the request rides
// the direct link of the entry it confirms, so the underlay source the
// peer's link observes is the requester's link socket and not a transit's
// address.
type linkClient struct {
	peer topology.PeerChannel

	mtx  sync.Mutex
	clts map[string]nodev1connect.LinkServiceClient
}

var _ LinkRequester = (*linkClient)(nil)

// Link asks the peer to admit the link, offering the requester's link
// address and interface ID, and answers the peer's side of it.
func (c *linkClient) Link(
	ctx context.Context,
	peer *scion.Addr,
	local netip.AddrPort,
	ifID uint16,
) (*nodev1.LinkReply, error) {

	authority := scionrpc.PeerAuthority(peer)
	c.mtx.Lock()
	if c.clts == nil {
		c.clts = make(map[string]nodev1connect.LinkServiceClient)
	}
	clt, ok := c.clts[authority]
	if !ok {
		clt = nodev1connect.NewLinkServiceClient(c.peer.OneHopClient(),
			"https://"+authority)
		c.clts[authority] = clt
	}
	c.mtx.Unlock()
	resp, err := clt.Request(ctx, connect.NewRequest(&nodev1.LinkRequest{
		LocalAddr: local.String(),
		IfId:      uint32(ifID),
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}
