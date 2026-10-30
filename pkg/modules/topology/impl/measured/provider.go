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
	"net/http"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/topology"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
	nodev1connect "github.com/fancl20/cion/proto/node/v1/nodev1connect"
)

// The joiner's rendezvous dials: entries whose rendezvous has not answered
// yet are re-dialed until it does or the candidate window retires them, a
// pass each joinDialInterval, each entry's re-dials backing off from it up
// to joinDialRetryMax.
const (
	joinDialInterval = 5 * time.Second
	joinDialRetryMax = 30 * time.Second
)

// confirmPassWindows caps the wait between an unanswered entry's confirms in
// the confirm pass, in selection windows.
const confirmPassWindows = 4

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
	// the rendezvous port and the probes' among them.
	ControlHost netip.Addr
	// NewConn binds a SCION connection on an ephemeral port: the socket the
	// directory's publish and fetch ride on non-core nodes, the selection
	// probe's socket, and the punch requests' socket.
	NewConn func() (*scion.Conn, error)
	// FounderRoute resolves the founding core's endpoint, which the
	// directory's client rides on non-core nodes.
	FounderRoute func() *scion.Addr
	// Sockets is the socket source the acceptor's bind, the dials, and the
	// band probes construct through, and the founding core's domain
	// resolves through; the zero value is the kernel's.
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
	// linkState is the node's link state topic on the environment's bus,
	// and directoryState its node directory topic.
	linkState      *bus.Topic[bus.LinkState]
	directoryState *bus.Topic[bus.Directory]

	// external is the learned external host, persisted beside the identity
	// so a restart republishes it; domain looks up the founding core's own
	// published host from its identity.
	external externalHost
	domain   *domainHost
	// self is the topic of the node's own state on the environment's bus;
	// selfMtx serializes the provider's updates of it, each published only
	// when it changes the state.
	self    *bus.Topic[bus.SelfState]
	selfMtx sync.Mutex

	// bootstrap is the first start's completed rendezvous, the seed it
	// taught both sides landing complete.
	bootstrap *bootstrapped

	// stranded records the selection loop's finding that no directory
	// candidate answered the window's probe: the joiner's dial loop then
	// re-dials the rendezvous addresses the table already holds, retired
	// entries included — the one address a stranded node independently
	// holds is worth more than an empty or expired directory snapshot.
	stranded atomic.Bool

	// joinDials paces each entry's rendezvous dials; the join dials loop
	// owns it.
	joinDials loops.Attempts[uint16]

	// mtx guards the one-time assembly of the serving machinery.
	mtx sync.Mutex
	// rendezvous, links, linker, puncher, directoryStore, directory, and
	// the three conns drawn through NewConn are the assembled machinery,
	// built by Mounts before Run.
	rendezvous     *Rendezvous
	links          *LinkService
	linker         *linkClient
	puncher        *puncher
	directoryStore *DirectoryStore
	directory      *NodeDirectory
	directoryConn  *scion.Conn
	probeConn      *scion.Conn
	punchConn      *scion.Conn
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
		domain: newDomainHost(cfg.Domain, cfg.ControlHost, cfg.Sockets.Lookup),
		joinDials: loops.Attempts[uint16]{
			Backoff: loops.Backoff{Base: joinDialInterval, Max: joinDialRetryMax},
		},
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
// return — and publishes it once the provider is wired. The founding core
// publishes its domain's address alone.
func (z *Provider) learn(host netip.Addr) {
	if err := z.external.observe(host); err != nil {
		slog.Error("Persisting the learned external host", "err", err)
	}
	if z.self != nil && !z.cfg.Core {
		z.updateSelf(func(s *bus.SelfState) { s.Host = z.knownHost() })
	}
}

// knownHost returns the host the node's publications carry as far as it is
// known without a lookup: the founding core's domain when the domain is an
// address, zero while a lookup answers for a name; a joiner's learned host,
// else the control host when it names one — under the wildcard bind the zero
// address, which publishes nothing until a host is learned.
func (z *Provider) knownHost() netip.Addr {
	if z.cfg.Core {
		return z.domain.literal
	}
	if host := z.external.host(); host.IsValid() {
		return host
	}
	if z.cfg.ControlHost.IsUnspecified() {
		return netip.Addr{}
	}
	return z.cfg.ControlHost
}

// updateSelf applies f to the node's own state and publishes the result when
// it changed.
func (z *Provider) updateSelf(f func(*bus.SelfState)) {
	z.selfMtx.Lock()
	defer z.selfMtx.Unlock()
	s := z.self.Latest()
	next := s
	f(&next)
	if next != s {
		z.self.Publish(next)
	}
}

// runDomain keeps the founding core's published host on its domain's
// address: it looks the domain up at once, again domainSuccessTTL after an
// answer and domainFailureTTL after a failure, and publishes each answer. A
// failed lookup holds the last answer.
func (z *Provider) runDomain(ctx context.Context) {
	for {
		wait := domainFailureTTL
		if host, ok := z.domain.lookupAddr(ctx); ok {
			z.updateSelf(func(s *bus.SelfState) { s.Host = host })
			wait = domainSuccessTTL
		}
		if !loops.Sleep(ctx, wait) {
			return
		}
	}
}

// behindNAT reports whether a NAT stands between the node and its peers at
// the published host: the host is not one of the node's own addresses.
func (z *Provider) behindNAT(host netip.Addr) (bool, error) {
	held, err := holds(z.cfg.Sockets, host)
	return !held, err
}

// recordAnswer publishes a link reply's report of the acceptor's echo at the
// node's published rendezvous address, the latest report winning.
func (z *Provider) recordAnswer(answered bool) {
	z.updateSelf(func(s *bus.SelfState) { s.RendezvousUnanswered = !answered })
}

// echoPublished sends a binding request to the peer's published rendezvous
// address as the selection loop's probe does — from an ephemeral port on the
// control host — and reports whether it answered; ok is false when the node
// directory holds no entry for the peer. The echo checks the peer alone: its
// answer teaches the node nothing of its own external host.
func (z *Provider) echoPublished(ctx context.Context, peer addr.IA) (answered, ok bool) {
	e, ok := z.directoryState.Latest().Entry(peer)
	if !ok {
		return false, false
	}
	_, _, err := bindingEcho(ctx, z.cfg.Sockets, z.cfg.ControlHost, e.RendezvousAddr)
	return err == nil, true
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
		z.learn(reply.Reflexive.Addr())
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

// Wire stores the phases' products for the machinery's assembly, and
// publishes the node's own state as the provider starts with it.
func (z *Provider) Wire(env topology.Environment) {
	z.env = env
	z.linkState = env.Bus.Links()
	z.directoryState = env.Bus.Directory()
	z.self = env.Bus.Self()
	z.self.Publish(bus.SelfState{Host: z.knownHost()})
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
	// The punch requests ride a conn of their own: the QUIC transport over
	// it reads every datagram the conn receives.
	punchConn, err := z.cfg.NewConn()
	if err != nil {
		return err
	}
	z.punchConn = punchConn
	z.puncher = &puncher{
		conn:      punchConn,
		engine:    z.env.Engine,
		paths:     z.env.Paths,
		reflector: z.reflector,
		sockets:   z.cfg.Sockets,
		host:      z.cfg.ControlHost,
	}
	z.links = &LinkService{
		Store:       z.env.Store,
		MaxLinks:    MaxNeighbors,
		LinkHost:    z.cfg.ControlHost,
		MinInterval: z.cfg.Pacing.RendezvousRate,
		Sockets:     z.cfg.Sockets,
		Links:       z.linkState,
		Echo:        z.echoPublished,
		Reflector:   z.reflector,
		Punching:    z.puncher.punching,
	}
	z.linker = &linkClient{peer: z.env.Peer, answered: z.recordAnswer}
	directoryCfg := NodeDirectoryConfig{
		IA:              z.env.IA,
		Self:            z.self,
		BehindNAT:       z.behindNAT,
		Directory:       z.directoryState,
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
		directoryCfg.FounderRoute = z.cfg.FounderRoute
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
// on every node, the node directory's beside it on the core. Both register
// on the one connect server, which connecthttp.Mount spreads over a private
// mux; the tuples carry each service name's canonical pattern with that mux
// as their handler.
func (z *Provider) Mounts() ([]scionrpc.Mount, error) {
	if err := z.assemble(); err != nil {
		return nil, err
	}
	server := connect.NewServer()
	nodev1connect.RegisterLinkServiceHandler(server, z.links)
	if z.directoryStore != nil {
		nodev1connect.RegisterDirectoryServiceHandler(server,
			&DirectoryService{Store: z.directoryStore})
	}
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	mounts := []scionrpc.Mount{{
		Pattern: "/" + nodev1connect.LinkServiceName + "/",
		Handler: mux,
	}}
	if z.directoryStore != nil {
		mounts = append(mounts, scionrpc.Mount{
			Pattern: "/" + nodev1connect.DirectoryServiceName + "/",
			Handler: mux,
		})
	}
	return mounts, nil
}

// Run owns the measured provider's loops until the context is canceled — the
// rendezvous acceptor, the joiner's dials, the node directory's publish and
// fetch, the selection sweep, the confirm pass over the entries the node
// holds, the link upkeep keeping each link on its peer's current mapping, by
// following its flow or punching it again, and the founding core's lookup of
// its domain when the domain is a name — and returns once every one has
// returned. Mounts assembled what the loops serve.
func (z *Provider) Run(ctx context.Context) {
	var wg sync.WaitGroup
	loops.Go(ctx, &wg, "rendezvous", z.rendezvous.Run)
	loops.Go(ctx, &wg, "join dials", z.runJoinDials)
	loops.Go(ctx, &wg, "node directory", z.directory.Run)
	loops.Go(ctx, &wg, "selection", func(ctx context.Context) {
		RunSelection(ctx, z.selectionConfig())
	})
	loops.Go(ctx, &wg, "confirm pass", z.runConfirmPass)
	loops.Go(ctx, &wg, "link upkeep", z.runUpkeep)
	if z.cfg.Core && z.cfg.Domain != "" && !z.domain.literal.IsValid() {
		loops.Go(ctx, &wg, "domain lookup", z.runDomain)
	}
	wg.Wait()
}

// errNoReflector reports that no neighbor whose link is up reports itself
// dialable.
var errNoReflector = errors.New("no neighbor whose link is up reports itself dialable")

// reflector returns the published rendezvous address of a neighbor whose
// link is up and whose own report says it answers: a node outside the
// node's NAT, whose acceptor echoes a socket's reflexive address.
func (z *Provider) reflector(ctx context.Context) (netip.AddrPort, error) {
	entries, err := z.env.Store.All(ctx)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("reading the link store: %w", err)
	}
	state := z.linkState.Latest()
	if ap, ok := pickReflector(entries, state.Up, z.directoryState.Latest().Entries()); ok {
		return ap, nil
	}
	return netip.AddrPort{}, errNoReflector
}

// pickReflector returns the published rendezvous address of the first
// directory entry whose node reports its address answering and holds an
// established link to this node whose verdict, as linkUp reports it, is up.
func pickReflector(
	entries []*links.Link, linkUp func(ifID uint16) bool, directory []bus.DirectoryEntry,
) (netip.AddrPort, bool) {

	up := make(map[addr.IA]bool, len(entries))
	for _, l := range entries {
		if l.State == links.StateEstablished && linkUp(l.IfID) {
			up[l.NeighborIA] = true
		}
	}
	for _, e := range directory {
		if up[e.IA] && !e.Reach.RendezvousUnanswered {
			return e.RendezvousAddr, true
		}
	}
	return netip.AddrPort{}, false
}

// Close releases what Mounts bound, once Run has returned: the directory's
// and the punches' transports, the three conns drawn through NewConn
// beneath them, and the acceptor's socket. A provider never assembled
// releases nothing.
func (z *Provider) Close() error {
	var errs []error
	if z.directory != nil {
		errs = append(errs, z.directory.Close())
	}
	if z.puncher != nil {
		errs = append(errs, z.puncher.Close())
	}
	for _, conn := range []*scion.Conn{z.directoryConn, z.probeConn, z.punchConn} {
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
		Directory:   z.directoryState,
		Links:       z.linkState,
		Latencies:   z.env.Bus.Latencies(),
		Paths:       z.env.Paths,
		Conn:        z.probeConn,
		ControlHost: z.cfg.ControlHost,
		LinkHost:    z.cfg.ControlHost,
		Sockets:     z.cfg.Sockets,
		Link:        z.linker,
		Punch:       z.puncher,
		Learn:       z.learn,
		Stranded:    &z.stranded,
		Interval:    z.cfg.Pacing.Selection,
		Window:      z.cfg.Pacing.CandidateWindow,
	}
}

// runJoinDials dials the rendezvous of every entry still aimed at one: the
// reply retargets the entry to the acceptor's link address under the claim
// rule, and the first generation serves it. Each entry a pass revives sends
// its link request.
func (z *Provider) runJoinDials(ctx context.Context) {
	for {
		for _, l := range z.dialJoins(ctx) {
			z.confirmLanded(ctx, l)
		}
		if !loops.Sleep(ctx, joinDialInterval) {
			return
		}
	}
}

// dialJoins runs one pass of the joiner's dials and returns the entries it
// revived. The reply names the joiner's own entry — the acceptor's ISD-AS —
// beside retargeting it, so both sides of the establishment are named
// before the link serves. A stranded node — the selection loop's window
// found it below the floor with no reachable candidate from the directory —
// dials what it knows: each retired entry revivable admits re-dials its
// peer's rendezvous socket too, and an answered re-dial revives the entry as
// a candidate, the state flip and the recorded sides, whose own link request
// the caller sends, the confirm a promotion sends too. A revival records the
// rendezvous socket it dialed, for the revived link is this node's dial
// whoever dialed the entry before. It keeps the entry's local address unless
// a live entry now holds it — a later allocation drew the retired entry's
// port — and then claims a fresh one, the address the revived entry serves.
// An answer naming a neighbor the table holds live revives nothing, and the
// store refuses to name a live entry after it: that entry retires, for its
// re-dials would retarget the peer's unproven entry for this node to an
// address no generation serves. A revival the store refuses — its neighbor
// or its address recorded live meanwhile — waits for the next pass. Each
// check reads the table as the pass's earlier revivals left it. An
// unanswered dial costs a UDP round trip and changes nothing, the entry's
// next waiting on its backoff.
func (z *Provider) dialJoins(ctx context.Context) []*links.Link {
	entries, err := z.env.Store.All(ctx)
	if err != nil {
		slog.Error("Reading the link store", "err", err)
		return nil
	}
	var revived []*links.Link
	stranded := z.stranded.Load()
	now := time.Now()
	dialed := make(map[uint16]bool)
	defer z.joinDials.Retain(func(ifID uint16) bool { return dialed[ifID] })
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
		dialed[l.IfID] = true
		if !z.joinDials.Due(l.IfID, now) {
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
			z.joinDials.Tried(l.IfID, now)
			continue
		}
		z.joinDials.Forget(l.IfID)
		z.learn(reply.Reflexive.Addr())
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
			l.Rendezvous = target
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
		if revival {
			revived = append(revived, l)
		}
	}
	return revived
}

// confirmLanded sends the link request of an entry whose locator just
// landed — a revived one, a punched-again one — once the generation serves
// the entry, retrying inside EstablishTimeout as an establishment's confirm
// does: the acceptor's side waits on it, and the confirm pass may have ended
// before the locator landed.
func (z *Provider) confirmLanded(ctx context.Context, l *links.Link) {
	ctx, cancel := context.WithTimeout(ctx, EstablishTimeout)
	defer cancel()
	for !z.confirmEntry(ctx, l) {
		if !loops.Sleep(ctx, ConfirmRetryPause) {
			slog.Warn("The landed entry's link request did not answer",
				"neighbor", l.NeighborIA, "interface", l.IfID)
			return
		}
	}
}

// runConfirmPass re-reaches the entries the node holds: a returning node's
// start and a first start's identity completion confirm every entry over its
// one-hop path, the dial the establishment already makes, and each answered
// request leaves a confirm behind it — the far side polls nothing. Entries
// the pass cannot yet reach retry until they answer or retire, each backing
// off from the selection's cadence up to confirmPassWindows of it, and the
// pass ends once every held entry has answered. The exchange's replies
// retarget the returning node's own entries on the way, as the join dials
// already do, and the enrollment is never re-run.
func (z *Provider) runConfirmPass(ctx context.Context) {
	interval := z.cfg.Pacing.Selection
	if interval == 0 {
		interval = SelectionInterval
	}
	retries := loops.Attempts[uint16]{
		Backoff: loops.Backoff{Base: interval, Max: confirmPassWindows * interval},
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
			now := time.Now()
			for _, l := range entries {
				if !l.Live() || !l.Remote.IsValid() || l.NeighborIA.IsZero() {
					delete(pending, l.IfID)
					retries.Forget(l.IfID)
					continue
				}
				if started && !pending[l.IfID] || !retries.Due(l.IfID, now) {
					continue
				}
				if z.confirmEntry(ctx, l) {
					delete(pending, l.IfID)
					retries.Forget(l.IfID)
				} else {
					pending[l.IfID] = true
					retries.Tried(l.IfID, now)
				}
			}
			started = true
		}
		if started && len(pending) == 0 {
			// The pass is complete — every held entry answered. The loop's
			// contract is to run until the context ends, so it holds here
			// rather than logging an exit.
			<-ctx.Done()
			return
		}
		if !loops.Sleep(ctx, interval) {
			return
		}
	}
}

// confirmEntry sends one held entry's link request over the link's one-hop
// path — the peer's control service addressed by it, the dial naming the
// entry's own interface so the link's verdict gates nothing — and lands the
// reply's side: the address the link observes the peer at, else the peer's
// recorded addresses under the claim rule, and the established state a
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
	state := z.linkState.Latest()
	if recorded := observedOr(state, l.IfID, recordedLinkAddr(remote, claimFallback(l))); recorded != l.Remote ||
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

// repunch punches a down link again and records both ends' current
// reflexive addresses on its entry. The punch leaves from a fresh link
// address — the link's own socket stays bound until the entry lands — and
// the entry keeps its interface ID, so the routes through the link carry
// again once the confirm lands. A failed punch changes nothing: the link
// stays down for the next attempt or the selection's retirement.
func (z *Provider) repunch(ctx context.Context, punch Puncher, l *links.Link) {
	entries, err := z.env.Store.All(ctx)
	if err != nil {
		slog.Error("Reading the link store", "err", err)
		return
	}
	local, err := AllocateLinkAddr(z.cfg.Sockets, z.cfg.ControlHost, entries)
	if err != nil {
		slog.Error("Allocating a link address", "neighbor", l.NeighborIA, "err", err)
		return
	}
	fresh := *l
	fresh.Local = local
	punchCtx, cancel := context.WithTimeout(ctx, EstablishTimeout)
	defer cancel()
	theirs, ifID, err := punch.Establish(punchCtx, l.NeighborIA, &fresh)
	if err != nil {
		slog.Warn("The re-punch failed", "neighbor", l.NeighborIA, "interface", l.IfID, "err", err)
		return
	}
	// The punch took seconds: an entry another loop moved or retired
	// meanwhile keeps that change, and the punch's openings lapse.
	current, err := z.env.Store.ByNeighbor(ctx, l.NeighborIA)
	if err != nil || current == nil || current.IfID != l.IfID || current.Local != l.Local ||
		current.Remote != l.Remote || current.State != l.State {
		slog.Info("The re-punched entry moved meanwhile", "neighbor", l.NeighborIA,
			"interface", l.IfID)
		return
	}
	fresh.Remote = theirs
	fresh.RemoteIfID = ifID
	if err := z.env.Store.Update(ctx, &fresh); err != nil {
		slog.Error("Recording the re-punch", "neighbor", l.NeighborIA, "err", err)
		return
	}
	slog.Info("Punched a link again", "neighbor", l.NeighborIA, "interface", l.IfID,
		"local", fresh.Local, "remote", fresh.Remote)
	z.confirmLanded(ctx, &fresh)
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

// observedOr returns the address the interface's link last observed its
// peer at, else the fallback: the observation is the peer's socket as its
// packets cross every NAT between, where a claim names only the
// socket the peer bound.
func observedOr(state bus.LinkState, ifID uint16, fallback netip.AddrPort) netip.AddrPort {
	if ap := state.Observed(ifID); ap.IsValid() {
		return ap
	}
	return fallback
}

// revivable reports whether a stranded node re-dials a retired entry. A
// named entry is re-dialed while no live entry names its neighbor, so a
// revival never doubles a live neighbor. An unnamed entry is re-dialed only
// when it records the rendezvous address it was seeded with: the entries a
// joiner's first claim mints on the acceptor name no peer. Either waits
// while the named live entries fill the cap.
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
// reuses the connection. The one-hop dial is the point, and it names the
// entry's own interface: the request rides the direct link of the entry it
// confirms whatever the link's verdict — the confirm is the authenticated
// instrument that restores the locator a down verdict waits on, so gating
// its egress on the verdict would deadlock the very recovery it serves —
// and the underlay source the peer's link observes is the requester's link
// socket and not a transit's address.
type linkClient struct {
	peer topology.PeerChannel
	// answered receives each reply's report of the acceptor's echo at the
	// node's published rendezvous address; nil discards the reports.
	answered func(bool)

	mtx  sync.Mutex
	clts map[string]nodev1connect.LinkServiceClient
}

var _ LinkRequester = (*linkClient)(nil)

// Link asks the peer to admit the link, offering the requester's link
// address and interface ID, and answers the peer's side of it; a reply that
// reports the acceptor's echo hands the report to answered.
func (c *linkClient) Link(
	ctx context.Context,
	peer *scion.Addr,
	local netip.AddrPort,
	ifID uint16,
) (*nodev1.LinkReply, error) {

	authority := scionrpc.PeerAuthority(&scion.Addr{
		IA:      peer.IA,
		Addr:    peer.Addr,
		Service: peer.Service,
		IfID:    ifID,
	})
	c.mtx.Lock()
	if c.clts == nil {
		c.clts = make(map[string]nodev1connect.LinkServiceClient)
	}
	clt, ok := c.clts[authority]
	if !ok {
		clt = nodev1connect.NewLinkServiceClient(connect.NewClient(
			connecthttp.NewTransport(c.peer.OneHopClient(), "https://"+authority)))
		c.clts[authority] = clt
	}
	c.mtx.Unlock()
	reply, err := clt.Request(ctx, &nodev1.LinkRequest{
		LocalAddr: local.String(),
		IfId:      uint32(ifID),
	})
	if err != nil {
		return nil, err
	}
	if reply.RendezvousAnswered != nil && c.answered != nil {
		c.answered(*reply.RendezvousAnswered)
	}
	return reply, nil
}
