package topology

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/scion"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
	nodev1connect "github.com/fancl20/cion/proto/node/v1/nodev1connect"
)

// joinDialInterval paces the joiner's rendezvous dials: entries whose
// rendezvous has not answered yet are re-dialed until it does or the
// candidate window retires them.
const joinDialInterval = 5 * time.Second

// ZeroconfConfig configures the measured provider with the pieces the node's
// identity completion and run arguments own; Wire delivers the rest, the
// products of the node's phases, before Seed, Mounts, and Run.
type ZeroconfConfig struct {
	// Core marks the founding core: its draw is its network's name already,
	// and it serves the node directory from its own store.
	Core bool
	// Neighbors are the --neighbor rendezvous addresses; a non-core's first
	// start needs at least one, later starts seed additional entries,
	// idempotent by remote address.
	Neighbors []string
	// BehindNAT publishes the node's reachability class as private:
	// joinable by no one, candidate for no one's floor.
	BehindNAT bool
	// ControlHost is the control address's host: the rendezvous port, the
	// directory's advertised addresses, and the probe claims sit on it.
	ControlHost netip.Addr
	// AllowAS optionally restricts link admission to the listed ISD-ASes;
	// nil means open admission.
	AllowAS map[addr.IA]bool
	// NewConn binds a SCION connection on an ephemeral port: the socket the
	// directory's publish and fetch ride on non-core nodes and the selection
	// probe's socket.
	NewConn func() (*scion.Conn, error)
	// Evidence reports whether a candidate's peer has proven itself — a
	// chain of the peer the node knows, one it issued on the core or one a
	// verified beacon's signatures resolved through.
	Evidence func(*links.Link) bool
	// CoreRoute resolves the core's endpoint, which the directory's client
	// rides on non-core nodes.
	CoreRoute func() *scion.Addr
	// Notify signals a store change — every mutation lands as a data plane
	// generation swap.
	Notify func()

	// Pacing shortens the loops' periods; zero values keep the production
	// constants. The daemon never sets it — the integration tests do.
	Pacing Pacing
}

// Pacing carries the test pacing of the provider's loops.
type Pacing struct {
	RendezvousRate  time.Duration // admission rate caps
	Directory       time.Duration // directory publish and fetch
	Selection       time.Duration // selection evaluation window
	CandidateWindow time.Duration // unproven candidate lifetime
}

// Zeroconf is the measured provider: the rendezvous acceptor, the joiner's
// dials, the node directory, the in-band link service, and the selection
// loop of ADR-0006 and proposal 0008, moved unchanged from the node
// assembly and the core. Loading it is what makes a node zero-conf, and it
// loads by default; nothing about its behavior differs from what the node
// itself ran but its import path.
type Zeroconf struct {
	cfg ZeroconfConfig
	pcs Pieces

	// bootstrap is the first start's completed rendezvous, the seed it
	// taught both sides landing complete.
	bootstrap *bootstrapped

	// mtx guards the one-time assembly of the serving machinery.
	mtx sync.Mutex
	// rendezvous, links, directoryStore, directory, and probeConn are the
	// assembled machinery, built before the first of Mounts and Run.
	rendezvous     *Rendezvous
	links          *LinkService
	directoryStore *DirectoryStore
	directory      *NodeDirectory
	probeConn      *scion.Conn
	assembled      bool
}

// NewZeroconf builds the measured provider.
func NewZeroconf(cfg ZeroconfConfig) *Zeroconf {
	return &Zeroconf{cfg: cfg}
}

// bootstrapped is what a first-start joiner's rendezvous taught it: the
// network's ISD, the neighbor's ISD-AS, and the link's addresses — the seed
// lands complete.
type bootstrapped struct {
	target netip.AddrPort
	reply  RendezvousReply
	local  netip.AddrPort
}

// CompleteIdentity completes a first-start joiner's identity: the ISD of its
// draw is provisional, replaced by the network's — the answering neighbor's
// — so the enrollment's chains verify against the ISD's TRC. The joiner
// claims the zero ISD-AS in its dial; the neighbor's entry adopts the final
// one from the joiner's first greeting. The founding core's draw is its
// network's name already.
func (z *Zeroconf) CompleteIdentity(ctx context.Context, ia addr.IA) (addr.IA, error) {
	if z.cfg.Core {
		return ia, nil
	}
	if len(z.cfg.Neighbors) == 0 {
		// Unreachable: a non-core's first start carries a neighbor.
		return ia, fmt.Errorf("a non-core's first start needs at least one --neighbor")
	}
	local, err := AllocateLinkAddr(z.cfg.ControlHost)
	if err != nil {
		return ia, err
	}
	for _, s := range z.cfg.Neighbors {
		target, err := netip.ParseAddrPort(s)
		if err != nil {
			return ia, fmt.Errorf("parsing --neighbor %q: %w", s, err)
		}
		reply, _, err := RendezvousEcho(ctx, z.cfg.ControlHost, target,
			addr.IA(0), local)
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
		z.bootstrap = &bootstrapped{target: target, reply: reply, local: local}
		return ia, nil
	}
	return ia, fmt.Errorf("no bootstrap neighbor answered its rendezvous; " +
		"retry once one does")
}

// Wire stores the phases' products for the machinery's assembly.
func (z *Zeroconf) Wire(pcs Pieces) {
	z.pcs = pcs
}

// Seed seeds the store with an entry per --neighbor, aimed at the given
// rendezvous address and idempotent by it: the joiner's dial loop retargets
// the entry when the reply arrives. A non-core that holds no entry and names
// no neighbor could never link; it refuses to start.
func (z *Zeroconf) Seed(ctx context.Context) error {
	entries, err := z.pcs.Store.All(ctx)
	if err != nil {
		return err
	}
	if !z.cfg.Core && len(z.cfg.Neighbors) == 0 && len(entries) == 0 {
		return fmt.Errorf("a non-core's first start needs at least one --neighbor")
	}
	if len(z.cfg.Neighbors) == 0 {
		return nil
	}
	for _, s := range z.cfg.Neighbors {
		rendezvous, err := netip.ParseAddrPort(s)
		if err != nil {
			return fmt.Errorf("parsing --neighbor %q: %w", s, err)
		}
		existing, err := z.pcs.Store.ByRemote(ctx, rendezvous)
		if err != nil {
			return err
		}
		if existing != nil {
			continue
		}
		if b := z.bootstrap; b != nil && b.target == rendezvous {
			// The bootstrap's dial already taught both sides: the seed lands
			// retargeted, the data plane's first generation serving it.
			if err := z.pcs.Store.Insert(ctx, &links.Link{
				NeighborIA: b.reply.IA,
				Local:      b.local,
				Remote:     b.reply.LinkAddr,
				RemoteIfID: b.reply.IfID,
				Rendezvous: rendezvous,
				State:      links.StateCandidate,
			}); err != nil {
				return err
			}
			z.notify()
			slog.Info("Seeded the bootstrapped neighbor", "neighbor", b.reply.IA,
				"rendezvous", rendezvous)
			continue
		}
		local, err := AllocateLinkAddr(z.cfg.ControlHost)
		if err != nil {
			return err
		}
		if err := z.pcs.Store.Insert(ctx, &links.Link{
			Local:      local,
			Rendezvous: rendezvous,
			State:      links.StateCandidate,
		}); err != nil {
			return err
		}
		z.notify()
		slog.Info("Seeded a bootstrap neighbor", "rendezvous", rendezvous)
	}
	return nil
}

// assemble builds the serving machinery once: the acceptor every node
// serves, the in-band link service, the directory — the core's store and
// service beside every node's publish and fetch — and the selection probe
// socket.
func (z *Zeroconf) assemble() error {
	z.mtx.Lock()
	defer z.mtx.Unlock()
	if z.assembled {
		return nil
	}
	rendezvous, err := NewRendezvous(RendezvousConfig{
		Bind:        netip.AddrPortFrom(z.cfg.ControlHost, RendezvousPort).String(),
		IA:          z.pcs.IA,
		MinInterval: z.cfg.Pacing.RendezvousRate,
		Store:       z.pcs.Store,
		AllowAS:     z.cfg.AllowAS,
		MaxLinks:    MaxNeighbors,
		LinkHost:    z.cfg.ControlHost,
		Changed:     z.cfg.Notify,
	})
	if err != nil {
		return err
	}
	z.rendezvous = rendezvous
	z.links = &LinkService{
		Store:       z.pcs.Store,
		AllowAS:     z.cfg.AllowAS,
		MaxLinks:    MaxNeighbors,
		LinkHost:    z.cfg.ControlHost,
		MinInterval: z.cfg.Pacing.RendezvousRate,
		Changed:     z.cfg.Notify,
	}
	directoryCfg := NodeDirectoryConfig{
		Entry: DirectoryEntry{
			IA:             z.pcs.IA,
			ControlAddr:    netip.AddrPortFrom(z.cfg.ControlHost, controlplane.DiscoveryPort),
			RendezvousAddr: netip.AddrPortFrom(z.cfg.ControlHost, RendezvousPort),
			Private:        z.cfg.BehindNAT,
		},
		Engine:          z.pcs.Engine,
		Provider:        z.pcs.Provider,
		PublishInterval: z.cfg.Pacing.Directory,
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
		directoryCfg.Conn = conn
		directoryCfg.CoreRoute = z.cfg.CoreRoute
	}
	directory, err := NewNodeDirectory(directoryCfg)
	if err != nil {
		return err
	}
	z.directory = directory
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
func (z *Zeroconf) Mounts() ([]controlplane.Mount, error) {
	if err := z.assemble(); err != nil {
		return nil, err
	}
	path, handler := nodev1connect.NewLinkServiceHandler(z.links)
	mounts := []controlplane.Mount{{Pattern: path, Handler: handler}}
	if z.directoryStore != nil {
		path, handler := nodev1connect.NewDirectoryServiceHandler(
			&DirectoryService{Store: z.directoryStore})
		mounts = append(mounts, controlplane.Mount{Pattern: path, Handler: handler})
	}
	return mounts, nil
}

// Run owns the measured provider's loops until the context is canceled: the
// rendezvous acceptor, the joiner's dials, the node directory's publish and
// fetch, and the selection sweep.
func (z *Zeroconf) Run(ctx context.Context) {
	if err := z.assemble(); err != nil {
		// Mounts assembled the machinery already; a provider run without it
		// keeps the error here rather than crashing the node.
		slog.Error("Assembling the measured provider", "err", err)
		return
	}
	if z.rendezvous != nil {
		runLoop(ctx, "rendezvous", z.rendezvous.Run)
	}
	runLoop(ctx, "join dials", z.runJoinDials)
	if z.directory != nil {
		runLoop(ctx, "node directory", z.directory.Run)
	}
	runLoop(ctx, "selection", func(ctx context.Context) {
		RunSelection(ctx, z.selectionConfig())
	})
}

// Close releases the acceptor's and the directory's sockets.
func (z *Zeroconf) Close() error {
	var err error
	if z.directory != nil {
		err = z.directory.Close()
	}
	if z.rendezvous != nil {
		if cerr := z.rendezvous.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// selectionConfig builds the topology loop's configuration from the
// provider's own pieces: the link store its decisions land in, the directory
// its candidates come from, the provider and conn its probes ride, and the
// neighbor liveness its demotions read.
func (z *Zeroconf) selectionConfig() SelectionConfig {
	return SelectionConfig{
		IA:          z.pcs.IA,
		Store:       z.pcs.Store,
		Directory:   z.directory.Entries,
		Neighbors:   z.pcs.Neighbors,
		Provider:    z.pcs.Provider,
		Conn:        z.probeConn,
		ControlAddr: netip.AddrPortFrom(z.cfg.ControlHost, controlplane.DiscoveryPort),
		LinkHost:    z.cfg.ControlHost,
		Link:        &linkClient{peer: z.pcs.Peer},
		Evidence:    z.cfg.Evidence,
		Changed:     z.cfg.Notify,
		Interval:    z.cfg.Pacing.Selection,
		Window:      z.cfg.Pacing.CandidateWindow,
	}
}

func (z *Zeroconf) notify() {
	if z.cfg.Notify != nil {
		z.cfg.Notify()
	}
}

// runJoinDials dials the rendezvous of every entry still aimed at one: the
// reply retargets the entry to the acceptor's link address, and the first
// generation serves it.
func (z *Zeroconf) runJoinDials(ctx context.Context) {
	for {
		z.dialJoins(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(joinDialInterval):
		}
	}
}

// dialJoins runs one pass of the joiner's dials.
func (z *Zeroconf) dialJoins(ctx context.Context) {
	entries, err := z.pcs.Store.All(ctx)
	if err != nil {
		slog.Error("Reading the link store", "err", err)
		return
	}
	for _, l := range entries {
		if !l.Live() || !l.Rendezvous.IsValid() || l.Remote.IsValid() {
			continue
		}
		reply, _, err := RendezvousEcho(ctx, z.cfg.ControlHost,
			l.Rendezvous, z.pcs.IA, l.Local)
		if err != nil {
			slog.Debug("Rendezvous dial", "rendezvous", l.Rendezvous, "err", err)
			continue
		}
		l.Remote = reply.LinkAddr
		l.RemoteIfID = reply.IfID
		if err := z.pcs.Store.Update(ctx, l); err != nil {
			slog.Error("Retargeting a seeded neighbor", "err", err)
			continue
		}
		z.notify()
		slog.Info("Joined a neighbor by rendezvous",
			"local", l.Local, "remote", l.Remote, "interface", l.IfID)
	}
}

// linkClient establishes links in-band over the peer client's mutually
// verified channel — the drafts' client machinery consumed as a library, a
// client per peer keyed by its encoded authority so the transport reuses
// the connection.
type linkClient struct {
	peer *controlplane.PeerClient

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

	authority := controlplane.PeerAuthority(peer)
	c.mtx.Lock()
	if c.clts == nil {
		c.clts = make(map[string]nodev1connect.LinkServiceClient)
	}
	clt, ok := c.clts[authority]
	if !ok {
		clt = nodev1connect.NewLinkServiceClient(c.peer.VerifiedClient(),
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
