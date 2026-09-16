package services

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/links"
	linkbbolt "github.com/fancl20/cion/pkg/links/impl/bbolt"
	pathdbbbolt "github.com/fancl20/cion/pkg/pathdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/trust/impl/bbolt"
)

// joinDialInterval paces the joiner's rendezvous dials: entries whose
// rendezvous has not answered yet are re-dialed until it does or the
// candidate window retires them.
const joinDialInterval = 5 * time.Second

// setupControlPlane brings up the node's control plane, in phases: the state
// databases and keys — the link store of proposal 0008 among them — the
// trust role (the founding core's issuer or every other node's core client),
// the messenger (trust engine and peer client), beaconing (lookup, beaconer,
// and the path provider closing their cycle), the link machinery (discovery,
// the rendezvous acceptor, the link service, the node directory), the
// control endpoint's socket, and the echo responder. Each phase assigns what
// it opens to the node as it goes, so setupNode's single deferred unwinding
// releases a partial node.
func (n *node) setupControlPlane(ctx context.Context) error {
	allowAS, err := parseAllowIA(n.cfg.AllowIA)
	if err != nil {
		return err
	}
	n.allowAS = allowAS
	if err := n.openState(ctx); err != nil {
		return err
	}
	if err := n.setupTrustRole(ctx); err != nil {
		return err
	}
	if err := n.buildMessenger(); err != nil {
		return err
	}
	if err := n.assembleLinks(); err != nil {
		return err
	}
	if err := n.buildBeaconing(); err != nil {
		return err
	}
	if err := n.assembleEndpoint(ctx); err != nil {
		return err
	}
	return n.assembleResponder()
}

// openState opens the trust, path, and link databases and the AS key under
// the state directory. A node may start with zero links: the store is empty
// until a neighbor joins or the selection loop promotes one.
func (n *node) openState(ctx context.Context) error {
	trustDB, err := bbolt.New(filepath.Join(n.cfg.State, "trust.db"), nil)
	if err != nil {
		return fmt.Errorf("opening trust DB: %w", err)
	}
	n.trustDB = trustDB
	asKey, err := trust.LoadOrCreateASKey(n.cfg.State)
	if err != nil {
		return fmt.Errorf("loading AS key: %w", err)
	}
	n.asKey = asKey
	pathDB, err := pathdbbbolt.New(filepath.Join(n.cfg.State, "path.db"), nil)
	if err != nil {
		return fmt.Errorf("opening path DB: %w", err)
	}
	n.pathDB = pathDB
	linkStore, err := linkbbolt.New(filepath.Join(n.cfg.State, "links.db"), nil)
	if err != nil {
		return fmt.Errorf("opening link DB: %w", err)
	}
	n.linkStore = linkStore

	// A non-core's first start carries at least one neighbor; later starts
	// read the persisted table.
	entries, err := linkStore.All(ctx)
	if err != nil {
		return fmt.Errorf("reading link DB: %w", err)
	}
	if !n.cfg.Core && len(n.cfg.Neighbors) == 0 && len(entries) == 0 {
		return fmt.Errorf("a non-core's first start needs at least one --neighbor")
	}
	return nil
}

// seedNeighbors seeds the store with an entry per --neighbor, aimed at the
// given rendezvous address and idempotent by it: the joiner's dial loop
// retargets the entry when the reply arrives.
func (n *node) seedNeighbors(ctx context.Context) error {
	if len(n.cfg.Neighbors) == 0 {
		return nil
	}
	host, err := parseControlHost(n.cfg.Control)
	if err != nil {
		return err
	}
	for _, s := range n.cfg.Neighbors {
		rendezvous, err := netip.ParseAddrPort(s)
		if err != nil {
			return fmt.Errorf("parsing --neighbor %q: %w", s, err)
		}
		existing, err := n.linkStore.ByRemote(ctx, rendezvous)
		if err != nil {
			return err
		}
		if existing != nil {
			continue
		}
		if b := n.bootstrapped; b != nil && b.target == rendezvous {
			// The bootstrap's dial already taught both sides: the seed lands
			// retargeted, the data plane's first generation serving it.
			if err := n.linkStore.Insert(ctx, &links.Link{
				NeighborIA: b.reply.IA,
				Local:      b.local,
				Remote:     b.reply.LinkAddr,
				RemoteIfID: b.reply.IfID,
				Rendezvous: rendezvous,
				State:      links.StateCandidate,
			}); err != nil {
				return err
			}
			n.notifyLinkChange()
			slog.Info("Seeded the bootstrapped neighbor", "neighbor", b.reply.IA,
				"rendezvous", rendezvous)
			continue
		}
		local, err := controlplane.AllocateLinkAddr(host)
		if err != nil {
			return err
		}
		if err := n.linkStore.Insert(ctx, &links.Link{
			Local:      local,
			Rendezvous: rendezvous,
			State:      links.StateCandidate,
		}); err != nil {
			return err
		}
		n.notifyLinkChange()
		slog.Info("Seeded a bootstrap neighbor", "rendezvous", rendezvous)
	}
	return nil
}

// runJoinDials dials the rendezvous of every entry still aimed at one: the
// reply retargets the entry to the acceptor's link address, and the first
// generation serves it.
func (n *node) runJoinDials(ctx context.Context) {
	host, err := parseControlHost(n.cfg.Control)
	if err != nil {
		slog.Error("Parsing the control address", "err", err)
		return
	}
	for {
		n.dialJoins(ctx, host)
		select {
		case <-ctx.Done():
			return
		case <-time.After(joinDialInterval):
		}
	}
}

// dialJoins runs one pass of the joiner's dials.
func (n *node) dialJoins(ctx context.Context, host netip.Addr) {
	entries, err := n.linkStore.All(ctx)
	if err != nil {
		slog.Error("Reading the link store", "err", err)
		return
	}
	for _, l := range entries {
		if !l.Live() || !l.Rendezvous.IsValid() || l.Remote.IsValid() {
			continue
		}
		reply, _, err := controlplane.RendezvousEcho(ctx, host,
			l.Rendezvous, n.ident.ia, l.Local)
		if err != nil {
			slog.Debug("Rendezvous dial", "rendezvous", l.Rendezvous, "err", err)
			continue
		}
		l.Remote = reply.LinkAddr
		l.RemoteIfID = reply.IfID
		if err := n.linkStore.Update(ctx, l); err != nil {
			slog.Error("Retargeting a seeded neighbor", "err", err)
			continue
		}
		n.notifyLinkChange()
		slog.Info("Joined a neighbor by rendezvous",
			"local", l.Local, "remote", l.Remote, "interface", l.IfID)
	}
}

// setupTrustRole establishes the node's trust role: the founding core
// originates its TRC, issuer, and first chain synchronously — the chain
// lifecycle's first pass — while every other node builds the client for
// enrolling with its core over the SCION-native transport.
func (n *node) setupTrustRole(ctx context.Context) error {
	if n.ident.asType != trust.ASTypeCore {
		// The client socket takes an ephemeral port on the control address;
		// the local router delivers the core's replies to it.
		conn, err := n.scionConn(0)
		if err != nil {
			return err
		}
		coreClt, err := controlplane.NewCoreClient(controlplane.CoreClientConfig{
			Domain:  n.cfg.Domain,
			Conn:    conn,
			RootCAs: n.cfg.RootCAs,
			Locator: n.coreRoute,
		})
		if err != nil {
			return err
		}
		n.coreClt = coreClt
		return nil
	}
	keys, err := trust.LoadOrCreateCoreKeys(n.cfg.State)
	if err != nil {
		return err
	}
	trc, err := trust.Genesis(ctx, n.trustDB, n.ident.ia, keys)
	if err != nil {
		return fmt.Errorf("TRC genesis: %w", err)
	}
	issuer, err := trust.NewIssuer(n.ident.ia, keys, trc)
	if err != nil {
		return fmt.Errorf("creating issuer: %w", err)
	}
	n.issuer = issuer
	if _, err := selfEnroll(ctx, n.trustDB, issuer, n.ident.ia, n.asKey); err != nil {
		return fmt.Errorf("self-enrolling core: %w", err)
	}
	return nil
}

// buildMessenger builds the trust engine and the peer client every node
// beacons and fetches segments through.
func (n *node) buildMessenger() error {
	// The provider behind the engine is DB-first: non-core nodes fall back
	// to the core's endpoint over the SCION-native transport; the core uses
	// none, since its DB holds every chain it issued.
	remote := trust.Remote(nil)
	if n.coreClt != nil {
		remote = n.coreClt
	}
	n.engine = trust.NewEngine(n.ident.ia, n.asKey,
		&trust.NetworkProvider{DB: n.trustDB, Remote: remote})

	peerConn, err := n.scionConn(0)
	if err != nil {
		return err
	}
	peerClt := controlplane.NewPeerClient(controlplane.PeerClientConfig{
		Engine: n.engine,
		Conn:   peerConn,
		PathTo: func(dst addr.IA) *spath.Decoded {
			path, err := n.provider.LocalPath(dst)
			if err != nil {
				return nil
			}
			return path
		},
	})
	n.peerClt = peerClt
	return nil
}

// buildBeaconing builds the segment lookup, the beaconer, and the path
// provider that closes the cycle between them: the provider resolves
// through the lookup, the lookup fetches through the peer client, and the
// beaconer bootstraps the provider. The beaconer reads the link table live —
// a node may start with zero links.
func (n *node) buildBeaconing() error {
	cores := func(isd addr.ISD) []addr.IA {
		ias, err := n.engine.CoreASes(isd)
		if err != nil {
			slog.Warn("Enumerating core ASes from the pinned TRC", "err", err)
			return nil
		}
		return ias
	}

	lookup := controlplane.NewLookupService()
	lookup.IA = n.ident.ia
	lookup.DB = n.pathDB
	lookup.IsCore = n.ident.asType == trust.ASTypeCore
	lookup.Cores = cores
	lookup.Fetch = n.peerClt.Segments
	lookup.CoreRoute = n.coreRoute
	n.lookup = lookup

	beacons := controlplane.NewBeaconStore()
	n.beaconStore = beacons
	beaconer, err := controlplane.NewBeaconer(controlplane.BeaconerConfig{
		IA:                   n.ident.ia,
		Engine:               n.engine,
		MACKey:               n.ident.key,
		Store:                beacons,
		DB:                   n.pathDB,
		Links:                n.linkTable,
		Neighbors:            n.discovery.Neighbors,
		Sender:               n.peerClt,
		CoreRoute:            n.coreRoute,
		Core:                 n.ident.asType == trust.ASTypeCore,
		PropagationInterval:  n.cfg.Pacing.Propagation,
		RegistrationInterval: n.cfg.Pacing.Registration,
	})
	if err != nil {
		return err
	}
	n.beaconer = beaconer

	n.provider = &scion.PathProvider{
		IA:        n.ident.ia,
		DB:        n.pathDB,
		Lookup:    lookup.Down,
		Bootstrap: beaconer.BootstrapRoute,
		Cores:     cores,
	}
	return nil
}

// assembleLinks builds discovery over the store and the rendezvous acceptor
// every node serves — proposal 0008's link machinery the beaconer and the
// endpoint build on.
func (n *node) assembleLinks() error {
	control, err := parseControlHost(n.cfg.Control)
	if err != nil {
		return err
	}
	discovery, err := controlplane.NewDiscovery(controlplane.DiscoveryConfig{
		IA:           n.ident.ia,
		ControlAddr:  n.cfg.Control,
		MACKey:       n.ident.key,
		InternalAddr: n.cfg.Internal,
		Store:        n.linkStore,
		Interval:     n.cfg.Pacing.Discovery,
	})
	if err != nil {
		return err
	}
	n.discovery = discovery

	rendezvous, err := controlplane.NewRendezvous(controlplane.RendezvousConfig{
		Bind:        netip.AddrPortFrom(control, controlplane.RendezvousPort).String(),
		IA:          n.ident.ia,
		MinInterval: n.cfg.Pacing.RendezvousRate,
		Store:       n.linkStore,
		AllowAS:     n.allowAS,
		MaxLinks:    controlplane.MaxNeighbors,
		LinkHost:    control,
		Changed:     n.notifyLinkChange,
	})
	if err != nil {
		return err
	}
	n.rendezvous = rendezvous
	return nil
}

// assembleEndpoint binds the control endpoint's socket and, on the core,
// its WebPKI certificate, the enrollment allowlist, and the node directory
// service. Every node serves its ConnectRPC services over HTTP/3 on the
// endpoint port — the drafts' beside proposal 0008's LinkService — and the
// core's endpoint additionally serves the bootstrap channel for clients
// offering its domain as the TLS server name.
func (n *node) assembleEndpoint(ctx context.Context) error {
	if n.ident.asType == trust.ASTypeCore {
		webPKI, err := controlplane.ManageTLSCert(ctx, controlplane.TLSCertConfig{
			Domain:   n.cfg.Domain,
			Email:    n.cfg.AcmeEmail,
			CertFile: n.cfg.CertFile,
			KeyFile:  n.cfg.KeyFile,
			Storage:  filepath.Join(n.cfg.State, "certs"),
		})
		if err != nil {
			return err
		}
		n.webPKI = webPKI
	}
	endpointConn, err := n.scionConn(controlplane.EndpointPort)
	if err != nil {
		return err
	}
	n.endpointConn = endpointConn

	control, err := parseControlHost(n.cfg.Control)
	if err != nil {
		return err
	}
	n.services = &controlplane.Services{
		TrustService: &controlplane.TrustService{
			DB:      n.trustDB,
			Issuer:  n.issuer,
			AllowAS: n.allowAS,
		},
		SegmentService: &controlplane.SegmentService{
			Beaconer: n.beaconer,
			Lookup:   n.lookup,
		},
		Link: &controlplane.LinkService{
			Store:       n.linkStore,
			AllowAS:     n.allowAS,
			MaxLinks:    controlplane.MaxNeighbors,
			LinkHost:    control,
			MinInterval: n.cfg.Pacing.RendezvousRate,
			Changed:     n.notifyLinkChange,
		},
	}
	var directory *controlplane.DirectoryService
	if n.ident.asType == trust.ASTypeCore {
		directory = &controlplane.DirectoryService{Store: controlplane.NewDirectoryStore()}
		n.services.Directory = directory
	}

	// The node directory: the core publishes into and fetches from the store
	// it serves; every other node rides its verified channel to the core's
	// endpoint.
	directoryCfg := controlplane.NodeDirectoryConfig{
		Entry: controlplane.DirectoryEntry{
			IA:             n.ident.ia,
			ControlAddr:    netip.AddrPortFrom(control, controlplane.DiscoveryPort),
			RendezvousAddr: netip.AddrPortFrom(control, controlplane.RendezvousPort),
			Private:        n.cfg.BehindNAT,
		},
		Engine:          n.engine,
		Provider:        n.provider,
		PublishInterval: n.cfg.Pacing.Directory,
		FetchInterval:   n.cfg.Pacing.Directory,
	}
	if directory != nil {
		directoryCfg.Store = directory.Store
	} else {
		conn, err := n.scionConn(0)
		if err != nil {
			return err
		}
		directoryCfg.Conn = conn
		directoryCfg.CoreRoute = n.coreRoute
	}
	nodeDirectory, err := controlplane.NewNodeDirectory(directoryCfg)
	if err != nil {
		return err
	}
	n.directory = nodeDirectory

	if n.ident.asType == trust.ASTypeCore {
		n.discovery.SetCoreEndpoint(n.ident.ia,
			endpointConn.LocalAddr().(*scion.Addr).Addr)
	}
	return nil
}

// scionConn returns a SCION connection bound to the control address's host
// with the given port, sending through the node's internal link.
func (n *node) scionConn(port uint16) (*scion.Conn, error) {
	bind, err := controlBind(n.cfg.Control, port)
	if err != nil {
		return nil, err
	}
	return scion.NewConn(scion.ConnConfig{
		IA:           n.ident.ia,
		Bind:         bind,
		InternalAddr: n.cfg.Internal,
		MACKey:       n.ident.key,
		Links:        n.linkTable,
	})
}

// coreRoute returns the route to the core this node enrolls with. The
// one-hop path when the core is a neighbor, else the reversed freshest up
// segment, which exists from beaconing alone, or the bootstrap route before
// the TRC is pinned. Local state only: resolving a route inside a dial must
// not spawn RPCs over the transport being dialed.
func (n *node) coreRoute() *scion.Addr {
	coreIA, coreEndpoint, ok := n.discovery.CoreEndpoint()
	if !ok {
		return nil
	}
	// The one-hop path when the core is a neighbor; a link whose greeting
	// went stale falls through to the composed route.
	for ifID, neighborIA := range n.linkTable() {
		if neighborIA.Equal(coreIA) {
			if remote, ok := n.remoteOf(ifID); ok {
				return &scion.Addr{
					IA:   coreIA,
					Addr: netip.AddrPortFrom(remote.ControlAddr.Addr(), controlplane.EndpointPort),
				}
			}
		}
	}
	// ...else the reversed up segment from the path provider, when
	// beaconing has already filled it.
	if n.provider != nil {
		if path, err := n.provider.LocalPath(coreIA); err == nil {
			return &scion.Addr{IA: coreIA, Addr: coreEndpoint, Path: path}
		}
	}
	return nil
}

// remoteOf returns the neighbor's control address learned from greetings.
func (n *node) remoteOf(ifID uint16) (controlplane.Neighbor, bool) {
	for id, neighbor := range n.discovery.Neighbors() {
		if id == ifID {
			return neighbor, true
		}
	}
	return controlplane.Neighbor{}, false
}
