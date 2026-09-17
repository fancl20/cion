package services

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/apps/topology"
	"github.com/fancl20/cion/pkg/controlplane"
	linkbbolt "github.com/fancl20/cion/pkg/links/impl/bbolt"
	pathdbbbolt "github.com/fancl20/cion/pkg/pathdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/trust/impl/bbolt"
)

// setupControlPlane brings up the node's control plane, in phases: the state
// databases and keys — the link store of proposal 0008 among them — the
// trust role (the founding core's issuer or every other node's core client),
// the messenger (trust engine and peer client), discovery, beaconing (the
// lookup, beaconer, and path provider closing their cycle), the wiring of
// the loaded topology provider over what the phases built, the control
// endpoint's socket and the provider's mounted services, and the echo
// responder. Each phase assigns what it opens to the node as it goes, so
// setupNode's single deferred unwinding releases a partial node.
func (n *node) setupControlPlane(ctx context.Context) error {
	if err := n.openState(ctx); err != nil {
		return err
	}
	if err := n.setupTrustRole(ctx); err != nil {
		return err
	}
	if err := n.buildMessenger(); err != nil {
		return err
	}
	if err := n.assembleDiscovery(); err != nil {
		return err
	}
	if err := n.assembleMonitor(); err != nil {
		return err
	}
	if err := n.buildBeaconing(); err != nil {
		return err
	}
	n.wireTopology()
	if err := n.assembleEndpoint(ctx); err != nil {
		return err
	}
	return n.assembleResponder()
}

// openState opens the trust, path, and link databases and the AS key under
// the state directory. A node may start with zero links: the store is empty
// until a neighbor joins, the selection loop promotes one, or the loaded
// provider seeds it — the first-start neighbor requirement being the
// provider's to satisfy, by a --neighbor or a non-empty link-set.
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
	return nil
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
			path, err := n.pathProvider.LocalPath(dst)
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
		Verdicts:             n.monitor.Verdicts,
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

	n.pathProvider = &scion.PathProvider{
		IA:            n.ident.ia,
		DB:            n.pathDB,
		Lookup:        lookup.Down,
		Bootstrap:     beaconer.BootstrapRoute,
		Cores:         cores,
		InterfaceDown: n.ifDown,
	}
	return nil
}

// wireTopology delivers the phases' products to the loaded provider: the
// completed identity, the store its decisions land in, the peer client its
// in-band requests ride, the path provider its comparator baselines with,
// the trust engine its directory channel authenticates with, the neighbor
// map — identity, however stale the greetings — and the monitor's verdicts.
// The last step before the provider mounts and runs, and the one direction
// the dependency ever crosses: the application imports the core and the
// shared libraries, never the reverse.
func (n *node) wireTopology() {
	n.topology.Wire(topology.Pieces{
		IA:        n.ident.ia,
		Store:     n.linkStore,
		Peer:      n.peerClt,
		Provider:  n.pathProvider,
		Engine:    n.engine,
		Neighbors: n.discovery.Neighbors,
		Verdicts:  n.monitor.Verdicts,
	})
}

// assembleDiscovery builds discovery over the store: the greeting stream,
// the neighbor map, and the core-endpoint relay — CION's own but owed by
// every node however its topology is decided (ADR-0007), the beaconer and
// the endpoint build on it.
func (n *node) assembleDiscovery() error {
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
	return nil
}

// assembleMonitor builds the health monitor over the link store (ADR-0008's
// ninth point, ADR-0009's core enumeration): a BFD session per serving link
// whatever the loaded provider is doing — a neighbor's detection of the node
// depends on the node answering its BFD, which makes answering a service of
// the node itself. It is assembled before the first data plane generation,
// so every generation finds a session per serving link, and the file
// provider's nodes get them too: the monitor reads the store, not the
// provider. The interface-down cache is assembled with it — the conns the
// phases bind record the signals the data plane's egress-down branch sends.
func (n *node) assembleMonitor() error {
	monitor, err := controlplane.NewHealthMonitor(controlplane.HealthMonitorConfig{
		IA:       n.ident.ia,
		MACKey:   n.ident.key,
		Store:    n.linkStore,
		Interval: n.cfg.Pacing.BFD,
	})
	if err != nil {
		return err
	}
	n.monitor = monitor
	n.ifDown = scion.NewInterfaceDownCache()
	return nil
}

// assembleEndpoint binds the control endpoint's socket and, on the core,
// its WebPKI certificate. Every node serves its ConnectRPC services over
// HTTP/3 on the endpoint port — the drafts' beside the loaded provider's
// mounts — and the core's endpoint additionally serves the bootstrap
// channel for clients offering its domain as the TLS server name.
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

	mounts, err := n.topology.Mounts()
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
		Mounts: mounts,
	}

	if n.ident.asType == trust.ASTypeCore {
		n.discovery.SetCoreEndpoint(n.ident.ia,
			endpointConn.LocalAddr().(*scion.Addr).Addr)
	}
	return nil
}

// scionConn returns a SCION connection bound to the control address's host
// with the given port, sending through the node's internal link. Every conn
// shares the node's interface-down cache: each receive path recognizes the
// signal the data plane's egress-down branch sends back.
func (n *node) scionConn(port uint16) (*scion.Conn, error) {
	bind, err := controlBind(n.cfg.Control, port)
	if err != nil {
		return nil, err
	}
	return scion.NewConn(scion.ConnConfig{
		IA:            n.ident.ia,
		Bind:          bind,
		InternalAddr:  n.cfg.Internal,
		MACKey:        n.ident.key,
		Links:         n.linkTable,
		InterfaceDown: n.ifDown,
	})
}

// coreRoute returns the route to the core this node enrolls with. The
// one-hop path when the core is a neighbor whose verdict is up, else the
// reversed freshest up segment, which exists from beaconing alone, or the
// bootstrap route before the TRC is pinned. Local state only: resolving a
// route inside a dial must not spawn RPCs over the transport being dialed.
func (n *node) coreRoute() *scion.Addr {
	coreIA, coreEndpoint, ok := n.discovery.CoreEndpoint()
	if !ok {
		return nil
	}
	// The one-hop path when the core is a neighbor and its verdict holds;
	// a link the monitor marked down falls through to the composed route.
	for ifID, neighborIA := range n.linkTable() {
		if neighborIA.Equal(coreIA) && n.monitor.Up(ifID) {
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
	if n.pathProvider != nil {
		if path, err := n.pathProvider.LocalPath(coreIA); err == nil {
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
