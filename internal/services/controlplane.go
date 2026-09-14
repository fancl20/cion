package services

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/controlplane"
	pathdbbbolt "github.com/fancl20/cion/pkg/pathdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/trust/impl/bbolt"
)

// setupControlPlane brings up the node's control plane per proposal 0004,
// in phases: the state databases and keys, the trust role (the founding
// core's issuer or every other node's core client), the messenger (trust
// engine and peer client), beaconing (lookup, beaconer, and the path
// provider closing their cycle), the control endpoint's sockets, and the
// echo responder. Each phase assigns what it opens to the node as it goes,
// so setupNode's single deferred unwinding releases a partial node.
func (n *node) setupControlPlane(ctx context.Context) error {
	if err := n.openState(); err != nil {
		return err
	}
	if err := n.setupTrustRole(ctx); err != nil {
		return err
	}
	if err := n.buildMessenger(); err != nil {
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

// openState opens the trust and path databases and the AS key under the
// state directory.
func (n *node) openState() error {
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
			Domain:  n.cfg.CoreDomain,
			Conn:    conn,
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
// beaconer bootstraps the provider.
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

	store := controlplane.NewBeaconStore()
	beaconer, err := controlplane.NewBeaconer(controlplane.BeaconerConfig{
		IA:        n.ident.ia,
		Engine:    n.engine,
		MACKey:    n.ident.key,
		Store:     store,
		DB:        n.pathDB,
		Links:     n.links,
		Neighbors: n.discovery.Neighbors,
		Sender:    n.peerClt,
		CoreRoute: n.coreRoute,
		Core:      n.ident.asType == trust.ASTypeCore,
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

// assembleEndpoint binds the control endpoint's socket and, on the core,
// its WebPKI certificate and the enrollment allowlist. Every node serves
// its ConnectRPC services over HTTP/3 on the endpoint port, since beacons
// terminate on each node's SegmentCreationService; the core's endpoint
// additionally serves the bootstrap channel for clients offering its
// domain as the TLS server name.
func (n *node) assembleEndpoint(ctx context.Context) error {
	if n.ident.asType == trust.ASTypeCore {
		webPKI, err := controlplane.ManageTLSCert(ctx, controlplane.TLSCertConfig{
			Domain:   n.cfg.Domain,
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
	allowAS, err := parseAllowIAS(n.cfg.AllowIAS)
	if err != nil {
		return err
	}
	n.allowAS = allowAS
	n.services = &controlplane.Services{
		TrustService: &controlplane.TrustService{
			DB:      n.trustDB,
			Issuer:  n.issuer,
			AllowAS: allowAS,
		},
		SegmentService: &controlplane.SegmentService{
			Beaconer: n.beaconer,
			Lookup:   n.lookup,
		},
	}
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
		Links:        n.links,
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
	// The one-hop path when the core is a neighbor...
	for _, neighbor := range n.discovery.Neighbors() {
		if neighbor.IA.Equal(coreIA) {
			return &scion.Addr{
				IA:   coreIA,
				Addr: netip.AddrPortFrom(neighbor.ControlAddr.Addr(), controlplane.EndpointPort),
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
