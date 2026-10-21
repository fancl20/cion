package services

import (
	"context"
	"crypto"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/supervise"
	"github.com/fancl20/cion/pkg/apps"
	"github.com/fancl20/cion/pkg/apps/voting"
	"github.com/fancl20/cion/pkg/core/controlplane"
	"github.com/fancl20/cion/pkg/core/dataplane"
	"github.com/fancl20/cion/pkg/core/liveness"
	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/webpki"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/pathdb"
	"github.com/fancl20/cion/pkg/modules/topology"
	filesource "github.com/fancl20/cion/pkg/modules/topology/impl/file"
	measured "github.com/fancl20/cion/pkg/modules/topology/impl/measured"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// node is the fully wired CION node: data plane generations, the control
// plane, the resident applications, and — loaded through the provider seam —
// the topology machinery. setupNode assembles it phase by phase, each phase
// registering what it acquires with the node's group; start launches its
// loops on the group, which releases the resources once the loops have
// returned.
type node struct {
	cfg     resolvedConfig
	ident   identity
	opts    DataplaneOptions
	sockets underlay.Sockets

	// topology is the loaded source module: the measured provider by
	// default, the file provider when --topology.link-set names a link-set. It
	// completes a first start's identity, seeds the store, mounts its
	// services on the endpoint, and runs its loops under start.
	topology topology.Provider
	// publishedHost resolves the host the node's publications carry — the
	// measured provider's own, the learned host beside the bind; the file
	// provider's the control host a concrete bind names, for it learns
	// nothing. The zero address publishes nothing.
	publishedHost func(context.Context) netip.Addr

	// Link state: the neighbor table as the one source of truth, wrapped so
	// that every write signals linkChanges and lands as the data plane's
	// next state — a locator change re-aimed in place, a membership change
	// rebuilt.
	linkStore   links.DB
	linkChanges chan struct{}

	// Data plane generations, served by the data plane loop.
	metrics *dataplane.Metrics

	// backendsMtx guards the serving generation and the applications' service
	// backends, which each new generation re-registers.
	backendsMtx sync.Mutex
	gen         *generation
	backends    []backend

	// tableMtx guards the cached link snapshot and its version.
	tableMtx      sync.Mutex
	tableVersion  uint64
	tableBuilt    uint64
	tableSnapshot map[uint16]addr.IA

	// Control plane, assembled by setupControlPlane's phases.
	trustDB      trustdb.DB
	pathDB       pathdb.DB
	asKey        crypto.Signer
	engine       *trust.Engine
	peerClt      *controlplane.PeerClient
	lookup       *controlplane.LookupService
	beaconer     *controlplane.Beaconer
	beaconStore  *controlplane.BeaconStore
	pathProvider *scion.PathProvider
	// linkLatency carries the selection loop's per-link one-way delay
	// samples to the beaconer's entries; both sides hold this one table.
	linkLatency *controlplane.LinkLatency
	// monitor owns the BFD sessions and their verdicts; ifDown is the
	// node's shared negative cache of interface-down signals its conns
	// record and its path composition consults.
	monitor *liveness.HealthMonitor
	ifDown  *scion.InterfaceDownCache

	// The trust role's products for the later phases, each held as the type
	// its consumer takes and nil where the role offers none: the engine's
	// remote — the core client, every role's but the founder's — and the
	// founder's issuer, TRC decision, and WebPKI identity. roleLoops are
	// the role's own loops, built with its parts; start hands them to the
	// group.
	remote      trust.Remote
	issuer      *trust.Issuer
	trcDecision voting.Decider
	certMgr     *webpki.CertManager
	webPKI      *tls.Config
	roleLoops   []roleLoop

	// Assembled sockets and services, started by start.
	endpointConn *scion.Conn
	// httpsMounts are the handlers the applications mounted on the HTTPS
	// server as they were constructed, each at its own pattern.
	httpsMounts []httpsMount
	// httpsLn and httpsHandler are the node's HTTPS server: the listener the
	// assembly holds on internet HTTPS's port — answering the ACME TLS-ALPN
	// challenge beside the mounted apps' handlers — and those handlers. nil when
	// nothing binds: every role but the founder, or a static-file founder whose
	// apps mount nothing.
	httpsLn      net.Listener
	httpsHandler http.Handler
	services     *controlplane.Services
	responder    *responder
	// apps is the loaded resident applications in table order — the
	// WireGuard application first, its borrowers after — constructed at
	// setup with their borrows resolved. start launches them under the
	// node's supervision; the group releases them in reverse, the borrowers
	// before the machinery they borrow.
	apps []apps.Loaded

	// group runs the node's loops under their policies and holds the
	// resources the boot registered, released in reverse once every loop has
	// returned.
	group *supervise.Group
}

// identity is the node's decoded self: what every assembly phase needs from
// the state directory, where the first start generated it.
type identity struct {
	ia        addr.IA
	key       []byte
	localHost addr.Host
}

// loadIdentity reads the node's identity from the state directory,
// generating it on first start: the ISD-AS drawn randomly from the private
// ranges, the forwarding key beside the AS keys. The ISD-AS is the node's
// name for its lifetime, logged loudly at creation. A first start's ISD is
// a provisional draw the loaded provider completes with the network's.
func loadIdentity(cfg resolvedConfig) (identity, bool, error) {
	ia, err := trust.LoadIA(cfg.State)
	if err != nil {
		return identity{}, false, err
	}
	created := ia.IsZero()
	if created {
		// A first start's draw, provisional until persisted: the core's at
		// once, a joiner's once its provider completes the network's ISD.
		ia, err = trust.GenerateIA()
		if err != nil {
			return identity{}, false, err
		}
		slog.Info("Generated ISD-AS — the node's name for its lifetime; "+
			"a wiped state directory means a new identity", "ia", ia)
	}
	key, err := trust.LoadOrCreateForwardingKey(cfg.State)
	if err != nil {
		return identity{}, false, err
	}
	localHost := addr.HostIP(cfg.internalAddr.Addr())
	return identity{ia: ia, key: key, localHost: localHost}, created, nil
}

// selectProvider loads the source module the run arguments name: the
// measured implementation by default — loading it is what makes a node
// zero-conf — the file one when --topology.link-set names a link-set. The
// provider completes a first start's identity before the phases
// assemble, Wire delivers the phases' products to it, and Seed, Mounts,
// and Run follow. The provider's core flag marks the founding tier alone:
// a joining core takes the joiner's path — its neighbor's rendezvous, its
// learned host — like any local node.
func (n *node) selectProvider() error {
	founding := n.cfg.role == trust.ASTypeCore
	if n.cfg.LinkSet != "" {
		n.topology = filesource.New(filesource.Config{
			Core:          founding,
			Path:          n.cfg.LinkSet,
			WatchInterval: n.cfg.Pacing.LinkSetPoll,
		})
		// The static provider learns nothing: its publication names the
		// control host a concrete bind carries, nothing under the wildcard.
		n.publishedHost = func(context.Context) netip.Addr {
			if host := n.cfg.controlAddr.Addr(); !host.IsUnspecified() {
				return host
			}
			return netip.Addr{}
		}
		return nil
	}
	cfg := measured.Config{
		Core:        founding,
		Neighbors:   n.cfg.Neighbors,
		StateDir:    n.cfg.State,
		ControlHost: n.cfg.controlAddr.Addr(),
		NewConn: func() (*scion.Conn, error) {
			return n.scionConn(0)
		},
		CoreRoute: n.coreRoute,
		Sockets:   n.sockets,
		Pacing: measured.Pacing{
			RendezvousRate:  n.cfg.Pacing.RendezvousRate,
			Directory:       n.cfg.Pacing.Directory,
			Selection:       n.cfg.Pacing.Selection,
			CandidateWindow: n.cfg.Pacing.CandidateWindow,
		},
	}
	if founding {
		// The founding core's published host derives from its own domain; a
		// joiner's — the joining core included — is what the rendezvous
		// exchange teaches it.
		cfg.Domain = n.cfg.Domain
	}
	provider, err := measured.New(cfg)
	if err != nil {
		return err
	}
	n.topology = provider
	n.publishedHost = provider.PublishedHost
	return nil
}

// setupNode assembles a complete node from its run arguments and the state
// directory, each phase registering the resources it acquires with the
// group, so the group's Stop releases a partially built node.
func setupNode(
	ctx context.Context,
	group *supervise.Group,
	cfg NodeConfig,
	opts DataplaneOptions,
	sockets underlay.Sockets,
) (*node, error) {

	rc, err := cfg.resolve()
	if err != nil {
		return nil, err
	}
	ident, created, err := loadIdentity(rc)
	if err != nil {
		return nil, err
	}
	n := &node{
		cfg:         rc,
		ident:       ident,
		opts:        opts,
		sockets:     sockets,
		linkChanges: make(chan struct{}, 1),
		group:       group,
	}
	if err := n.selectProvider(); err != nil {
		return nil, err
	}
	if created {
		// The one moment before the phases: the provider completes the
		// provisional ISD draw — the measured provider's from a bootstrap
		// neighbor's reply, the file provider's from the link-set's first
		// entry — and the founding core's draw is final already; either
		// way the completed identity persists before anything assembles.
		ia, err := n.topology.CompleteIdentity(ctx, n.ident.ia)
		if err != nil {
			return nil, err
		}
		n.ident.ia = ia
		if err := trust.PersistIA(n.cfg.State, ia); err != nil {
			return nil, err
		}
	}
	if err := n.setupMetrics(); err != nil {
		return nil, err
	}
	if err := n.setupControlPlane(ctx); err != nil {
		return nil, err
	}
	if err := n.topology.Seed(ctx); err != nil {
		return nil, err
	}
	if err := n.setupApplications(); err != nil {
		return nil, err
	}
	if err := n.assembleHTTPS(); err != nil {
		return nil, err
	}
	return n, nil
}

// start launches the node's loops on its group, each under its policy: the
// core's — the data plane serving the generation boot built, the BFD health
// monitor, beaconing, the control endpoint, the SCMP echo responder — and
// the HTTPS server under Fatal, a failure stopping the node; the loaded
// topology provider's and the resident applications under Degrade, a
// failure logged and the node serving on; and the role's own loops under
// the policies its case in setupTrustRole gave them. Nothing serves before
// start, so assembly and serving stay separate lifecycles.
func (n *node) start(gen *generation) {
	g := n.group
	g.Go("data plane", supervise.Fatal, func(ctx context.Context) error {
		return n.serveGenerations(ctx, gen)
	})
	g.Go("health monitor", supervise.Fatal, func(ctx context.Context) error {
		n.monitor.Run(ctx)
		return nil
	})
	g.Go("beaconer", supervise.Fatal, func(ctx context.Context) error {
		n.beaconer.Run(ctx)
		return nil
	})
	g.Go("control endpoint", supervise.Fatal, func(ctx context.Context) error {
		// The serve returns with the socket released, so a restart in the
		// same process rebinds the fixed endpoint port.
		return scionrpc.ServeHTTP3(ctx, n.endpointConn,
			controlplane.NewServer(n.services).Handler,
			scionrpc.EndpointTLS(scionrpc.EndpointTLSConfig{
				Domain:      n.cfg.Domain,
				WebPKI:      n.webPKI,
				Credentials: n.engine,
				Key:         n.engine.Key,
			}))
	})
	g.Go("echo responder", supervise.Fatal, n.responder.Run)
	g.Go("topology provider", supervise.Degrade, func(ctx context.Context) error {
		n.topology.Run(ctx)
		return nil
	})
	slog.Info("Serving control endpoint", "port", scionrpc.EndpointPort)
	if n.httpsLn != nil {
		// The node's HTTPS server: the listener is held from assembly, and the
		// founder's certificate maintenance among the role's loops launches
		// only after it — a first issuance's probe finds the port answered.
		ln, handler := n.httpsLn, n.httpsHandler
		g.Go("https server", supervise.Fatal, func(ctx context.Context) error {
			return n.certMgr.ServeHTTPS(ctx, ln, handler)
		})
	}
	for _, l := range n.roleLoops {
		g.Go(l.name, l.policy, l.run)
	}
	for _, l := range n.apps {
		g.Go(l.Name, supervise.Degrade, l.App.Run)
	}
}

// observedSource returns a serving link's last observed underlay source,
// the zero AddrPort while no generation serves the interface — the record
// the authenticated link request's agreement rule reads, the data plane's
// own witness of where the peer's packets come from.
func (n *node) observedSource(ifID uint16) netip.AddrPort {
	n.backendsMtx.Lock()
	gen := n.gen
	n.backendsMtx.Unlock()
	if gen == nil {
		return netip.AddrPort{}
	}
	return gen.provider.Observed(ifID)
}
