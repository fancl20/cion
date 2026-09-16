package services

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/apps/ping"
	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/pathdb"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// node is the fully wired CION node: data plane generations, discovery, the
// control plane, the link machinery of ADR-0006, and the resident
// applications, per proposals 0003-0008. setupNode assembles it phase by
// phase; start launches its loops; Close releases it.
type node struct {
	cfg   NodeConfig
	ident identity
	opts  DataplaneOptions

	// Link state: the neighbor table as the one source of truth, and the
	// change signal every mutation lands as a generation swap.
	linkStore    links.DB
	linkChanges  chan struct{}
	bootstrapped *bootstrapped

	// Data plane generations, run by superviseDataplanes.
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
	tableAt       time.Time
	tableSnapshot map[uint16]addr.IA

	// Control plane, assembled by setupControlPlane's phases.
	trustDB     trust.DB
	pathDB      pathdb.DB
	asKey       crypto.Signer
	issuer      *trust.Issuer            // core only
	coreClt     *controlplane.CoreClient // non-core only
	engine      *trust.Engine
	peerClt     *controlplane.PeerClient
	lookup      *controlplane.LookupService
	beaconer    *controlplane.Beaconer
	beaconStore *controlplane.BeaconStore
	provider    *scion.PathProvider
	discovery   *controlplane.Discovery
	rendezvous  *controlplane.Rendezvous
	directory   *controlplane.NodeDirectory

	// Assembled sockets and services, started by start.
	endpointConn *scion.Conn
	webPKI       *tls.Config
	allowAS      map[addr.IA]bool
	services     *controlplane.Services
	responder    *ping.Responder
	wireguard    *wireguard.App
}

// identity is the node's decoded self: what every assembly phase needs from
// the state directory, where the first start generated it (ADR-0006).
type identity struct {
	ia        addr.IA
	asType    trust.ASType
	key       []byte
	localHost addr.Host
}

// loadIdentity reads the node's identity from the state directory,
// generating it on first start: the ISD-AS drawn randomly from the private
// ranges, the forwarding key beside the AS keys. The ISD-AS is the node's
// name for its lifetime, logged loudly at creation. A first start's ISD is
// a provisional draw a joiner's bootstrap completes with the network's.
func loadIdentity(cfg NodeConfig) (identity, bool, error) {
	ia, err := trust.LoadIA(cfg.State)
	if err != nil {
		return identity{}, false, err
	}
	created := ia.IsZero()
	if created {
		// A first start's draw, provisional until persisted: the core's at
		// once, a joiner's once its bootstrap completes the network's ISD.
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
	asType := trust.ASTypeNormal
	if cfg.Core {
		asType = trust.ASTypeCore
	}
	localHost, err := parseInternalHost(cfg.Internal)
	if err != nil {
		return identity{}, false, err
	}
	return identity{ia: ia, asType: asType, key: key, localHost: localHost}, created, nil
}

// bootstrapped is what a first-start joiner's rendezvous taught it: the
// network's ISD, the neighbor's ISD-AS, and the link's addresses — the seed
// lands complete.
type bootstrapped struct {
	target netip.AddrPort
	reply  controlplane.RendezvousReply
	local  netip.AddrPort
}

// bootstrapIdentity completes a first-start joiner's identity: the ISD of
// its draw is provisional, replaced by the network's — the answering
// neighbor's — so the enrollment's chains verify against the ISD's TRC. The
// joiner claims the zero ISD-AS in its dial; the neighbor's entry adopts
// the final one from the joiner's first greeting.
func (n *node) bootstrapIdentity(ctx context.Context, created bool) error {
	if !created {
		return nil
	}
	if n.cfg.Core {
		// The founding core's draw is its network's name already.
		return trust.PersistIA(n.cfg.State, n.ident.ia)
	}
	if len(n.cfg.Neighbors) == 0 {
		// Unreachable: a non-core's first start carries a neighbor.
		return fmt.Errorf("a non-core's first start needs at least one --neighbor")
	}
	host, err := parseControlHost(n.cfg.Control)
	if err != nil {
		return err
	}
	local, err := controlplane.AllocateLinkAddr(host)
	if err != nil {
		return err
	}
	var answer *controlplane.RendezvousReply
	var targetOf netip.AddrPort
	for _, s := range n.cfg.Neighbors {
		target, err := netip.ParseAddrPort(s)
		if err != nil {
			return fmt.Errorf("parsing --neighbor %q: %w", s, err)
		}
		reply, _, err := controlplane.RendezvousEcho(ctx, host, target,
			addr.IA(0), local)
		if err != nil {
			slog.Warn("The bootstrap neighbor's rendezvous did not answer",
				"rendezvous", target, "err", err)
			continue
		}
		answer = &reply
		targetOf = target
		break
	}
	if answer == nil {
		return fmt.Errorf("no bootstrap neighbor answered its rendezvous; " +
			"retry once one does")
	}
	if answer.IA.ISD() != n.ident.ia.ISD() {
		if ia, err := addr.IAFrom(answer.IA.ISD(), n.ident.ia.AS()); err != nil {
			return err
		} else {
			slog.Info("Completed the identity with the network's ISD",
				"isd_as", ia, "provisional", n.ident.ia)
			n.ident.ia = ia
		}
	}
	if err := trust.PersistIA(n.cfg.State, n.ident.ia); err != nil {
		return err
	}
	n.bootstrapped = &bootstrapped{target: targetOf, reply: *answer, local: local}
	return nil
}

// setupNode assembles a complete node from its run arguments and the state
// directory. Each phase assigns the resources it opens to the node as it
// goes, so the single deferred unwinding below releases a partially built
// node — no per-phase Close cascades. A failed setup returns the
// already-closed partial node beside the error; callers check the error
// first.
func setupNode(ctx context.Context, cfg NodeConfig, opts DataplaneOptions) (n *node, err error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ident, created, err := loadIdentity(cfg)
	if err != nil {
		return nil, err
	}
	n = &node{
		cfg:         cfg,
		ident:       ident,
		opts:        opts,
		linkChanges: make(chan struct{}, 1),
	}
	defer func() {
		if err != nil {
			n.Close()
		}
	}()
	if err = n.bootstrapIdentity(ctx, created); err != nil {
		return n, err
	}
	if err = n.setupMetrics(); err != nil {
		return n, err
	}
	if err = n.setupControlPlane(ctx); err != nil {
		return n, err
	}
	if err = n.seedNeighbors(ctx); err != nil {
		return n, err
	}
	if err = n.setupWireguard(); err != nil {
		return n, err
	}
	return n, nil
}

// Close releases the node's resources in reverse startup order. Fields a
// partially built node never reached stay nil, so Close is safe at every
// point setupNode can fail. The loops' own sockets (endpoint, responder,
// clients) close with their owners when the process exits.
func (n *node) Close() {
	if n.wireguard != nil {
		n.wireguard.Close()
	}
	n.backendsMtx.Lock()
	gen := n.gen
	n.gen = nil
	n.backendsMtx.Unlock()
	if gen != nil {
		gen.stop()
	}
	if n.directory != nil {
		n.directory.Close() //nolint:errcheck
	}
	if n.rendezvous != nil {
		n.rendezvous.Close() //nolint:errcheck
	}
	if n.peerClt != nil {
		n.peerClt.Close() //nolint:errcheck
	}
	if n.discovery != nil {
		n.discovery.Close() //nolint:errcheck
	}
	if n.linkStore != nil {
		n.linkStore.Close() //nolint:errcheck
	}
	if n.pathDB != nil {
		n.pathDB.Close() //nolint:errcheck
	}
	if n.trustDB != nil {
		n.trustDB.Close() //nolint:errcheck
	}
}

// start launches the node's background loops: discovery, beaconing, the
// control endpoint, the SCMP echo responder, the chain lifecycle loop the
// node's role prescribes, and proposal 0008's — the rendezvous acceptor, the
// joiner's dials, the node directory, and the selection loop. Nothing serves
// before start, so assembly and serving stay separate lifecycles; the data
// plane generations are served by superviseDataplanes, the daemon's own
// body.
func (n *node) start(ctx context.Context) {
	runBackground(ctx, "discovery", func(ctx context.Context) error {
		n.discovery.Run(ctx)
		return nil
	})
	runBackground(ctx, "beaconer", func(ctx context.Context) error {
		n.beaconer.Run(ctx)
		return nil
	})
	runBackground(ctx, "control endpoint", func(ctx context.Context) error {
		// The socket releases with the node's cancellation, so an in-process
		// restart rebinds the fixed endpoint port.
		go func() {
			<-ctx.Done()
			n.endpointConn.Close() //nolint:errcheck
		}()
		return controlplane.ServeHTTP3(n.endpointConn,
			controlplane.NewServer(n.services).Handler,
			controlplane.EndpointTLS(controlplane.EndpointTLSConfig{
				Domain: n.cfg.Domain,
				WebPKI: n.webPKI,
				Engine: n.engine,
			}))
	})
	runBackground(ctx, "echo responder", func(ctx context.Context) error {
		n.responder.Run(ctx)
		return nil
	})
	runBackground(ctx, "rendezvous", func(ctx context.Context) error {
		n.rendezvous.Run(ctx)
		return nil
	})
	runBackground(ctx, "join dials", func(ctx context.Context) error {
		n.runJoinDials(ctx)
		return nil
	})
	runBackground(ctx, "node directory", func(ctx context.Context) error {
		n.directory.Run(ctx)
		return nil
	})
	runBackground(ctx, "selection", func(ctx context.Context) error {
		controlplane.RunSelection(ctx, n.selectionConfig())
		return nil
	})
	if n.ident.asType == trust.ASTypeCore {
		runBackground(ctx, "core enrollment", func(ctx context.Context) error {
			controlplane.RunCoreEnrollment(ctx, controlplane.EnrollmentConfig{
				IA:            n.ident.ia,
				DB:            n.trustDB,
				Key:           n.asKey,
				Issuer:        n.issuer,
				RetryInterval: n.cfg.Pacing.Enrollment,
			})
			return nil
		})
	} else {
		runBackground(ctx, "enrollment", func(ctx context.Context) error {
			controlplane.RunEnrollment(ctx, controlplane.EnrollmentConfig{
				IA:            n.ident.ia,
				DB:            n.trustDB,
				Key:           n.asKey,
				Remote:        n.coreClt,
				RetryInterval: n.cfg.Pacing.Enrollment,
			})
			return nil
		})
	}
	slog.Info("Serving control endpoint", "port", controlplane.EndpointPort)
	if n.wireguard != nil {
		runBackground(ctx, "wireguard", func(ctx context.Context) error {
			return n.wireguard.Run(ctx)
		})
	}
}

// selectionConfig builds the topology loop's configuration from the node's
// own pieces: the link store its decisions land in, the directory its
// candidates come from, the provider and conn its probes ride, and the
// neighbor liveness its demotions read.
func (n *node) selectionConfig() controlplane.SelectionConfig {
	probeConn, err := n.scionConn(0)
	if err != nil {
		slog.Error("Binding the selection probe socket", "err", err)
	}
	control, _ := parseControlHost(n.cfg.Control)
	controlAddr := netip.AddrPortFrom(control, controlplane.DiscoveryPort)
	return controlplane.SelectionConfig{
		IA:          n.ident.ia,
		Store:       n.linkStore,
		Directory:   n.directory.Entries,
		Neighbors:   n.discovery.Neighbors,
		Provider:    n.provider,
		Conn:        probeConn,
		ControlAddr: controlAddr,
		LinkHost:    control,
		Link:        n.peerClt,
		Evidence:    n.linkEvidence,
		Changed:     n.notifyLinkChange,
		Interval:    n.cfg.Pacing.Selection,
		Window:      n.cfg.Pacing.CandidateWindow,
	}
}

// linkEvidence reports whether a candidate's peer has proven itself: a
// chain of the peer the node knows — one it issued on the core, or one a
// verified beacon's signatures resolved through — is the enrollment and the
// verified beacon in one check.
func (n *node) linkEvidence(l *links.Link) bool {
	if l.NeighborIA.IsZero() {
		return false
	}
	now := time.Now()
	chains, err := n.trustDB.Chains(context.Background(), trust.ChainQuery{
		IA:       l.NeighborIA,
		Validity: cppki.Validity{NotBefore: now, NotAfter: now},
	})
	return err == nil && len(chains) > 0
}

// selfEnroll issues the core's own certificate chain locally, through the
// same issuer that serves enrollment requests.
func selfEnroll(
	ctx context.Context,
	db trust.DB,
	issuer *trust.Issuer,
	ia addr.IA,
	asKey crypto.Signer,
) ([]*x509.Certificate, error) {

	csr, err := trust.CreateCSR(ia, asKey)
	if err != nil {
		return nil, err
	}
	chain, err := issuer.IssueChain(csr)
	if err != nil {
		return nil, err
	}
	if _, err := db.InsertChain(ctx, chain); err != nil {
		return nil, err
	}
	return chain, nil
}

// runBackground runs one of the node's long-lived loops in its own
// goroutine: a panic is logged and absorbed — one loop's bug must not take
// the process down — and an error return is logged with the loop's name so
// the operator can tell which one exited.
func runBackground(ctx context.Context, name string, fn func(context.Context) error) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Panic in background service", "service", name, "panic", r)
			}
		}()
		if err := fn(ctx); err != nil {
			slog.Error("Background service exited", "service", name, "err", err)
		}
	}()
}
