package services

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"log/slog"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/apps/ping"
	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/pathdb"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// node is the fully wired CION node: data plane, discovery, control plane,
// and the resident applications, per proposals 0003-0005. setupNode
// assembles it phase by phase; start launches its background loops; Close
// releases it.
type node struct {
	cfg   *Config
	ident identity
	opts  DataplaneOptions

	// Data plane, assembled by setupDataPlane.
	metrics   *dataplane.Metrics
	udp       *dataplane.UDPProvider
	dp        *dataplane.DataPlane
	discovery *controlplane.Discovery

	// Control plane, assembled by setupControlPlane's phases.
	links    map[uint16]addr.IA
	trustDB  trust.DB
	pathDB   pathdb.DB
	asKey    crypto.Signer
	issuer   *trust.Issuer            // core only
	coreClt  *controlplane.CoreClient // non-core only
	engine   *trust.Engine
	peerClt  *controlplane.PeerClient
	lookup   *controlplane.LookupService
	beaconer *controlplane.Beaconer
	provider *scion.PathProvider

	// Assembled sockets and services, started by start.
	endpointConn *scion.Conn
	webPKI       *tls.Config
	allowAS      map[addr.IA]bool
	services     *controlplane.Services
	responder    *ping.Responder
}

// identity is the node's decoded self: what every assembly phase needs
// from the configuration.
type identity struct {
	ia        addr.IA
	asType    trust.ASType
	key       []byte
	localHost addr.Host
}

// setupNode assembles a complete node from the configuration. Each phase
// assigns the resources it opens to the node as it goes, so the single
// deferred unwinding below releases a partially built node — no per-phase
// Close cascades. A failed setup returns the already-closed partial node
// beside the error; callers check the error first.
func setupNode(ctx context.Context, cfg *Config, opts DataplaneOptions) (n *node, err error) {
	ident, err := parseIdentity(cfg)
	if err != nil {
		return nil, err
	}
	n = &node{cfg: cfg, ident: ident, opts: opts}
	defer func() {
		if err != nil {
			n.Close()
		}
	}()
	if err = n.setupDataPlane(); err != nil {
		return n, err
	}
	if err = n.setupControlPlane(ctx); err != nil {
		return n, err
	}
	return n, nil
}

// Close releases the node's resources in reverse startup order. Fields a
// partially built node never reached stay nil, so Close is safe at every
// point setupNode can fail. The loops' own sockets (endpoint, responder,
// clients) close with their owners when the process exits.
func (n *node) Close() {
	if n.peerClt != nil {
		n.peerClt.Close() //nolint:errcheck
	}
	if n.discovery != nil {
		n.discovery.Close() //nolint:errcheck
	}
	if n.pathDB != nil {
		n.pathDB.Close() //nolint:errcheck
	}
	if n.trustDB != nil {
		n.trustDB.Close() //nolint:errcheck
	}
}

// start launches the node's background loops: discovery, beaconing, the
// control endpoint, the SCMP echo responder, and the chain lifecycle loop
// the node's role prescribes (proposal 0004). Nothing serves before start,
// so assembly and serving stay separate lifecycles.
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
	if n.ident.asType == trust.ASTypeCore {
		runBackground(ctx, "core enrollment", func(ctx context.Context) error {
			controlplane.RunCoreEnrollment(ctx, controlplane.EnrollmentConfig{
				IA:     n.ident.ia,
				DB:     n.trustDB,
				Key:    n.asKey,
				Issuer: n.issuer,
			})
			return nil
		})
	} else {
		runBackground(ctx, "enrollment", func(ctx context.Context) error {
			controlplane.RunEnrollment(ctx, controlplane.EnrollmentConfig{
				IA:     n.ident.ia,
				DB:     n.trustDB,
				Key:    n.asKey,
				Remote: n.coreClt,
			})
			return nil
		})
	}
	slog.Info("Serving control endpoint", "port", controlplane.EndpointPort)
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
