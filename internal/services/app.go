// Package services assembles the CION node's services — the data plane
// generations, the control plane, the topology provider the run arguments
// load (ADR 0007), and the resident applications — from the node's run
// arguments and the state directory, where the first start generates the
// identity (ADR-0006). Run serves them as the daemon; BootApp boots them
// for an application sending over the node's own assembly.
package services

import (
	"context"
	"log/slog"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/pathdb"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// Run assembles the node the run arguments and state directory describe,
// starts its loops, and serves the data plane generations until the context
// is canceled — the run command's daemon.
func Run(ctx context.Context, cfg NodeConfig, opts DataplaneOptions) error {
	n, err := setupNode(ctx, cfg, opts)
	if err != nil {
		return err
	}
	defer n.Close()
	n.start(ctx)
	slog.Info("Starting CION", "ia", n.ident.ia, "asType", n.ident.asType,
		"core", cfg.Core, "internal", cfg.Internal, "control", cfg.Control)
	return n.superviseDataplanes(ctx)
}

// App is a fully assembled node booted for an application: the node's loops
// and data plane serve in the background while the application sends over
// its own conn and resolves paths through the node's provider — proposal
// 0005's in-process entry, the form tests and embedded use share with the
// subcommand.
type App struct {
	node *node
}

// BootApp assembles the node and starts it serving underneath the
// application; Close releases it when the application is done. The first
// data plane generation builds synchronously, so a bind failure surfaces
// here instead of as a lost packet.
func BootApp(ctx context.Context, cfg NodeConfig) (*App, error) {
	n, err := setupNode(ctx, cfg, DefaultDataplaneOptions())
	if err != nil {
		return nil, err
	}
	gen, err := n.startGeneration(ctx)
	if err != nil {
		n.Close()
		return nil, err
	}
	n.setGeneration(gen)
	n.start(ctx)
	runBackground(ctx, "dataplane", func(ctx context.Context) error {
		return n.supervise(ctx, gen)
	})
	return &App{node: n}, nil
}

// IA returns the node's ISD-AS.
func (a *App) IA() addr.IA { return a.node.ident.ia }

// Conn returns a SCION conn bound to the control address's host on the
// given port, 0 for an ephemeral one, sending through the node's internal
// link.
func (a *App) Conn(port uint16) (*scion.Conn, error) {
	return a.node.scionConn(port)
}

// Provider returns the node's path provider: the resolver the application
// composes routes through.
func (a *App) Provider() *scion.PathProvider {
	return a.node.pathProvider
}

// Links returns the node's neighbor table — the one source of truth the
// control plane reads and every data plane generation is built from.
func (a *App) Links() links.DB { return a.node.linkStore }

// Monitor returns the node's BFD health monitor — the sessions and their
// verdicts, one per serving link.
func (a *App) Monitor() *controlplane.HealthMonitor { return a.node.monitor }

// InterfaceDown returns the node's shared negative cache of SCMP
// interface-down signals.
func (a *App) InterfaceDown() *scion.InterfaceDownCache { return a.node.ifDown }

// TrustDB returns the node's trust database.
func (a *App) TrustDB() trust.DB { return a.node.trustDB }

// PathDB returns the node's path database.
func (a *App) PathDB() pathdb.DB { return a.node.pathDB }

// Close releases the node's resources.
func (a *App) Close() {
	a.node.Close()
}
