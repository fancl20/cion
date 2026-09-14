// Package services assembles the CION node's services — the data plane,
// the control plane, and the resident applications — from the node
// configuration. Run serves them as the daemon; BootApp boots them for an
// application sending over the node's own assembly.
package services

import (
	"context"
	"log/slog"

	"github.com/fancl20/cion/pkg/scion"
)

// Run assembles the node the configuration describes, starts its loops,
// and serves the data plane until the context is canceled — the run
// command's daemon.
func Run(ctx context.Context, cfg *Config, opts DataplaneOptions) error {
	n, err := setupNode(ctx, cfg, opts)
	if err != nil {
		return err
	}
	defer n.Close()
	n.start(ctx)
	slog.Info("Starting CION", "ia", n.ident.ia, "asType", n.ident.asType,
		"internal", cfg.Internal, "control", cfg.Control, "interfaces", len(cfg.Interfaces))
	return n.dp.Serve(ctx)
}

// App is a fully assembled node booted for an application: the node's
// loops and data plane serve in the background while the application sends
// over its own conn and resolves paths through the node's provider —
// proposal 0005's in-process entry, the form tests and embedded use share
// with the subcommand.
type App struct {
	node *node
}

// BootApp assembles the node and starts it serving underneath the
// application; Close releases it when the application is done.
func BootApp(ctx context.Context, cfg *Config) (*App, error) {
	n, err := setupNode(ctx, cfg, DefaultDataplaneOptions())
	if err != nil {
		return nil, err
	}
	n.start(ctx)
	runBackground(ctx, "dataplane", n.dp.Serve)
	return &App{node: n}, nil
}

// Conn returns a SCION conn bound to the control address's host on the
// given port, 0 for an ephemeral one, sending through the node's internal
// link.
func (a *App) Conn(port uint16) (*scion.Conn, error) {
	return a.node.scionConn(port)
}

// Provider returns the node's path provider: the resolver the application
// composes routes through.
func (a *App) Provider() *scion.PathProvider {
	return a.node.provider
}

// Close releases the node's resources.
func (a *App) Close() {
	a.node.Close()
}
