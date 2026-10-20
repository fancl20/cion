// Package services assembles the CION node's services — the data plane
// generations, the control plane, the topology provider the run arguments
// load, and the resident applications — from the node's run arguments and the
// state directory, where the first start generates the identity. Run serves
// them as the daemon; BootApp boots them for an application sending over the
// node's own assembly.
package services

import (
	"context"
	"errors"
	"log/slog"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/supervise"
	"github.com/fancl20/cion/pkg/apps"
	"github.com/fancl20/cion/pkg/core/controlplane"
	"github.com/fancl20/cion/pkg/core/liveness"
	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/pathdb"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// Run boots the node the run arguments and state directory describe and
// serves it until it stops — the run command's daemon — binding every
// underlay socket through the source. It returns nil once the context ends,
// or the failure of the Fatal loop that stopped the node, joined with the
// releases' errors.
func Run(
	ctx context.Context, cfg NodeConfig, opts DataplaneOptions, sockets underlay.Sockets,
) error {

	n, err := boot(ctx, cfg, opts, sockets)
	if err != nil {
		return err
	}
	slog.Info("Starting CION", "ia", n.ident.ia, "asType", n.cfg.role,
		"core", cfg.Core, "internal", cfg.Internal, "control", cfg.Control)
	return n.group.Wait()
}

// boot assembles the node, builds its first data plane generation, and
// starts its loops, all on one group. The generation builds synchronously,
// so a bind failure surfaces here instead of as a lost packet, and the
// loops start after it. A failed boot stops the group, releasing what the
// boot acquired.
func boot(
	ctx context.Context, cfg NodeConfig, opts DataplaneOptions, sockets underlay.Sockets,
) (*node, error) {

	group, loops := supervise.New(ctx)
	n, err := setupNode(ctx, group, cfg, opts, sockets)
	if err != nil {
		return nil, errors.Join(err, group.Stop())
	}
	gen, err := n.startGeneration(loops)
	if err != nil {
		return nil, errors.Join(err, group.Stop())
	}
	n.setGeneration(gen)
	n.start(gen)
	return n, nil
}

// App is a fully assembled node booted for an application: the node's loops
// and data plane serve in the background while the application sends over
// its own conn and resolves paths through the node's provider — the
// in-process entry, the form tests and embedded use share with the
// subcommand.
type App struct {
	node *node
}

// BootApp boots the node and starts it serving underneath the application,
// binding every underlay socket through the source; Close stops it when the
// application is done.
func BootApp(ctx context.Context, cfg NodeConfig, sockets underlay.Sockets) (*App, error) {
	n, err := boot(ctx, cfg, DefaultDataplaneOptions(), sockets)
	if err != nil {
		return nil, err
	}
	return &App{node: n}, nil
}

// Wait blocks until the node stops — its context ended, Close called, or a
// Fatal loop failed — and returns how: the Fatal failure, if one stopped
// it, joined with the releases' errors.
func (a *App) Wait() error { return a.node.group.Wait() }

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
func (a *App) Monitor() *liveness.HealthMonitor { return a.node.monitor }

// InterfaceDown returns the node's shared negative cache of SCMP
// interface-down signals.
func (a *App) InterfaceDown() *scion.InterfaceDownCache { return a.node.ifDown }

// TrustDB returns the node's trust database.
func (a *App) TrustDB() trustdb.DB { return a.node.trustDB }

// PathDB returns the node's path database.
func (a *App) PathDB() pathdb.DB { return a.node.pathDB }

// Lookup returns the node's segment lookup service — the handler the control
// endpoint serves and the fetcher the provider resolves through.
func (a *App) Lookup() *controlplane.LookupService { return a.node.lookup }

// Engine returns the node's trust engine: it signs the node's own beacon
// entries and verifies each received entry bound to the identity it claims.
func (a *App) Engine() *trust.Engine { return a.node.engine }

// PeerClient returns the node's verified peer channel: the client its
// beacons, registrations, and segment fetches ride.
func (a *App) PeerClient() *controlplane.PeerClient { return a.node.peerClt }

// Application returns the loaded application the name names, nil when it
// did not load. The labs assert the concrete application where they watch
// host peers — the same assertion the borrowing entries make.
func (a *App) Application(name string) apps.Application {
	return apps.AppOf(a.node.apps, name)
}

// Close stops the node and returns what Wait returns.
func (a *App) Close() error { return a.node.group.Stop() }
