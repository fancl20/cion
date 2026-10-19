package services

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/dataplane"
	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/modules/links"
)

// buffer sizes of the underlay sockets. They are fixed, not run flags: the
// OS caps them (net.core.rmem_max and friends), so a flag would promise a
// knob the kernel quietly ignores.
const (
	receiveBufferSize = 1 << 20
	sendBufferSize    = 1 << 20
)

// The generation swap's rebind retry: the serving generation's sockets close
// before the replacement binds the same addresses, and the operating system
// releases them on its own schedule — a bounded retry covers the gap.
const (
	bindAttempts   = 10
	bindRetryPause = 100 * time.Millisecond
)

// DataplaneOptions carries the run command's data-plane tuning; BootApp
// uses the defaults. The fields map one to one onto the data plane's
// RunConfig and the per-link queue depth.
type DataplaneOptions struct {
	Processors int // RunConfig.NumProcessors
	BatchSize  int // RunConfig.BatchSize and the UDP provider's batch
	QueueSize  int // internal and external link queue depth
}

// DefaultDataplaneOptions returns the data-plane tuning the daemon and the
// ping application run with unless the run command overrides it.
func DefaultDataplaneOptions() DataplaneOptions {
	return DataplaneOptions{
		Processors: max(1, runtime.NumCPU()/2),
		BatchSize:  64,
		QueueSize:  64,
	}
}

// generation is one serving data plane instance. The data plane's link set
// never mutates while serving: a membership change retires the serving
// generation and brings up its replacement, built from the link store's
// non-retired entries with each link's stable local address rebound
// identically — the swap invisible to the peers. A locator change is not a
// membership change: the serving generation re-aims the link in place, the
// locator live state its sends read at egress.
type generation struct {
	provider *dataplane.UDPProvider
	dp       *dataplane.DataPlane
	cancel   context.CancelFunc
	done     chan struct{} // closed when Serve returned
	// entries is the serving set the generation was built from, the
	// membership a store change is diffed against.
	entries []*links.Link
}

// reaim lands a locator change without a generational replacement: a store
// change whose serving set holds the same interfaces on the same local
// addresses re-aims each link whose remote moved, in place. It reports
// false — the change calls for the swap — on any membership or local
// address difference, and true with the generation's record advanced to
// the new locators. Retiring the plane per locator change would gap the
// very BFD session stream the design leans on; a re-aim is one store write
// and one field.
func (g *generation) reaim(entries []*links.Link) bool {
	if len(g.entries) != len(entries) {
		return false
	}
	built := make(map[uint16]*links.Link, len(g.entries))
	for _, l := range g.entries {
		built[l.IfID] = l
	}
	for _, l := range entries {
		b, ok := built[l.IfID]
		if !ok || b.Local != l.Local {
			return false
		}
		if b.Remote != l.Remote {
			g.provider.Aim(l.IfID, l.Remote)
		}
	}
	g.entries = entries
	return true
}

// stop gracefully retires the generation: the provider stops ingesting, the
// processors drain and exit, the links flush and their sockets close — and
// stop returns with the underlay addresses released.
func (g *generation) stop() {
	g.cancel()
	<-g.done
}

// setupMetrics creates the node's metrics, shared across generations; the
// per-link counters reset with each generation.
func (n *node) setupMetrics() error {
	metrics, err := dataplane.NewMetrics()
	if err != nil {
		return fmt.Errorf("creating metrics: %w", err)
	}
	n.metrics = metrics
	return nil
}

// startGeneration builds and serves one data plane from the link store's
// serving entries: a provider, the internal link, one external link per
// entry, every service backend registered on the new provider. It fails
// only while the serving generation's addresses are still releasing; the
// data plane loop's bounded retry covers that.
func (n *node) startGeneration(ctx context.Context) (*generation, error) {
	entries, err := n.servingLinks(ctx)
	if err != nil {
		return nil, err
	}
	provider := dataplane.NewUDPProvider(n.opts.BatchSize, receiveBufferSize, sendBufferSize)

	dlinks := make([]dataplane.Link, 0, len(entries)+1)
	internalLink, err := provider.NewInternalLink(
		n.cfg.internalAddr.String(), n.opts.QueueSize, n.metrics.NewInterfaceMetrics(0, n.ident.ia, 0))
	if err != nil {
		provider.Stop()
		return nil, fmt.Errorf("creating internal link: %w", err)
	}
	dlinks = append(dlinks, internalLink)
	for _, l := range entries {
		// Each serving link carries its BFD session — the monitor's, keyed by
		// interface ID and surviving the swap — and the verdict through it: the link
		// attaches its own raw writer, so the session's stream keeps leaving on the
		// rebound address.
		session := n.monitor.Session(l)
		link, err := provider.NewExternalLink(
			n.opts.QueueSize, session, l.Local.String(), l.Remote.String(), l.IfID,
			n.metrics.NewInterfaceMetrics(l.IfID, n.ident.ia, 0),
		)
		if err != nil {
			provider.Stop()
			return nil, fmt.Errorf("creating interface %d: %w", l.IfID, err)
		}
		dlinks = append(dlinks, link)
	}
	// The control service maps to the control endpoint's socket — the
	// registered service the drafts' service routing delivers to, so every
	// service-addressed packet, QUIC and resolution alike, reaches the
	// endpoint — beside whatever the applications registered through their
	// callback.
	if err := n.registerControlService(provider); err != nil {
		provider.Stop()
		return nil, fmt.Errorf("registering control service: %w", err)
	}
	if err := n.registerBackends(provider); err != nil {
		provider.Stop()
		return nil, fmt.Errorf("registering service backends: %w", err)
	}

	d, err := dataplane.NewDataPlane(n.ident.ia, n.ident.localHost, n.ident.key, provider, dlinks)
	if err != nil {
		provider.Stop()
		return nil, err
	}
	d.RunConfig = dataplane.RunConfig{
		NumProcessors:         n.opts.Processors,
		NumSlowPathProcessors: 1,
		BatchSize:             n.opts.BatchSize,
		ReceiveBufferSize:     receiveBufferSize,
		SendBufferSize:        sendBufferSize,
	}
	genCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	g := &generation{provider: provider, dp: d, cancel: cancel, done: done, entries: entries}
	go func() {
		defer close(done)
		if err := d.Serve(genCtx); err != nil {
			slog.Error("Data plane generation exited", "err", err)
		}
	}()
	return g, nil
}

// serveGenerations is the data plane loop: it serves the generation boot
// built and, on each link-store change, lands it — a locator change re-aims
// the link in place, anything else retires the serving generation — stop
// ingest, drain, close — and brings up its replacement, the same link
// addresses rebound. The control plane never restarts: its sockets are its
// own, and it submits packets to the internal link's address, which each
// generation rebinds. A swap is packet loss measured in milliseconds; the
// QUIC connections of the control channel retransmit through it. The loop
// stops the serving generation before it returns.
func (n *node) serveGenerations(ctx context.Context, gen *generation) error {
	for {
		select {
		case <-ctx.Done():
			gen.stop()
			return nil
		case <-n.linkChanges:
			entries, err := n.servingLinks(ctx)
			if err != nil {
				slog.Error("Reading the link store for the data plane", "err", err)
				continue
			}
			if gen.reaim(entries) {
				continue
			}
			gen.stop()
			n.setGeneration(nil)
			var next *generation
			for attempt := range bindAttempts {
				next, err = n.startGeneration(ctx)
				if err == nil {
					break
				}
				slog.Warn("Building the replacement data plane", "attempt", attempt, "err", err)
				if !loops.Sleep(ctx, bindRetryPause) {
					return nil
				}
			}
			if err != nil {
				return fmt.Errorf("building the replacement data plane: %w", err)
			}
			gen = next
			n.setGeneration(gen)
			slog.Info("Swapped the data plane generation")
		}
	}
}

// servingLinks reads the link store's serving entries.
func (n *node) servingLinks(ctx context.Context) ([]*links.Link, error) {
	entries, err := n.linkStore.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the link store: %w", err)
	}
	return links.Serving(entries), nil
}

// linkTable snapshots the live links' interface IDs and neighbors — the
// source every consumer of the link set reads: the beaconer's checks and
// targets whole, the routes out of the node through usableLinks. The
// snapshot caches, for a one-hop send reads it per packet, and rebuilds
// once the store's signal moved its version: every write to the node's
// store signals.
func (n *node) linkTable() map[uint16]addr.IA {
	n.tableMtx.Lock()
	defer n.tableMtx.Unlock()
	if n.tableSnapshot != nil && n.tableBuilt == n.tableVersion {
		return n.tableSnapshot
	}
	entries, err := n.linkStore.All(context.Background())
	if err != nil {
		// The write path reads this from quic-go's send goroutines, which
		// outlive Close by a write in flight: a closed store here is the
		// shutdown racing one last send, not corruption.
		slog.Error("Reading the link store", "err", err)
		return nil
	}
	n.tableSnapshot = links.Links(entries)
	n.tableBuilt = n.tableVersion
	return n.tableSnapshot
}

// usableLinks snapshots the links the node can send over: the link table's
// entries whose BFD verdict is up. The data plane refuses a down link's
// egress, and forwards a one-hop packet onto it without that check, so no
// signal tells the sender; every route out of the node — a composed path's
// first hop, the bootstrap route, a one-hop write, the core route's
// shortcut — resolves over these links alone, and fails at once where none
// serves. The beaconer reads the whole table: a beacon arriving on a down
// link still names its neighbor. A failed read of the store serves nil, as
// the table does.
func (n *node) usableLinks() map[uint16]addr.IA {
	return usable(n.linkTable(), n.monitor.Verdicts())
}

// usable keeps the table's links whose verdict is up; an interface with no
// verdict — one the monitor has not seen — is up, as the monitor counts it.
func usable(table map[uint16]addr.IA, verdicts map[uint16]bool) map[uint16]addr.IA {
	if table == nil {
		return nil
	}
	out := make(map[uint16]addr.IA, len(table))
	for ifID, neighbor := range table {
		if up, ok := verdicts[ifID]; !ok || up {
			out[ifID] = neighbor
		}
	}
	return out
}

// registerControlService registers the CS service on a data plane provider:
// the control endpoint's socket is the service's backend, so a packet
// addressed to the service destination — the peer RPCs' QUIC and the drafts'
// resolution requests alike — is delivered to the endpoint beside whose
// services the resolution answers.
func (n *node) registerControlService(provider *dataplane.UDPProvider) error {
	return provider.AddSvc(addr.SvcCS, n.deliveryHost(), scionrpc.EndpointPort)
}

// deliveryHost names the host the service registrations deliver to: the
// control host, or — under the wildcard bind — the internal address's, the
// host the internal link already sends from and every wildcard-bound
// receiver covers; the operating system's wildcard-means-loopback delivery
// convention is no contract.
func (n *node) deliveryHost() addr.Host {
	if n.cfg.controlAddr.Addr().IsUnspecified() {
		return addr.HostIP(n.cfg.internalAddr.Addr())
	}
	return addr.HostIP(n.cfg.controlAddr.Addr())
}

// backend is one service registration the applications own.
type backend struct {
	svc  addr.SVC
	port uint16
}

// registerBackends re-registers the applications' service backends on a new
// provider; the CS registration is discovery's own.
func (n *node) registerBackends(provider *dataplane.UDPProvider) error {
	host := n.deliveryHost()
	n.backendsMtx.Lock()
	defer n.backendsMtx.Unlock()
	for _, b := range n.backends {
		if err := provider.AddSvc(b.svc, host, b.port); err != nil {
			return err
		}
	}
	return nil
}

// registerSvc registers one of the applications' sockets as a SCION service
// in this AS — on the serving provider and on every generation to come.
func (n *node) registerSvc(svc addr.SVC, port uint16) error {
	host := n.deliveryHost()
	n.backendsMtx.Lock()
	defer n.backendsMtx.Unlock()
	n.backends = append(n.backends, backend{svc: svc, port: port})
	if n.gen != nil {
		return n.gen.provider.AddSvc(svc, host, port)
	}
	return nil
}

// unregisterSvc deregisters a socket registerSvc registered.
func (n *node) unregisterSvc(svc addr.SVC, port uint16) error {
	host := n.deliveryHost()
	n.backendsMtx.Lock()
	defer n.backendsMtx.Unlock()
	kept := n.backends[:0]
	for _, b := range n.backends {
		if b.svc == svc && b.port == port {
			continue
		}
		kept = append(kept, b)
	}
	n.backends = kept
	if n.gen != nil {
		return n.gen.provider.DelSvc(svc, host, port)
	}
	return nil
}

// setGeneration records the serving generation under the lock the service
// registration callbacks read it by.
func (n *node) setGeneration(g *generation) {
	n.backendsMtx.Lock()
	defer n.backendsMtx.Unlock()
	n.gen = g
}

// notifyLinkChange is the link store's signal, run after every write: it
// moves the cached snapshot's version and wakes the data plane loop, which
// lands the write as a generation swap. A burst of writes coalesces in the
// one-slot channel.
func (n *node) notifyLinkChange() {
	n.tableMtx.Lock()
	n.tableVersion++
	n.tableMtx.Unlock()
	select {
	case n.linkChanges <- struct{}{}:
	default:
	}
}
