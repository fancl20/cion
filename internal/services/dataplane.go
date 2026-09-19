package services

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/links"
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

// generation is one serving data plane instance. The data plane never
// mutates while serving (ADR-0008): a topology change retires the serving
// generation and brings up its replacement, built from the link store's
// non-retired entries with each link's stable local address rebound
// identically — the swap invisible to the peers' connected sockets.
type generation struct {
	provider *dataplane.UDPProvider
	dp       *dataplane.DataPlane
	cancel   context.CancelFunc
	done     chan struct{} // closed when Serve returned
}

// stop gracefully retires the generation: the provider stops ingesting, the
// processors drain and exit, the links flush and their sockets close — and
// stop returns with the underlay addresses released.
func (g *generation) stop() {
	g.cancel()
	<-g.done
}

// setupMetrics creates the node's metrics, shared across generations; the
// per-link counters reset with each generation (ADR-0008).
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
// supervisor's bounded retry covers that.
func (n *node) startGeneration(ctx context.Context) (*generation, error) {
	entries, err := n.servingLinks(ctx)
	if err != nil {
		return nil, err
	}
	provider := dataplane.NewUDPProvider(n.opts.BatchSize, receiveBufferSize, sendBufferSize)

	dlinks := make([]dataplane.Link, 0, len(entries)+1)
	internalLink, err := provider.NewInternalLink(
		n.cfg.Internal, n.opts.QueueSize, n.metrics.NewInterfaceMetrics(0, n.ident.ia, 0))
	if err != nil {
		provider.Stop()
		return nil, fmt.Errorf("creating internal link: %w", err)
	}
	dlinks = append(dlinks, internalLink)
	for _, l := range entries {
		// Each serving link carries its BFD session — the monitor's, keyed
		// by interface ID and surviving the swap — and the verdict through
		// it: the link attaches its own raw writer, so the session's stream
		// keeps leaving on the rebound address (ADR-0008).
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
	g := &generation{provider: provider, dp: d, cancel: cancel, done: done}
	go func() {
		defer close(done)
		if err := d.Serve(genCtx); err != nil {
			slog.Error("Data plane generation exited", "err", err)
		}
	}()
	return g, nil
}

// superviseDataplanes is the generation supervisor (ADR-0008): build a
// generation and serve it; on each link-store change, retire the serving
// one — stop ingest, drain, close — and bring up its replacement, the same
// link addresses rebound. The control plane never restarts: its sockets are
// its own, and it submits packets to the internal link's address, which
// each generation rebinds. A swap is packet loss measured in milliseconds;
// the QUIC connections of the control channel retransmit through it.
func (n *node) superviseDataplanes(ctx context.Context) error {
	gen, err := n.startGeneration(ctx)
	if err != nil {
		return err
	}
	n.setGeneration(gen)
	return n.supervise(ctx, gen)
}

// supervise watches the serving generation until the context ends or the
// link store changes, swapping in its replacement.
func (n *node) supervise(ctx context.Context, gen *generation) error {
	for {
		select {
		case <-ctx.Done():
			gen.stop()
			return nil
		case <-n.linkChanges:
			gen.stop()
			n.setGeneration(nil)
			var next *generation
			var err error
			for attempt := 0; attempt < bindAttempts; attempt++ {
				next, err = n.startGeneration(ctx)
				if err == nil {
					break
				}
				slog.Warn("Building the replacement data plane", "attempt", attempt, "err", err)
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(bindRetryPause):
				}
			}
			if err != nil {
				return fmt.Errorf("building the replacement data plane: %w", err)
			}
			gen = next
			n.setGeneration(gen)
			serving, err := n.servingLinks(ctx)
			if err != nil {
				slog.Error("Reading the link store after the swap", "err", err)
			}
			slog.Info("Swapped the data plane generation", "links", len(serving))
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

// tableTTL bounds how long a cached link snapshot serves between the
// change notifications: the writes that do not notify still surface within
// it.
const tableTTL = time.Second

// linkTable snapshots the live links' interface IDs and neighbors — the
// source every consumer of the link set reads: the beaconer's checks and
// targets, the connections' one-hop egress resolution, and the core
// route's one-hop shortcut. The snapshot caches: a one-hop send reads it
// per packet, and every mutation is one notification away; the TTL covers
// the writes that are not.
func (n *node) linkTable() map[uint16]addr.IA {
	n.tableMtx.Lock()
	defer n.tableMtx.Unlock()
	if n.tableBuilt == n.tableVersion && time.Since(n.tableAt) < tableTTL {
		return n.tableSnapshot
	}
	entries, err := n.linkStore.All(context.Background())
	if err != nil {
		slog.Error("Reading the link store", "err", err)
		return nil
	}
	n.tableSnapshot = links.Links(entries)
	n.tableBuilt = n.tableVersion
	n.tableAt = time.Now()
	return n.tableSnapshot
}

// registerControlService registers the CS service on a data plane provider:
// the control endpoint's socket is the service's backend, so a packet
// addressed to the service destination — the peer RPCs' QUIC and the drafts'
// resolution requests alike — is delivered to the endpoint beside whose
// services the resolution answers.
func (n *node) registerControlService(provider *dataplane.UDPProvider) error {
	host, err := parseControlHost(n.cfg.Control)
	if err != nil {
		return err
	}
	return provider.AddSvc(addr.SvcCS, addr.HostIP(host), controlplane.EndpointPort)
}

// backend is one service registration the applications own.
type backend struct {
	svc  addr.SVC
	port uint16
}

// registerBackends re-registers the applications' service backends on a new
// provider; the CS registration is discovery's own.
func (n *node) registerBackends(provider *dataplane.UDPProvider) error {
	host, err := parseControlHost(n.cfg.Control)
	if err != nil {
		return err
	}
	n.backendsMtx.Lock()
	defer n.backendsMtx.Unlock()
	for _, b := range n.backends {
		if err := provider.AddSvc(b.svc, addr.HostIP(host), b.port); err != nil {
			return err
		}
	}
	return nil
}

// registerSvc registers one of the applications' sockets as a SCION service
// in this AS — on the serving provider and on every generation to come.
func (n *node) registerSvc(svc addr.SVC, port uint16) error {
	host, err := parseControlHost(n.cfg.Control)
	if err != nil {
		return err
	}
	n.backendsMtx.Lock()
	defer n.backendsMtx.Unlock()
	n.backends = append(n.backends, backend{svc: svc, port: port})
	if n.gen != nil {
		return n.gen.provider.AddSvc(svc, addr.HostIP(host), port)
	}
	return nil
}

// unregisterSvc deregisters a socket registerSvc registered.
func (n *node) unregisterSvc(svc addr.SVC, port uint16) error {
	host, err := parseControlHost(n.cfg.Control)
	if err != nil {
		return err
	}
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
		return n.gen.provider.DelSvc(svc, addr.HostIP(host), port)
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

// notifyLinkChange signals the supervisor a link-store change — every
// mutation lands as a generation swap — and refreshes the cached snapshot.
func (n *node) notifyLinkChange() {
	n.tableMtx.Lock()
	n.tableVersion++
	n.tableMtx.Unlock()
	select {
	case n.linkChanges <- struct{}{}:
	default:
	}
}
