package wireguard

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/trust"
)

// Directory cadence (proposal 0006): the application owns its publication
// rhythm. Publication begins once enrollment has produced the node's chain,
// re-publishes on a constant — enrollment renews daily, so hourly is a
// reasonable rate — and a refresh constant re-fetches the directory between;
// a fresh node's tunnels come up as soon as its first publish lands and its
// first fetch returns the others.
const (
	// PublishInterval is the re-publication cadence.
	PublishInterval = time.Hour
	// RefreshInterval is the directory re-fetch cadence.
	RefreshInterval = 30 * time.Second
	// PublishRetry is how long publication waits before retrying — a chain
	// the enrollment loop has not produced yet, or a core that has not
	// answered.
	PublishRetry = 10 * time.Second
)

// Entry is one gateway's publication: everything another node needs to
// establish a mesh tunnel to it. The ISD-AS comes from the authenticated
// publisher's certificate chain, never from the claimed entry.
type Entry struct {
	// IA is the publisher's ISD-AS.
	IA addr.IA
	// PublicKey is the node's WireGuard public key.
	PublicKey PublicKey
	// GatewayPort is the underlay UDP port the mesh transport listens on.
	GatewayPort uint16
	// Underlay is the host address the gateway binds.
	Underlay netip.Addr
	// Overlay is the node's overlay subnet.
	Overlay netip.Prefix
}

// DirectoryStore is the core's persisted directory, following the trust DB's
// pattern of a pure interface and shared contract tests.
type DirectoryStore interface {
	// Publish records the entry, keyed by its ISD-AS.
	Publish(ctx context.Context, entry Entry) error
	// List returns every published entry.
	List(ctx context.Context) ([]Entry, error)
	Close() error
}

// directoryClient is the publish and list surface, whichever side of the
// network serves it: the RPC client on every node, the local store on the
// core itself.
type directoryClient interface {
	Publish(ctx context.Context, entry Entry) error
	List(ctx context.Context) ([]Entry, error)
}

// storeDirectoryClient serves the core's own application from its local
// store: the core publishes and fetches beside the store it serves.
type storeDirectoryClient struct {
	store DirectoryStore
}

func (c storeDirectoryClient) Publish(ctx context.Context, entry Entry) error {
	return c.store.Publish(ctx, entry)
}

func (c storeDirectoryClient) List(ctx context.Context) ([]Entry, error) {
	return c.store.List(ctx)
}

// runPublish owns the application's publication cadence: it waits for
// enrollment to produce the node's chain, publishes the node's entry, and
// re-publishes on the constant. Failures retry, never stop, the loop.
func (g *Gateway) runPublish(ctx context.Context) {
	interval := g.cfg.PublishInterval
	if interval == 0 {
		interval = PublishInterval
	}
	retry := g.cfg.PublishRetry
	if retry == 0 {
		retry = PublishRetry
	}
	for {
		if ctx.Err() != nil {
			return
		}
		if err := g.publish(ctx); err != nil {
			slog.Warn("Gateway publication", "err", err)
			if !sleepCtx(ctx, retry) {
				return
			}
			continue
		}
		if !sleepCtx(ctx, interval) {
			return
		}
	}
}

// publish sends the node's entry once the node's chain exists: an
// un-enrolled node has no certificate to authenticate the channel with.
func (g *Gateway) publish(ctx context.Context) error {
	chain, err := g.cfg.Engine.Chain(ctx)
	if err != nil {
		return err
	}
	if len(chain) == 0 {
		return fmt.Errorf("no certificate chain yet; enrollment has not produced one")
	}
	return g.directory.Publish(ctx, g.selfEntry())
}

// selfEntry is the node's own publication.
func (g *Gateway) selfEntry() Entry {
	return Entry{
		IA:          g.cfg.IA,
		PublicKey:   g.key.PublicKey(),
		GatewayPort: controlplane.GatewayPort,
		Underlay:    g.underlay,
		Overlay:     g.cfg.Subnet,
	}
}

// runSync owns the directory refresh: it re-fetches the directory on the
// constant and diffs it against the mesh devices — new peers gain a device,
// departed peers lose theirs. A fetch that fails logs and waits; a peer
// without a reachable path queues a refresh and logs rather than erroring
// the gateway.
func (g *Gateway) runSync(ctx context.Context) {
	interval := g.cfg.RefreshInterval
	if interval == 0 {
		interval = RefreshInterval
	}
	for {
		if !sleepCtx(ctx, interval) {
			return
		}
		entries, err := g.directory.List(ctx)
		if err != nil {
			slog.Warn("Gateway directory fetch", "err", err)
			continue
		}
		g.applyDirectory(entries)
		g.warmMeshPaths(ctx)
	}
}

// warmMeshPaths resolves each mesh peer's route in the background, where a
// fetch belongs: sends only ever read the cache, but a leaf-to-leaf route
// composes up and down segments and needs the lookup. A peer without a
// reachable path queues the next refresh and logs rather than erroring the
// gateway.
func (g *Gateway) warmMeshPaths(ctx context.Context) {
	for _, ia := range g.meshPeerIAs() {
		path, err := g.cfg.Provider.Path(ctx, ia)
		if err != nil {
			slog.Warn("Gateway mesh route", "peer", ia, "err", err)
			continue
		}
		g.mesh.warmPath(ia, path)
	}
}

// meshPeerIAs snapshots the mesh peers' ISD-ASes.
func (g *Gateway) meshPeerIAs() []addr.IA {
	g.mtx.Lock()
	defer g.mtx.Unlock()
	ias := make([]addr.IA, 0, len(g.meshPeers))
	for ia := range g.meshPeers {
		ias = append(ias, ia)
	}
	return ias
}

// sleepCtx sleeps for d or until the context ends, reporting whether it
// slept.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// Engine is the trust surface the gateway consumes: the chain that
// authenticates the directory channel.
type Engine = trust.Engine
