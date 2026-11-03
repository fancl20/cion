package wireguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/loops"
)

// Directory cadence: the application owns its publication rhythm. Publication
// begins once enrollment has produced the node's chain, re-publishes on a
// constant — enrollment renews daily, so hourly is a reasonable rate — and a
// refresh constant re-fetches the directory between; a fresh node's tunnels
// come up as soon as its first publish lands and its first fetch returns the
// others.
const (
	// PublishInterval is the re-publication cadence.
	PublishInterval = time.Hour
	// RefreshInterval is the directory re-fetch cadence.
	RefreshInterval = 30 * time.Second
	// PublishRetry is how long publication waits while the node's own state
	// is not ready — a chain the enrollment loop has not produced yet, a host
	// not resolved — and the first wait after a core refused it, the later
	// ones doubling up to PublishRetryMax.
	PublishRetry = 10 * time.Second
	// PublishRetryMax caps the wait after a refused publication.
	PublishRetryMax = 5 * time.Minute
)

// Entry is one node's publication: everything another node needs to establish
// a mesh tunnel to it, and a host's client needs to dial it. The ISD-AS comes
// from the authenticated publisher's certificate chain, never from the claimed
// entry, and the slice is the directory's assignment, never the claim. A mesh
// peer is its ISD-AS, its key, and its subnet: the mesh transport is a SCION
// service, so no reachability data rides the entry for the mesh's own sake.
type Entry struct {
	// IA is the publisher's ISD-AS.
	IA addr.IA
	// PublicKey is the node's WireGuard public key.
	PublicKey PublicKey
	// Overlay is the node's overlay subnet, its slice of the tailnet range —
	// the slice the directory's store assigned at the node's first
	// publication, which never moves.
	Overlay netip.Prefix
	// HostEndpoint is the host-facing endpoint — the underlay address and shared
	// port a host's client dials. The mesh needs it not; the coordination
	// service's netmap names it.
	HostEndpoint netip.AddrPort
}

// HostEntry is one host's registry entry: the record the coordination
// service's gate allocates and the directory distributes. The host's key is
// its identity — the same key re-registering meets the same entry — and the
// address, the owning node, the presenting machine, and the approving
// plugin's note ride beside it, with the client's own description of
// itself, which stays on the core.
type HostEntry struct {
	// PublicKey is the host's WireGuard public key.
	PublicKey PublicKey
	// MachineKey is the machine key the noise channel authenticated when the
	// registration arrived: the record names the machine its node key
	// belongs to, and the register answer and the map refuse any other.
	// Zero on a record from before the fact — the first machine to present
	// such a record binds it.
	MachineKey PublicKey
	// Addr is the tailnet address the coordination service allocated.
	Addr netip.Addr
	// IA is the owning node, whose slice of the tailnet range the address
	// came from. The record never moves: a re-registering host changes
	// nothing.
	IA addr.IA
	// Note is the approving plugin's own account of its decision.
	Note string
	// Hostname and OS are the client's claimed hostname and operating
	// system at admission: shown to the operator, decided on by nothing,
	// and kept on the core — the directory's wire form carries neither.
	Hostname string
	OS       string
}

// Directory is one fetch of the directory: node entries beside host entries,
// the same authenticated snapshot every node programs itself from.
type Directory struct {
	// Nodes holds one entry per publishing node.
	Nodes []Entry
	// Hosts holds one entry per registered host.
	Hosts []HostEntry
}

// DirectoryStore is the core's persisted directory, following the trust DB's
// pattern of a pure interface and shared contract tests.
type DirectoryStore interface {
	// Publish records the entry, keyed by its ISD-AS, placing the
	// publisher's slice should its ISD-AS hold none: the first free /24 of
	// the tailnet range by address order, the claimed overlay ignored. It
	// returns the recorded entry, whose slice is unique by construction,
	// stable per ISD-AS, and idempotent to repeat.
	Publish(ctx context.Context, entry Entry) (Entry, error)
	// PublishHost records the host entry, keyed by its public key. Host
	// entries enter the store locally, through the coordination application
	// the core alone runs — never through the node-authenticated publish.
	PublishHost(ctx context.Context, entry HostEntry) error
	// DeleteHost removes the host entry the public key names, releasing its
	// address; a key the store does not hold deletes nothing and succeeds.
	DeleteHost(ctx context.Context, key PublicKey) error
	// List returns every published entry, nodes and hosts together.
	List(ctx context.Context) (Directory, error)
	Close() error
}

// AssignSlice places one publisher's slice of the tailnet range over the
// entries the store holds: the slice its ISD-AS already holds, else the first
// free /24 of the range by address order — unique by construction, stable per
// ISD-AS, idempotent to repeat, nothing ever freed. A publisher cannot take
// another node's slice; it cannot take any slice, only receive its own.
func AssignSlice(ia addr.IA, entries []Entry) (netip.Prefix, error) {
	var held []netip.Prefix
	for _, e := range entries {
		if e.IA.Equal(ia) {
			return e.Overlay, nil
		}
		if e.Overlay.IsValid() {
			held = append(held, e.Overlay)
		}
	}
	// The candidates step one /24 at a time through the range, in address
	// order; a held slice — a wider one an older state may carry — keeps
	// every /24 it covers.
	base := Tailnet.Masked().Addr().As4()
	for i := 0; i < 1<<(24-Tailnet.Bits()); i++ {
		candidate := netip.PrefixFrom(netip.AddrFrom4(base), 24)
		free := true
		for _, overlay := range held {
			if overlay.Overlaps(candidate) {
				free = false
				break
			}
		}
		if free {
			return candidate, nil
		}
		if base[2]++; base[2] == 0 {
			if base[1]++; base[1] == 0 {
				base[0]++
			}
		}
	}
	return netip.Prefix{}, errors.New("the tailnet range holds no free slice")
}

// Registry is the coordination surface of the core's store: node entries read
// for the netmap and allocation, host entries written at admission and
// deleted at release. The store stays this application's; the coordination
// application borrows the view beside it, never the file.
type Registry interface {
	List(ctx context.Context) (Directory, error)
	PublishHost(ctx context.Context, entry HostEntry) error
	DeleteHost(ctx context.Context, key PublicKey) error
}

// directoryClient is the publish and list surface, whichever side of the
// network serves it: the RPC client on every node, the local store on the
// core itself. Publish answers with the store's assigned slice.
type directoryClient interface {
	Publish(ctx context.Context, entry Entry) (netip.Prefix, error)
	List(ctx context.Context) (Directory, error)
}

// storeDirectoryClient serves the core's own application from its local
// store: the core publishes and fetches beside the store it serves.
type storeDirectoryClient struct {
	store DirectoryStore
}

func (c storeDirectoryClient) Publish(ctx context.Context, entry Entry) (netip.Prefix, error) {
	recorded, err := c.store.Publish(ctx, entry)
	if err != nil {
		return netip.Prefix{}, err
	}
	return recorded.Overlay, nil
}

func (c storeDirectoryClient) List(ctx context.Context) (Directory, error) {
	return c.store.List(ctx)
}

// runPublish owns the application's publication cadence: it waits for
// enrollment to produce the node's chain, publishes the node's entry, and
// re-publishes on the constant and at each change of the node's own state.
// A publication waiting on the node's own state polls at the retry; one the
// core refused backs off from it up to PublishRetryMax. Failures never stop
// the loop.
func (a *App) runPublish(ctx context.Context) {
	interval := a.cfg.PublishInterval
	if interval == 0 {
		interval = PublishInterval
	}
	retry := a.cfg.PublishRetry
	if retry == 0 {
		retry = PublishRetry
	}
	backoff := loops.Backoff{Base: retry, Max: max(retry, PublishRetryMax)}
	self := a.cfg.Self.Subscribe(ctx)
	// The subscription delivers the state as it stands, which the first
	// publication reads anyway.
	select {
	case <-self:
	default:
	}
	for {
		wait := interval
		for range backoff.Tries(ctx) {
			err := a.publish(ctx)
			if err == nil {
				break
			}
			slog.Warn("WireGuard publication", "err", err)
			if errors.Is(err, errNotReady) {
				wait = retry
				break
			}
		}
		if !loops.SleepOr(ctx, wait, self) {
			return
		}
	}
}

// errNotReady marks a publication waiting on the node's own state.
var errNotReady = errors.New("the node's entry is not ready")

// publish sends the node's entry once the node's chain exists: an
// un-enrolled node has no certificate to authenticate the channel with. The
// answer is the store's assignment, which the application holds as the
// node's slice and publishes on the tailnet topic. A host the entry's
// endpoint cannot name — neither the resolver nor the wildcard bind —
// publishes nothing, the retry re-asking.
func (a *App) publish(ctx context.Context) error {
	chain, err := a.cfg.Engine.Chain(ctx)
	if err != nil {
		return err
	}
	if len(chain) == 0 {
		return fmt.Errorf("%w: no certificate chain yet; enrollment has not produced one", errNotReady)
	}
	entry, err := a.selfEntry()
	if err != nil {
		return err
	}
	subnet, err := a.directory.Publish(ctx, entry)
	if err != nil {
		return err
	}
	// The answer's fail-fast check: a /24 the tailnet range contains, the
	// shape the store's assignment guarantees — a core that answers anything
	// else surfaces at this seam nearest it, not deep in the netstack.
	if err := validateAssignment(subnet); err != nil {
		return err
	}
	a.assignSubnet(subnet)
	return nil
}

// selfEntry is the node's own publication: the claim without a slice — the
// store assigns it — the endpoint naming the published host at the shared
// port: the host of the node's own state — the host the node's peers see it
// at, the founding core's domain address — else the bind host when it names
// one, read anew at each publication.
func (a *App) selfEntry() (Entry, error) {
	host := a.cfg.Self.Latest().Host
	if !host.IsValid() || host.IsUnspecified() {
		host = a.cfg.ListenHost
	}
	if !host.IsValid() || host.IsUnspecified() {
		return Entry{}, fmt.Errorf("%w: the entry's host did not resolve", errNotReady)
	}
	return Entry{
		IA:           a.cfg.IA,
		PublicKey:    a.key.PublicKey(),
		HostEndpoint: netip.AddrPortFrom(host, a.cfg.ListenPort),
	}, nil
}

// Subnet returns the node's assigned slice of the tailnet range, waiting for
// the directory's answer. The answer never moves, so every wait returns the
// same slice.
func (a *App) Subnet(ctx context.Context) (netip.Prefix, error) {
	select {
	case <-a.assigned:
		return a.subnet, nil
	case <-ctx.Done():
		return netip.Prefix{}, ctx.Err()
	}
}

// assignSubnet holds the store's answer, publishes it on the tailnet topic
// beside the entries the view holds, and wakes the waiters: the first
// answer is the one, for the assignment never moves.
func (a *App) assignSubnet(subnet netip.Prefix) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if a.subnet.IsValid() {
		return
	}
	a.subnet = subnet
	view := a.tailnet
	view.Slice = subnet
	a.publishTailnetLocked(view)
	close(a.assigned)
	slog.Info("WireGuard slice assigned by the directory", "subnet", subnet)
}

// tailnetView returns the tailnet topic's view of the node's slice beside
// the directory's node and host entries.
func tailnetView(slice netip.Prefix, directory Directory) bus.TailnetState {
	nodes := make([]bus.TailnetNode, 0, len(directory.Nodes))
	for _, e := range directory.Nodes {
		nodes = append(nodes, bus.TailnetNode{
			IA: e.IA, PublicKey: e.PublicKey, Slice: e.Overlay, HostEndpoint: e.HostEndpoint,
		})
	}
	hosts := make([]bus.TailnetHost, 0, len(directory.Hosts))
	for _, h := range directory.Hosts {
		hosts = append(hosts, bus.TailnetHost{PublicKey: h.PublicKey, Addr: h.Addr, IA: h.IA})
	}
	return bus.NewTailnetState(slice, nodes, hosts)
}

// publishTailnetLocked publishes the view on the tailnet topic unless it
// equals the one last published. The caller holds the mutex, so the topic's
// events follow the order of the changes they carry.
func (a *App) publishTailnetLocked(view bus.TailnetState) {
	if view.Equal(a.tailnet) {
		return
	}
	a.tailnet = view
	a.cfg.Tailnet.Publish(view)
}

// runSync owns the directory refresh: it re-fetches the directory on the
// constant and diffs it against the mesh devices — new peers gain a device,
// departed peers lose theirs. A fetch that fails logs and waits; a peer
// without a reachable path queues a refresh and logs rather than erroring
// the application.
func (a *App) runSync(ctx context.Context) {
	interval := a.cfg.RefreshInterval
	if interval == 0 {
		interval = RefreshInterval
	}
	for {
		if !loops.Sleep(ctx, interval) {
			return
		}
		directory, err := a.directory.List(ctx)
		if err != nil {
			slog.Warn("WireGuard directory fetch", "err", err)
			continue
		}
		a.applyDirectory(ctx, directory)
		a.warmMeshPaths(ctx)
	}
}

// warmMeshPaths picks each mesh peer's route in the background, where a
// fetch belongs: sends only ever read the cache, but a leaf-to-leaf route
// composes up and down segments and needs the lookup. Each refresh
// enumerates the peer's candidates and hands them to the socket's landing,
// which ranks them by their declared one-way sums and lands the pick behind
// the switch hysteresis. An empty answer or an error keeps the cache and
// warns — before enrollment, the enumeration composes nothing, and the sends
// the loop would serve keep working through the bootstrap fallback.
func (a *App) warmMeshPaths(ctx context.Context) {
	for _, ia := range a.meshPeerIAs() {
		candidates, err := a.cfg.Paths.Enumerate(ctx, ia)
		if err != nil {
			slog.Warn("WireGuard mesh route", "peer", ia, "err", err)
			continue
		}
		if len(candidates) == 0 {
			slog.Warn("WireGuard mesh route composed no candidate", "peer", ia)
			continue
		}
		pick, switched := a.mesh.landRoute(ia, candidates)
		if switched {
			attrs := []any{"peer", ia, "hops", pick.Hops}
			if pick.Latency != nil {
				attrs = append(attrs, "latency", *pick.Latency)
			}
			slog.Info("WireGuard mesh route switched", attrs...)
		}
	}
}

// meshPeerIAs snapshots the mesh peers' ISD-ASes.
func (a *App) meshPeerIAs() []addr.IA {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	ias := make([]addr.IA, 0, len(a.meshPeers))
	for ia := range a.meshPeers {
		ias = append(ias, ia)
	}
	return ias
}

// Engine is the trust surface the application consumes: the chain that
// authenticates the directory channel.
type Engine = trust.Engine
