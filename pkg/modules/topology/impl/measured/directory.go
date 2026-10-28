package measured

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/peeria"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
	nodev1connect "github.com/fancl20/cion/proto/node/v1/nodev1connect"
)

// Node directory cadence: once enrolled, a node publishes its entry on a
// constant cadence and a fetch constant refreshes the local copy in between;
// entries expire without refresh.
const (
	// NodePublishInterval is the re-publication cadence.
	NodePublishInterval = time.Minute
	// NodeFetchInterval is the directory re-fetch cadence.
	NodeFetchInterval = 30 * time.Second
	// NodePublishRetry is how long publication waits while the node's own
	// state is not ready — a chain the enrollment loop has not produced yet,
	// a host not resolved — and the first wait after a core refused it, the
	// later ones doubling up to NodePublishInterval.
	NodePublishRetry = 5 * time.Second
	// NodeDirectoryTTL is how long the core serves an entry without refresh.
	NodeDirectoryTTL = 5 * time.Minute
)

// DirectoryEntry is one node's publication: everything the selection loop
// needs to probe the node as a candidate, and the node's report of how its
// peers reach it. The ISD-AS comes from the authenticated publisher's
// certificate chain, never from the claim.
type DirectoryEntry struct {
	// IA is the publisher's ISD-AS.
	IA addr.IA
	// ControlAddr is the underlay address of the publisher's control
	// service, the endpoint port on the published host.
	ControlAddr netip.AddrPort
	// RendezvousAddr is the underlay address the publisher's rendezvous
	// acceptor listens on for first contact, the fixed rendezvous port on
	// the published host.
	RendezvousAddr netip.AddrPort
	// Reach is the publisher's report of how its peers reach it.
	Reach Reach
	// Published is the publish time the core recorded.
	Published time.Time
}

// Reach is a node's report of how its peers reach it. The zero value
// reports nothing observed.
type Reach struct {
	// BehindNAT reports that the node's published host is not an address
	// of its own: a NAT stands between it and its peers.
	BehindNAT bool
	// RendezvousUnanswered reports that the acceptor of the node's latest
	// link request got no answer at its published rendezvous address.
	RendezvousUnanswered bool
}

// DirectoryStore is the core's in-memory directory. Entries expire without
// refresh; a core restart empties the directory until the publishers' next
// cadence re-populates it.
type DirectoryStore struct {
	mtx     sync.Mutex
	entries map[addr.IA]DirectoryEntry
}

// NewDirectoryStore returns an empty directory.
func NewDirectoryStore() *DirectoryStore {
	return &DirectoryStore{entries: make(map[addr.IA]DirectoryEntry)}
}

// Publish records the entry under its ISD-AS.
func (s *DirectoryStore) Publish(e DirectoryEntry) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.entries[e.IA] = e
}

// List returns every entry published within the TTL.
func (s *DirectoryStore) List(now time.Time) []DirectoryEntry {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	var out []DirectoryEntry
	for ia, e := range s.entries {
		if now.Sub(e.Published) > NodeDirectoryTTL {
			delete(s.entries, ia)
			continue
		}
		out = append(out, e)
	}
	return out
}

// DirectoryService is the core-served node directory: Publish records the
// publisher's entry on the control endpoint's authenticated channel, List
// serves the directory to every node. The publisher is identified by its
// verified certificate chain, so a node can only publish its own entry.
type DirectoryService struct {
	// Store holds the directory.
	Store *DirectoryStore
}

var _ nodev1connect.DirectoryServiceHandler = (*DirectoryService)(nil)

// Publish records the caller's entry. The entry's ISD-AS is the
// authenticated one; a claim of another ISD-AS is recorded under the
// authenticated one all the same.
func (s *DirectoryService) Publish(
	ctx context.Context,
	req *nodev1.PublishRequest,
) (*nodev1.PublishResponse, error) {

	publisher := peeria.AuthenticatedIA(ctx)
	if publisher.IsZero() {
		return nil, connect.NewError(connect.CodePermissionDenied,
			"no authenticated ISD-AS; the channel verified no chain")
	}
	if req == nil || req.Entry == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "no entry")
	}
	entry, err := entryFromPB(req.Entry)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			"malformed entry").WithCause(err)
	}
	if !entry.IA.Equal(publisher) {
		slog.Warn("Node directory publish claims another ISD-AS; recording the authenticated one",
			"authenticated", publisher, "claimed", entry.IA)
	}
	entry.IA = publisher
	entry.Published = time.Now()
	s.Store.Publish(entry)
	return &nodev1.PublishResponse{}, nil
}

// List returns every published entry.
func (s *DirectoryService) List(
	ctx context.Context,
	req *nodev1.ListRequest,
) (*nodev1.ListResponse, error) {

	entries := s.Store.List(time.Now())
	resp := &nodev1.ListResponse{}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, e.pb())
	}
	return resp, nil
}

func entryFromPB(pb *nodev1.Entry) (DirectoryEntry, error) {
	control, err := netip.ParseAddrPort(pb.ControlAddr)
	if err != nil {
		return DirectoryEntry{}, fmt.Errorf("parsing control address: %w", err)
	}
	rendezvous, err := netip.ParseAddrPort(pb.RendezvousAddr)
	if err != nil {
		return DirectoryEntry{}, fmt.Errorf("parsing rendezvous address: %w", err)
	}
	return DirectoryEntry{
		IA:             addr.IA(pb.IsdAs),
		ControlAddr:    control,
		RendezvousAddr: rendezvous,
		Reach: Reach{
			BehindNAT:            pb.BehindNat,
			RendezvousUnanswered: pb.RendezvousUnanswered,
		},
	}, nil
}

func (e DirectoryEntry) pb() *nodev1.Entry {
	return &nodev1.Entry{
		IsdAs:                uint64(e.IA),
		ControlAddr:          e.ControlAddr.String(),
		RendezvousAddr:       e.RendezvousAddr.String(),
		BehindNat:            e.Reach.BehindNAT,
		RendezvousUnanswered: e.Reach.RendezvousUnanswered,
	}
}

// directoryClient is the publish and list surface, whichever side of the
// network serves it: the RPC client on every node, the local store on the
// core itself.
type directoryClient interface {
	Publish(ctx context.Context, entry DirectoryEntry) error
	List(ctx context.Context) ([]DirectoryEntry, error)
}

// storeDirectoryClient serves the core's own node from its local store: the
// core publishes and fetches beside the directory it serves.
type storeDirectoryClient struct {
	store *DirectoryStore
}

func (c storeDirectoryClient) Publish(_ context.Context, entry DirectoryEntry) error {
	entry.Published = time.Now()
	c.store.Publish(entry)
	return nil
}

func (c storeDirectoryClient) List(_ context.Context) ([]DirectoryEntry, error) {
	return c.store.List(time.Now()), nil
}

// rpcDirectoryClient publishes and fetches over the SCION-native channel
// toward the core's endpoint, the core's chain verified against the TRC.
type rpcDirectoryClient struct {
	conn      *scion.Conn
	engine    *trust.Engine
	paths     DirectoryPaths
	coreRoute func() *scion.Addr

	qclt *quic.Transport

	mtx sync.Mutex
	// hclt is the one HTTP client every request rides, built at the first
	// and pooling a connection per endpoint authority; clt serves the
	// current core endpoint, and the authority it is keyed by replaces it
	// when the core's route moves.
	hclt      *http.Client
	clt       nodev1connect.DirectoryServiceClient
	authority string
}

// client returns the ConnectRPC client for the core's endpoint, building it —
// or rebuilding it when the core's route moved — on demand. A rebuild closes
// the connections no request rides then: the replaced endpoint's, which its
// keep-alives would otherwise hold open, unused, until the age cap's next
// sweep.
func (c *rpcDirectoryClient) client() (nodev1connect.DirectoryServiceClient, error) {
	core := c.coreRoute()
	if core == nil {
		return nil, errors.New("no route to the core's endpoint yet")
	}
	authority := scionrpc.PeerAuthority(core)
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.clt != nil && c.authority == authority {
		return c.clt, nil
	}
	if c.hclt == nil {
		c.hclt = scionrpc.NewSCIONClient(scionrpc.PeerClientConfig{
			Credentials: c.engine,
			Key:         c.engine.Key,
			Conn:        c.conn,
			PathTo: func(dst addr.IA) *spath.Decoded {
				path, err := c.paths.LocalPath(dst)
				if err != nil {
					return nil
				}
				return path
			},
		}, c.qclt, true)
	}
	if c.clt != nil {
		c.hclt.CloseIdleConnections()
	}
	c.clt = nodev1connect.NewDirectoryServiceClient(connect.NewClient(
		connecthttp.NewTransport(c.hclt, "https://"+authority)))
	c.authority = authority
	return c.clt, nil
}

// Publish records the node's entry with the core.
func (c *rpcDirectoryClient) Publish(ctx context.Context, entry DirectoryEntry) error {
	clt, err := c.client()
	if err != nil {
		return err
	}
	_, err = clt.Publish(ctx, &nodev1.PublishRequest{
		Entry: entry.pb(),
	})
	return err
}

// List fetches the directory from the core.
func (c *rpcDirectoryClient) List(ctx context.Context) ([]DirectoryEntry, error) {
	clt, err := c.client()
	if err != nil {
		return nil, err
	}
	resp, err := clt.List(ctx, &nodev1.ListRequest{})
	if err != nil {
		return nil, err
	}
	entries := make([]DirectoryEntry, 0, len(resp.Entries))
	for _, pb := range resp.Entries {
		entry, err := entryFromPB(pb)
		if err != nil {
			return nil, fmt.Errorf("decoding an entry: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// NodeDirectory is the node's view of the directory: the publish loop that
// records the node's own entry once enrollment has produced its chain, the
// fetch loop that refreshes the local copy, and the snapshot the selection
// loop draws its candidates from. The measured provider runs it on every
// node; the core serves the store it publishes into.
type NodeDirectory struct {
	cfg NodeDirectoryConfig

	// client is the publish and list surface: the RPC client, or the local
	// store on the core itself.
	client directoryClient

	mtx sync.Mutex
	// local is the fetched copy; nil until the first fetch lands.
	local []DirectoryEntry
}

// DirectoryPaths is the path resolution the directory's channel calls: the
// path to the core from local state alone, safe inside the channel's dial.
type DirectoryPaths interface {
	LocalPath(dst addr.IA) (*spath.Decoded, error)
}

// NodeDirectoryConfig configures a NodeDirectory.
type NodeDirectoryConfig struct {
	// IA is the publisher's ISD-AS.
	IA addr.IA
	// Self is the topic of the node's own state: the host the entry
	// publishes — every socket keeps binding the control host whatever it
	// names, and a zero host publishes nothing — and the rendezvous answer
	// its report carries. The entry publishes at each event, beside the
	// cadence.
	Self *bus.Topic[bus.SelfState]
	// BehindNAT reports, at each publication, whether a NAT stands between
	// the node and its peers at the published host; an error fails the
	// publication. Nil reports none.
	BehindNAT func(host netip.Addr) (bool, error)
	// Engine provides the node's AS chain as the client certificate; a node
	// without a chain cannot publish.
	Engine *trust.Engine
	// Conn is the SCION connection the publish and fetch rides.
	Conn *scion.Conn
	// Paths resolves the path to the core.
	Paths DirectoryPaths
	// CoreRoute resolves the core's endpoint; nil on the core itself, which
	// serves the directory from Store.
	CoreRoute func() *scion.Addr
	// Store is the core's own directory store (core only).
	Store *DirectoryStore
	// PublishInterval, FetchInterval, and PublishRetry override the
	// defaults; zero keeps them.
	PublishInterval time.Duration
	FetchInterval   time.Duration
	PublishRetry    time.Duration
}

// NewNodeDirectory builds the node's directory view. The core keeps its own
// store as the client.
func NewNodeDirectory(cfg NodeDirectoryConfig) *NodeDirectory {
	d := &NodeDirectory{cfg: cfg}
	if cfg.CoreRoute == nil {
		d.client = storeDirectoryClient{store: cfg.Store}
		return d
	}
	rpc := &rpcDirectoryClient{
		conn:      cfg.Conn,
		engine:    cfg.Engine,
		paths:     cfg.Paths,
		coreRoute: cfg.CoreRoute,
	}
	// The transport exists only over a conn: a provider whose conn is
	// absent mounts its services without one, and Close has nothing to
	// release — quic-go's Close over a nil conn would panic.
	if cfg.Conn != nil {
		rpc.qclt = &quic.Transport{Conn: cfg.Conn}
	}
	d.client = rpc
	return d
}

// Close releases the publish and fetch transport.
func (d *NodeDirectory) Close() error {
	if rpc, ok := d.client.(*rpcDirectoryClient); ok && rpc.qclt != nil {
		return rpc.qclt.Close()
	}
	return nil
}

// Run owns the publication and fetch cadence until the context is canceled,
// returning once both loops have returned.
func (d *NodeDirectory) Run(ctx context.Context) {
	var publish sync.WaitGroup
	loops.Go(ctx, &publish, "node directory publication", d.runPublish)
	d.runFetch(ctx)
	publish.Wait()
}

// runPublish waits for enrollment to produce the node's chain, publishes the
// node's entry, and re-publishes on the cadence and at each change of the
// node's own state. A publication waiting on the node's own state polls at
// the retry; one the core refused backs off from it up to the cadence.
// Failures never stop the loop.
func (d *NodeDirectory) runPublish(ctx context.Context) {
	interval := intervalOr(d.cfg.PublishInterval, NodePublishInterval)
	retry := intervalOr(d.cfg.PublishRetry, NodePublishRetry)
	backoff := loops.Backoff{Base: retry, Max: interval}
	var self <-chan bus.SelfState
	if d.cfg.Self != nil {
		self = d.cfg.Self.Subscribe(ctx)
		// The subscription delivers the state as it stands, which the
		// first publication reads anyway.
		select {
		case <-self:
		default:
		}
	}
	for {
		wait := interval
		for range backoff.Tries(ctx) {
			err := d.publish(ctx)
			if err == nil {
				break
			}
			slog.Debug("Node directory publication", "err", err)
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

// publish sends the node's entry once the node's chain exists: an un-enrolled
// node has no certificate to authenticate the channel with. The entry is
// built, not baked: its host and its report read the node's own state at
// each publication. A zero host — the founding core's name before its first
// answer — publishes nothing, the retry re-asking.
func (d *NodeDirectory) publish(ctx context.Context) error {
	if d.cfg.Engine != nil {
		chain, err := d.cfg.Engine.Chain(ctx)
		if err != nil {
			return err
		}
		if len(chain) == 0 {
			return fmt.Errorf("%w: no certificate chain yet; enrollment has not produced one", errNotReady)
		}
	}
	self := d.cfg.Self.Latest()
	host := self.Host
	if !host.IsValid() {
		return fmt.Errorf("%w: the entry's host did not resolve", errNotReady)
	}
	reach := Reach{RendezvousUnanswered: self.RendezvousUnanswered}
	if d.cfg.BehindNAT != nil {
		var err error
		if reach.BehindNAT, err = d.cfg.BehindNAT(host); err != nil {
			return fmt.Errorf("reporting the entry's reach: %w", err)
		}
	}
	return d.client.Publish(ctx, DirectoryEntry{
		IA:             d.cfg.IA,
		ControlAddr:    netip.AddrPortFrom(host, scionrpc.EndpointPort),
		RendezvousAddr: netip.AddrPortFrom(host, RendezvousPort),
		Reach:          reach,
	})
}

// runFetch re-fetches the directory on the cadence, replacing the local copy.
func (d *NodeDirectory) runFetch(ctx context.Context) {
	interval := intervalOr(d.cfg.FetchInterval, NodeFetchInterval)
	for {
		entries, err := d.client.List(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Debug("Node directory fetch", "err", err)
		} else {
			d.mtx.Lock()
			d.local = entries
			d.mtx.Unlock()
		}
		if !loops.Sleep(ctx, interval) {
			return
		}
	}
}

// Entries returns the current local copy of the directory.
func (d *NodeDirectory) Entries() []DirectoryEntry {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	return d.local
}

func intervalOr(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}
