package topology

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/peeria"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
	nodev1connect "github.com/fancl20/cion/proto/node/v1/nodev1connect"
)

// Node directory cadence (ADR-0008): once enrolled, a node publishes its
// entry on a constant cadence and a fetch constant refreshes the local copy
// in between; entries expire without refresh.
const (
	// NodePublishInterval is the re-publication cadence.
	NodePublishInterval = time.Minute
	// NodeFetchInterval is the directory re-fetch cadence.
	NodeFetchInterval = 30 * time.Second
	// NodePublishRetry is how long publication waits before retrying — a
	// chain the enrollment loop has not produced yet, or a core that has not
	// answered.
	NodePublishRetry = 5 * time.Second
	// NodeDirectoryTTL is how long the core serves an entry without refresh.
	NodeDirectoryTTL = 5 * time.Minute
)

// DirectoryEntry is one node's publication: everything the selection loop
// needs to probe the node as a candidate. The ISD-AS comes from the
// authenticated publisher's certificate chain, never from the claim.
type DirectoryEntry struct {
	// IA is the publisher's ISD-AS.
	IA addr.IA
	// ControlAddr is the underlay address of the publisher's control
	// service; the endpoint and rendezvous ports derive from its host.
	ControlAddr netip.AddrPort
	// RendezvousAddr is the underlay address the publisher's rendezvous
	// acceptor listens on for first contact.
	RendezvousAddr netip.AddrPort
	// Private marks a node behind address translation: joinable by no one,
	// candidate for no one's redundancy floor.
	Private bool
	// Published is the publish time the core recorded.
	Published time.Time
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
	req *connect.Request[nodev1.PublishRequest],
) (*connect.Response[nodev1.PublishResponse], error) {

	publisher := peeria.AuthenticatedIA(ctx)
	if publisher.IsZero() {
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("no authenticated ISD-AS; the channel verified no chain"))
	}
	if req.Msg == nil || req.Msg.Entry == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("no entry"))
	}
	entry, err := entryFromPB(req.Msg.Entry)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("malformed entry: %w", err))
	}
	if !entry.IA.Equal(publisher) {
		slog.Warn("Node directory publish claims another ISD-AS; recording the authenticated one",
			"authenticated", publisher, "claimed", entry.IA)
	}
	entry.IA = publisher
	entry.Published = time.Now()
	s.Store.Publish(entry)
	return connect.NewResponse(&nodev1.PublishResponse{}), nil
}

// List returns every published entry.
func (s *DirectoryService) List(
	ctx context.Context,
	req *connect.Request[nodev1.ListRequest],
) (*connect.Response[nodev1.ListResponse], error) {

	entries := s.Store.List(time.Now())
	resp := &nodev1.ListResponse{}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, e.pb())
	}
	return connect.NewResponse(resp), nil
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
		Private:        pb.Private,
	}, nil
}

func (e DirectoryEntry) pb() *nodev1.Entry {
	return &nodev1.Entry{
		IsdAs:          uint64(e.IA),
		ControlAddr:    e.ControlAddr.String(),
		RendezvousAddr: e.RendezvousAddr.String(),
		Private:        e.Private,
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

// rpcDirectoryClient publishes and fetches over the SCION-native verified
// channel toward the core's endpoint, the control endpoint's client machinery
// consumed as a library.
type rpcDirectoryClient struct {
	conn      *scion.Conn
	engine    *trust.Engine
	provider  *scion.PathProvider
	coreRoute func() *scion.Addr

	qclt *quic.Transport

	mtx sync.Mutex
	// clt serves the current core endpoint; the authority it is keyed by
	// replaces it when the core's route moves.
	clt       nodev1connect.DirectoryServiceClient
	authority string
}

func (c *rpcDirectoryClient) client() (nodev1connect.DirectoryServiceClient, error) {
	core := c.coreRoute()
	if core == nil {
		return nil, errors.New("no route to the core's endpoint yet")
	}
	authority := controlplane.PeerAuthority(core)
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.clt != nil && c.authority == authority {
		return c.clt, nil
	}
	hclt := controlplane.NewSCIONClient(controlplane.PeerClientConfig{
		Engine: c.engine,
		Conn:   c.conn,
		PathTo: func(dst addr.IA) *spath.Decoded {
			path, err := c.provider.LocalPath(dst)
			if err != nil {
				return nil
			}
			return path
		},
	}, c.qclt, true)
	c.clt = nodev1connect.NewDirectoryServiceClient(hclt, "https://"+authority)
	c.authority = authority
	return c.clt, nil
}

// Publish records the node's entry with the core.
func (c *rpcDirectoryClient) Publish(ctx context.Context, entry DirectoryEntry) error {
	clt, err := c.client()
	if err != nil {
		return err
	}
	_, err = clt.Publish(ctx, connect.NewRequest(&nodev1.PublishRequest{
		Entry: entry.pb(),
	}))
	return err
}

// List fetches the directory from the core.
func (c *rpcDirectoryClient) List(ctx context.Context) ([]DirectoryEntry, error) {
	clt, err := c.client()
	if err != nil {
		return nil, err
	}
	resp, err := clt.List(ctx, connect.NewRequest(&nodev1.ListRequest{}))
	if err != nil {
		return nil, err
	}
	entries := make([]DirectoryEntry, 0, len(resp.Msg.Entries))
	for _, pb := range resp.Msg.Entries {
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

// NodeDirectoryConfig configures a NodeDirectory.
type NodeDirectoryConfig struct {
	// Entry is the node's own publication.
	Entry DirectoryEntry
	// Engine provides the node's AS chain as the client certificate; a node
	// without a chain cannot publish.
	Engine *trust.Engine
	// Conn is the SCION connection the publish and fetch rides.
	Conn *scion.Conn
	// Provider resolves the path to the core.
	Provider *scion.PathProvider
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
func NewNodeDirectory(cfg NodeDirectoryConfig) (*NodeDirectory, error) {
	d := &NodeDirectory{cfg: cfg}
	if cfg.CoreRoute == nil {
		if cfg.Store == nil {
			return nil, errors.New("the core's directory needs its store")
		}
		d.client = storeDirectoryClient{store: cfg.Store}
		return d, nil
	}
	rpc := &rpcDirectoryClient{
		conn:      cfg.Conn,
		engine:    cfg.Engine,
		provider:  cfg.Provider,
		coreRoute: cfg.CoreRoute,
	}
	// The transport exists only over a conn: a provider whose conn is
	// absent mounts its services without one, and Close has nothing to
	// release — quic-go's Close over a nil conn would panic.
	if cfg.Conn != nil {
		rpc.qclt = &quic.Transport{Conn: cfg.Conn}
	}
	d.client = rpc
	return d, nil
}

// Close releases the publish and fetch transport.
func (d *NodeDirectory) Close() error {
	if rpc, ok := d.client.(*rpcDirectoryClient); ok && rpc.qclt != nil {
		return rpc.qclt.Close()
	}
	return nil
}

// Run owns the publication and fetch cadence until the context is canceled.
func (d *NodeDirectory) Run(ctx context.Context) {
	go d.runPublish(ctx)
	d.runFetch(ctx)
}

// runPublish waits for enrollment to produce the node's chain, publishes the
// node's entry, and re-publishes on the cadence. Failures retry, never stop,
// the loop.
func (d *NodeDirectory) runPublish(ctx context.Context) {
	interval := intervalOr(d.cfg.PublishInterval, NodePublishInterval)
	retry := intervalOr(d.cfg.PublishRetry, NodePublishRetry)
	for {
		if ctx.Err() != nil {
			return
		}
		if err := d.publish(ctx); err != nil {
			slog.Debug("Node directory publication", "err", err)
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

// publish sends the node's entry once the node's chain exists: an un-enrolled
// node has no certificate to authenticate the channel with.
func (d *NodeDirectory) publish(ctx context.Context) error {
	if d.cfg.Engine != nil {
		chain, err := d.cfg.Engine.Chain(ctx)
		if err != nil {
			return err
		}
		if len(chain) == 0 {
			return errors.New("no certificate chain yet; enrollment has not produced one")
		}
	}
	return d.client.Publish(ctx, d.cfg.Entry)
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
		if !sleepCtx(ctx, interval) {
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
