package wireguard

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/scionproto/scion/pkg/addr"
	"go.opentelemetry.io/otel"
	"golang.zx2c4.com/wireguard/device"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	wireguardv1connect "github.com/fancl20/cion/proto/wireguard/v1/wireguardv1connect"
)

// OverlayMTU is the overlay's maximum inner packet: an inner packet of 1280
// bytes plus WireGuard's data overhead (~32), the outer IPv4 and UDP headers
// (28), and a worst-case SCION header stack (~156 for a long composed path)
// stays within a standard 1500-byte MTU. The router enforces the constant —
// no kernel TUN exists to do it.
const OverlayMTU = 1280

// CION's private SCION service values. The drafts' registry names the low
// values — DS 0x0001, CS 0x0002, the wildcard 0x0010 — and the SVC type's top
// bit is the multicast flag, so CION's own services take a private slice above
// both, 0x7ff1 through 0x7fff. The drafts define no WireGuard service: the
// values are CION's to allocate, the convention proto/wireguard/v1 is.
const (
	// SvcWireguard is the mesh transport service. Every node's application
	// registers its mesh socket under this value in its own AS.
	SvcWireguard addr.SVC = 0x7ff1
	// SvcDirectory is the core's directory service. The core node's
	// application registers its directory socket under this value.
	SvcDirectory addr.SVC = 0x7ff2
	// SvcHostRelay is the host relay service. Every node's application
	// registers its relay socket under this value in its own AS: a host's
	// node relays the host's datagrams for another node to that node's
	// relay service, and the node answers to the relaying node's.
	SvcHostRelay addr.SVC = 0x7ff3
)

// PersistentKeepalive is the mesh peers' keepalive interval, a code constant
// set so sessions and paths stay warm enough that path rotation is exercised
// rather than discovered at first use. A keepalive reads its peer's lease
// without use, so a peer kept alive but idle goes unprobed.
const PersistentKeepalive = 25 * time.Second

// Paths is the node's path resolution the application calls: each
// destination's lease, the path its sends and its directory channel ride.
type Paths interface {
	Lease(dst addr.IA) *scion.Lease
}

// Config configures the application.
type Config struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// ListenHost is the underlay host the shared host-facing UDP port binds.
	ListenHost netip.Addr
	// ListenPort is the shared host-facing UDP port — hosts are plain
	// internet clients with a single endpoint to reach.
	ListenPort uint16
	// Self is the topic of the node's own state, whose host the entry's
	// host-facing endpoint prefers at each publication: the host the node's
	// peers see it at, the founding core's domain address. A state that
	// names none leaves the bind host — a wildcard bind naming neither holds
	// the publication for the cadence's retry — and each event publishes the
	// entry anew.
	Self *bus.Topic[bus.SelfState]
	// Tailnet is the topic the application publishes its view of the
	// directory on: the node's slice once the directory assigns it, beside
	// the node and host entries of the last directory it applied, published
	// at the assignment and at each applied directory that changes the view.
	Tailnet *bus.Topic[bus.TailnetState]
	// DERP is the relay presence the node holds: received datagrams feed
	// the shared host port and sends carry the replies, so a host on a
	// network where UDP to the node cannot pass still reaches its node.
	// Nil runs no presence, and the node serves its hosts over UDP alone.
	DERP *DERPConfig
	// StateDir is the application's own state directory: the WireGuard key
	// pair's home.
	StateDir string
	// Paths leases the paths mesh datagrams and the directory channel ride.
	Paths Paths
	// Engine provides the node's chain for the directory channel.
	Engine *Engine
	// Store is the directory store the core node's application serves, and
	// publishes and fetches through locally; nil on every other node, which
	// reaches the core's over FounderRoute instead.
	Store DirectoryStore
	// FounderRoute resolves the founding core's directory endpoint — its
	// ISD-AS named by the directory service — on non-core nodes.
	FounderRoute func() *scion.Addr
	// NewConn binds a SCION connection of this node on an ephemeral port:
	// the socket the mesh transport serves on, the relay socket beside it,
	// the one the core's directory serves on, and the one every other
	// node's client publishes and fetches through.
	NewConn func() (*scion.Conn, error)
	// RegisterSvc registers one of the application's sockets as a SCION
	// service in this AS — the same registration discovery makes for the CS
	// service over the data plane's provider — so the router delivers
	// service-addressed packets to the socket's port. Close deregisters
	// through UnregisterSvc.
	RegisterSvc func(svc addr.SVC, port uint16) error
	// UnregisterSvc deregisters a socket RegisterSvc registered.
	UnregisterSvc func(svc addr.SVC, port uint16) error

	// Cadence overrides for tests; zero means the package constant.
	PublishInterval time.Duration
	RefreshInterval time.Duration
	PublishRetry    time.Duration
}

// App is the WireGuard application: the mesh transport and directory, the one
// host-facing device behind its shared port — programmed from the host entries
// the directory distributes — with the relay that carries the node's hosts'
// sessions with other nodes, and the in-process router between the tunnels,
// the surface a resident service application borrows. The node running it
// holds unprivileged UDP sockets and its own state, and nothing else.
type App struct {
	cfg Config
	key PrivateKey
	cnt *counters

	mesh   *meshSocket
	relay  *hostRelay
	host   *hostSocket
	router *router

	directory directoryClient
	dirConn   *rpcDirectoryClient
	dirServe  *scion.Conn

	// regs holds the service registrations the sockets made in their own AS,
	// for Close to undo.
	regs []svcReg

	// logger is wireguard-go's device logger.
	logger *device.Logger

	// bridge is the node's DERP presence, when configured.
	bridge *derpBridge

	// wg joins Run's loops and the mesh peers' drains applyDirectory starts
	// beneath the sync loop.
	wg        sync.WaitGroup
	closeOnce sync.Once

	mtx sync.Mutex
	// meshPeers holds one mesh device per directory peer.
	meshPeers map[addr.IA]*meshPeer
	// hosts holds the one host-facing device.
	hosts *hostDevice
	// hostPeers holds the host entries the device's peers are programmed
	// from — every host the directory holds — keyed by the hosts' public
	// keys.
	hostPeers map[PublicKey]HostEntry
	// subnet is the slice the directory assigned — set once, when the
	// publication's answer arrives, and assigned closes to wake the waits
	// on it.
	subnet   netip.Prefix
	assigned chan struct{}
	// tailnet is the view last published on the tailnet topic.
	tailnet bus.TailnetState
}

// hostDevice is the one host-facing device: the node's key pair on the
// shared port, its peers every host entry the directory holds.
type hostDevice struct {
	dev  *device.Device
	pipe *pipe
}

// meshPeer is one directory peer's mesh device.
type meshPeer struct {
	entry Entry
	dev   *device.Device
	pipe  *pipe
}

// svcReg is one socket's registration as a SCION service in its own AS.
type svcReg struct {
	svc  addr.SVC
	port uint16
}

// New assembles the application: it loads or creates the node's WireGuard key
// pair, binds the mesh socket and the relay socket on ephemeral ports and
// registers them under the wireguard and host relay services in its own AS,
// binds the shared host-facing port, creates the one host device, builds the
// router, and wires the directory surfaces: the core's store it serves over
// its own registered service socket, the route every other node publishes
// and fetches through. Run serves it.
func New(cfg Config) (*App, error) {
	if cfg.Self == nil {
		return nil, fmt.Errorf("no topic of the node's own state")
	}
	if cfg.Tailnet == nil {
		return nil, fmt.Errorf("no tailnet topic")
	}
	key, err := LoadOrCreateKey(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("loading the application key: %w", err)
	}
	cnt := &counters{}
	meshConn, err := cfg.NewConn()
	if err != nil {
		return nil, fmt.Errorf("binding the mesh socket: %w", err)
	}
	relayConn, err := cfg.NewConn()
	if err != nil {
		_ = meshConn.Close()
		return nil, fmt.Errorf("binding the relay socket: %w", err)
	}
	hostConn, err := net.ListenUDP("udp",
		&net.UDPAddr{IP: cfg.ListenHost.AsSlice(), Port: int(cfg.ListenPort)})
	if err != nil {
		_ = meshConn.Close()
		_ = relayConn.Close()
		return nil, fmt.Errorf("binding the host port: %w", err)
	}
	mesh := newMeshSocket(meshConn, cfg.Paths, cnt)
	relay := newHostRelay(cfg.IA, key.PublicKey(), relayConn, mesh, cnt)
	a := &App{
		cfg:       cfg,
		key:       key,
		cnt:       cnt,
		mesh:      mesh,
		relay:     relay,
		host:      newHostSocket(hostConn, relay, cnt),
		router:    newRouter(OverlayMTU, cnt),
		meshPeers: make(map[addr.IA]*meshPeer),
		hostPeers: make(map[PublicKey]HostEntry),
		assigned:  make(chan struct{}),
		logger:    device.NewLogger(device.LogLevelError, "cion-wireguard"),
	}
	if err := a.register(SvcWireguard, meshConn.LocalPort()); err != nil {
		a.release()
		return nil, fmt.Errorf("registering the mesh socket: %w", err)
	}
	if err := a.register(SvcHostRelay, relayConn.LocalPort()); err != nil {
		a.release()
		return nil, fmt.Errorf("registering the relay socket: %w", err)
	}
	if cfg.Store != nil {
		a.directory = storeDirectoryClient{store: cfg.Store}
		// The core serves the directory on a socket of its own, registered
		// under the directory service the way the mesh socket is under the
		// wireguard service.
		dirServe, err := cfg.NewConn()
		if err != nil {
			a.release()
			return nil, fmt.Errorf("binding the directory socket: %w", err)
		}
		a.dirServe = dirServe
		if err := a.register(SvcDirectory, dirServe.LocalPort()); err != nil {
			a.release()
			return nil, fmt.Errorf("registering the directory socket: %w", err)
		}
	} else {
		dirConn, err := cfg.NewConn()
		if err != nil {
			a.release()
			return nil, fmt.Errorf("binding the directory socket: %w", err)
		}
		a.dirConn = newRPCDirectoryClient(dirConn, cfg.FounderRoute, cfg.Engine, cfg.Paths)
		a.directory = a.dirConn
	}
	if cfg.DERP != nil {
		// The relay presence stands before the host device, so the device's
		// sends can return over the relay from the first datagram.
		a.bridge = newDERPBridge(derpBridgeConfig{
			Key:       key,
			Socket:    a.host,
			Cnt:       cnt,
			URL:       cfg.DERP.URL,
			Resolvers: cfg.DERP.Resolvers,
			IPv4:      cfg.DERP.IPv4,
		})
	}
	if err := a.startHostDevice(); err != nil {
		a.release()
		return nil, err
	}
	return a, nil
}

// validateAssignment checks the assigned slice fail-fast: a /24 the tailnet
// range contains, the shape the store's assignment guarantees — a core that
// answers anything else surfaces at the publication, the seam nearest it,
// rather than deep in the netstack.
func validateAssignment(subnet netip.Prefix) error {
	if !subnet.IsValid() || !subnet.Addr().Is4() || subnet.Bits() != 24 ||
		!Tailnet.Contains(subnet.Addr()) {
		return fmt.Errorf("the assigned slice %s is not a /24 of the tailnet range %s",
			subnet, Tailnet)
	}
	return nil
}

// Tailnet is the overlay's host space, the range every node's slice is a slice
// of. A destination outside it is the internet, which only the host device's
// packets reach, through the router's default delivery.
var Tailnet = netip.MustParsePrefix("100.64.0.0/10")

// register registers a socket's port as a SCION service in this AS and
// records the registration for Close to undo.
func (a *App) register(svc addr.SVC, port uint16) error {
	if err := a.cfg.RegisterSvc(svc, port); err != nil {
		return err
	}
	a.regs = append(a.regs, svcReg{svc: svc, port: port})
	return nil
}

// deregisterAll undoes the recorded registrations, most recent first.
func (a *App) deregisterAll() {
	for _, reg := range slices.Backward(a.regs) {
		if err := a.cfg.UnregisterSvc(reg.svc, reg.port); err != nil {
			slog.Warn("WireGuard service deregistration", "service", reg.svc, "err", err)
		}
	}
	a.regs = nil
}

// release closes what New opened beneath the devices: the service
// registrations undo, and the sockets and the directory client close. A
// failed construction runs it alone — the store stays the caller's: it opened
// it, and a construction that never returned owns nothing of it — and Close
// runs it between the devices and the store.
func (a *App) release() {
	a.deregisterAll()
	a.mesh.Close()
	a.relay.Close()
	a.host.Close()
	if a.dirConn != nil {
		_ = a.dirConn.Close()
	}
	if a.dirServe != nil {
		_ = a.dirServe.Close()
	}
}

// Router returns the overlay routing a resident service application borrows:
// the reply path its produced packets ride, the delivery installation for
// the address it serves on, and the default delivery of the hosts' packets
// for the internet. Without this application there is nothing to borrow.
func (a *App) Router() Router { return a.router }

// startHostDevice creates the one host device on the shared port's
// dispatcher — the node's key pair, no peers yet: the peers arrive with the
// host entries the directory distributes, the diff applyDirectory programs.
func (a *App) startHostDevice() error {
	pipe := newPipe("host", OverlayMTU, a.cnt)
	dev := device.NewDevice(pipe, newHostBind(a.host, a.bridge), a.logger)
	ipc := "private_key=" + hex.EncodeToString(a.key[:]) + "\n" +
		"listen_port=" + strconv.Itoa(int(a.host.LocalPort())) + "\n" +
		"replace_peers=true\n"
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		_ = pipe.Close()
		return fmt.Errorf("configuring the host device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		_ = pipe.Close()
		return fmt.Errorf("raising the host device: %w", err)
	}
	a.hosts = &hostDevice{dev: dev, pipe: pipe}
	return nil
}

// newMeshDevice builds one directory peer's mesh device: the node's key pair,
// and the peer's entry as its endpoint and allowed IPs — its overlay slice
// alone, for the mesh carries tailnet traffic and nothing else.
func (a *App) newMeshDevice(entry Entry) (*meshPeer, error) {
	bind := newMeshBind(a.mesh)
	pipe := newPipe("mesh-"+entry.IA.String(), OverlayMTU, a.cnt)
	dev := device.NewDevice(pipe, bind, a.logger)
	var ipc strings.Builder
	ipc.WriteString("private_key=" + hex.EncodeToString(a.key[:]) + "\n")
	ipc.WriteString("replace_peers=true\n")
	ipc.WriteString("public_key=" + entry.PublicKey.String() + "\n")
	ipc.WriteString("endpoint=" + endpointString(entry.IA) + "\n")
	ipc.WriteString("allowed_ip=" + entry.Overlay.String() + "\n")
	ipc.WriteString("persistent_keepalive_interval=" +
		strconv.Itoa(int(PersistentKeepalive.Seconds())) + "\n")
	if err := dev.IpcSet(ipc.String()); err != nil {
		dev.Close()
		_ = pipe.Close()
		return nil, fmt.Errorf("configuring the mesh device for %s: %w", entry.IA, err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		_ = pipe.Close()
		return nil, fmt.Errorf("raising the mesh device for %s: %w", entry.IA, err)
	}
	return &meshPeer{entry: entry, dev: dev, pipe: pipe}, nil
}

// applyDirectory diffs a fetched directory against the mesh devices and the
// one host device: new mesh peers gain a device, departed peers lose theirs
// and their router entries; every host entry becomes a host device peer — a
// new key gains its /32, a departed key loses it — the same diff shape the
// node entries give the mesh, and the node entries key the relay's checkers.
// A later milestone's host removal arrives as this same diff. A new peer's
// drain joins the application's wait group and returns when ctx ends or the
// peer departs. The directory's entries beside the node's slice become the
// tailnet topic's view, published when they change it.
func (a *App) applyDirectory(ctx context.Context, directory Directory) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	live := make(map[addr.IA]bool, len(directory.Nodes))
	for _, entry := range directory.Nodes {
		if entry.IA.Equal(a.cfg.IA) {
			continue
		}
		live[entry.IA] = true
		if _, ok := a.meshPeers[entry.IA]; ok {
			continue
		}
		peer, err := a.newMeshDevice(entry)
		if err != nil {
			// A directory entry that fails to raise a device queues a
			// refresh and logs rather than erroring the application.
			slog.Warn("WireGuard mesh device", "peer", entry.IA, "err", err)
			continue
		}
		a.meshPeers[entry.IA] = peer
		a.wg.Go(func() { peer.pipe.drain(ctx, a.router.route) })
		slog.Info("WireGuard mesh tunnel up", "peer", entry.IA, "subnet", entry.Overlay)
	}
	for ia, peer := range a.meshPeers {
		if live[ia] {
			continue
		}
		peer.dev.Close()
		_ = peer.pipe.Close()
		delete(a.meshPeers, ia)
		slog.Info("WireGuard mesh tunnel down", "peer", ia)
	}
	a.relay.setNodes(directory.Nodes)
	a.applyHostEntries(directory.Hosts)
	a.rebuildLocked()
	a.publishTailnetLocked(tailnetView(a.subnet, directory))
}

// applyHostEntries programs the host device from every host entry the
// directory holds — the entries the coordination registry distributes — each
// with its /32, so the node accepts a session from any host. The IPC diff
// adds the new keys and removes the departed ones, so a surviving peer's
// cached endpoint — the leg its datagrams last arrived on, UDP, DERP, or
// relay — survives the programming.
func (a *App) applyHostEntries(hosts []HostEntry) {
	if a.hosts == nil {
		return
	}
	all := make(map[PublicKey]HostEntry, len(hosts))
	for _, host := range hosts {
		all[host.PublicKey] = host
	}
	var ipc strings.Builder
	for key, host := range all {
		if _, ok := a.hostPeers[key]; ok {
			continue
		}
		ipc.WriteString("public_key=" + key.String() + "\n")
		ipc.WriteString("allowed_ip=" + netip.PrefixFrom(host.Addr, 32).String() + "\n")
	}
	for key := range a.hostPeers {
		if _, ok := all[key]; ok {
			continue
		}
		ipc.WriteString("public_key=" + key.String() + "\n")
		ipc.WriteString("remove=true\n")
	}
	if ipc.Len() > 0 {
		if err := a.hosts.dev.IpcSet(ipc.String()); err != nil {
			slog.Warn("WireGuard host device", "err", err)
			return
		}
	}
	for key, host := range all {
		if _, ok := a.hostPeers[key]; !ok {
			a.hostPeers[key] = host
			slog.Info("WireGuard host joined",
				"key", key, "addr", host.Addr, "ia", host.IA, "note", host.Note)
		}
	}
	for key := range a.hostPeers {
		if _, ok := all[key]; !ok {
			delete(a.hostPeers, key)
			slog.Info("WireGuard host departed", "key", key)
		}
	}
}

// rebuildLocked recomposes the router table from the devices; the
// application's mutex serializes rebuilds with the device set. The table
// holds every directory host on the host device, the owned marked as the
// hosts forwarded packets reach, and each node entry's slice to its mesh
// device — longest prefix first.
func (a *App) rebuildLocked() {
	nets := make([]route, 0, len(a.meshPeers))
	for _, peer := range a.meshPeers {
		nets = append(nets, route{prefix: peer.entry.Overlay, dst: peer.pipe})
	}
	var hostPipe *pipe
	var hosts []hostRoute
	if a.hosts != nil {
		hostPipe = a.hosts.pipe
		for _, host := range a.hostPeers {
			hosts = append(hosts, hostRoute{addr: host.Addr, owned: host.IA.Equal(a.cfg.IA)})
		}
	}
	a.router.rebuild(hostPipe, hosts, nets)
}

// PublicKey returns the node's WireGuard public key — the public key a
// host's client configuration peers with.
func (a *App) PublicKey() PublicKey {
	return a.key.PublicKey()
}

// HostPort returns the shared host-facing UDP port — the one port every
// host dials.
func (a *App) HostPort() uint16 {
	return a.cfg.ListenPort
}

// MeshPeers snapshots the ISD-ASes the directory has produced mesh devices
// for.
func (a *App) MeshPeers() []addr.IA {
	return a.meshPeerIAs()
}

// HostPeers snapshots the host entries the node owns — the hosts its router
// forwards to — among the host device's peers, which are every host entry
// the fetched directory holds.
func (a *App) HostPeers() []HostEntry {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	hosts := make([]HostEntry, 0, len(a.hostPeers))
	for _, host := range a.hostPeers {
		if host.IA.Equal(a.cfg.IA) {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// Directory fetches the node's view of the registry: the core's own store
// beside it, every other node's fetched copy.
func (a *App) Directory(ctx context.Context) (Directory, error) {
	return a.directory.List(ctx)
}

// Counters snapshots the application's counters by the names the process's
// meter serves them by.
func (a *App) Counters() map[string]int64 { return a.cnt.values() }

// Registry returns the coordination surface of the core's store — nil on
// every other node, which fetches the directory over the core's route
// instead.
func (a *App) Registry() Registry {
	return a.cfg.Store
}

// Run serves the application until the context is canceled: the sockets'
// readers, the relay socket's among them, the host device's drain, the DERP
// presence, the directory — served by the core, published and fetched by
// everyone — and the counters on the process's meter. It returns once every
// goroutine it started has returned, the mesh peers' drains among them, and
// leaves what New bound to Close.
func (a *App) Run(ctx context.Context) error {
	served, err := a.cnt.serve(otel.GetMeterProvider().Meter(meterScope), a.cfg.IA)
	if err != nil {
		return fmt.Errorf("serving the WireGuard counters: %w", err)
	}
	defer func() { _ = served.Unregister() }()
	loops.Go(ctx, &a.wg, "wireguard mesh socket", a.mesh.run)
	loops.Go(ctx, &a.wg, "wireguard host socket", a.host.run)
	loops.Go(ctx, &a.wg, "wireguard relay socket", a.host.runRelay)
	if a.hosts != nil {
		pipe := a.hosts.pipe
		loops.Go(ctx, &a.wg, "wireguard host drain", func(ctx context.Context) {
			pipe.drain(ctx, a.router.routeFromHost)
		})
	}
	if a.bridge != nil {
		loops.Go(ctx, &a.wg, "wireguard relay presence", a.bridge.run)
	}
	if a.cfg.Store != nil {
		loops.Go(ctx, &a.wg, "wireguard directory service", a.serveDirectory)
	}
	loops.Go(ctx, &a.wg, "wireguard directory publication", a.runPublish)
	loops.Go(ctx, &a.wg, "wireguard directory sync", a.runSync)
	slog.Info("Serving the WireGuard application",
		"ia", a.cfg.IA, "listenPort", a.cfg.ListenPort,
		"publicKey", a.PublicKey())
	<-ctx.Done()
	a.wg.Wait()
	return nil
}

// serveDirectory serves the core's directory on the socket New bound and
// registered under the directory service, over the application's
// authenticated channel — the SCION-native channel's TLS, every publisher
// identified by its verified chain — until the context ends, and returns
// with the socket closed and every request's handler returned. Close closes
// the socket again, harmlessly.
func (a *App) serveDirectory(ctx context.Context) {
	slog.Info("Serving the WireGuard directory", "service", serviceName(SvcDirectory))
	if err := scionrpc.ServeHTTP3(ctx, a.dirServe, a.DirectoryHandler(),
		scionrpc.EndpointTLS(scionrpc.EndpointTLSConfig{
			Credentials: a.cfg.Engine,
			Key:         a.cfg.Engine.Key,
		})); err != nil && ctx.Err() == nil {
		slog.Error("WireGuard directory service exited", "err", err)
	}
}

// DirectoryHandler is the core's directory HTTP handler: the ConnectRPC
// service registered on a connect server, connecthttp.Mount spreading it
// over a private mux, behind the middleware that peers each request's
// verified chain into its context.
func (a *App) DirectoryHandler() http.Handler {
	server := connect.NewServer()
	wireguardv1connect.RegisterDirectoryServiceHandler(server,
		&DirectoryService{Store: a.cfg.Store, Cnt: a.cnt})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	return Authenticate(mux)
}

// Close releases what New bound: the devices close, the sockets retire with
// their service registrations, and the store closes last; no operating-system
// provisioning exists to undo. It runs once Run has returned, or alone when
// Run never ran, and a second call releases nothing.
func (a *App) Close() {
	a.closeOnce.Do(func() {
		a.mtx.Lock()
		defer a.mtx.Unlock()
		for _, peer := range a.meshPeers {
			peer.dev.Close()
			_ = peer.pipe.Close()
		}
		a.meshPeers = nil
		if a.hosts != nil {
			a.hosts.dev.Close()
			_ = a.hosts.pipe.Close()
			a.hosts = nil
		}
		a.hostPeers = nil
		a.release()
		if a.cfg.Store != nil {
			_ = a.cfg.Store.Close()
		}
	})
}
