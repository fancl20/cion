package wireguard

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"golang.zx2c4.com/wireguard/device"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/scion"
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
)

// PersistentKeepalive is the mesh peers' keepalive interval, a code constant
// set so sessions and paths stay warm enough that path rotation is exercised
// rather than discovered at first use.
const PersistentKeepalive = 25 * time.Second

// CountersInterval is how often the application logs its counters — the
// overlay's substitute for the operating system's tooling, which cannot see
// in-process forwarding.
const CountersInterval = time.Minute

// Config configures the application.
type Config struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// Subnet is the node's slice of the tailnet range, 100.64.0.0/10: the
	// space the coordination service allocates the node's hosts from. The
	// slice's first address is the node's own.
	Subnet netip.Prefix
	// ListenHost is the underlay host the shared host-facing UDP port binds.
	ListenHost netip.Addr
	// ListenPort is the shared host-facing UDP port — hosts are plain
	// internet clients with a single endpoint to reach.
	ListenPort uint16
	// DERP is the relay presence the node holds: received datagrams feed
	// the shared host port and sends carry the replies, so a host on a
	// network where UDP to the node cannot pass still reaches its node.
	// Nil runs no presence, and the node serves its hosts over UDP alone.
	DERP *DERPConfig
	// StateDir is the application's own state directory: the WireGuard key
	// pair's home.
	StateDir string
	// Provider resolves the paths mesh datagrams ride.
	Provider *scion.PathProvider
	// Engine provides the node's chain for the directory channel.
	Engine *Engine
	// Store is the directory store the core node's application serves, and
	// publishes and fetches through locally; nil on every other node, which
	// reaches the core's over CoreRoute instead.
	Store DirectoryStore
	// CoreRoute resolves the core's directory endpoint — its ISD-AS named by
	// the directory service — on non-core nodes.
	CoreRoute func() *scion.Addr
	// NewConn binds a SCION connection of this node on an ephemeral port:
	// the socket the mesh transport serves on, the one the core's directory
	// serves on beside it, and the one every other node's client publishes
	// and fetches through.
	NewConn func() (*scion.Conn, error)
	// RegisterSvc registers one of the application's sockets as a SCION
	// service in this AS — the same registration discovery makes for the CS
	// service over the data plane's provider — so the router delivers
	// service-addressed packets to the socket's port. Close deregisters
	// through UnregisterSvc.
	RegisterSvc func(svc addr.SVC, port uint16) error
	// UnregisterSvc deregisters a socket RegisterSvc registered.
	UnregisterSvc func(svc addr.SVC, port uint16) error
	// InterfaceDown is the node's shared negative cache of SCMP
	// interface-down signals; the mesh transport drops the cached path of
	// the destination a signal's quote names, so its next send re-resolves
	// through the filtered composition. Nil leaves the failure-and-refresh
	// behavior alone.
	InterfaceDown *scion.InterfaceDownCache

	// Cadence overrides for tests; zero means the package constant.
	PublishInterval time.Duration
	RefreshInterval time.Duration
	PublishRetry    time.Duration
}

// App is the WireGuard application: the mesh transport and directory, the one
// host-facing device behind its shared port — programmed from the host entries
// the directory distributes — and the in-process router between the tunnels,
// the surface a resident service application borrows. The node running it
// holds unprivileged UDP sockets and its own state, and nothing else.
type App struct {
	cfg Config
	key PrivateKey
	cnt *counters

	mesh   *meshSocket
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

	mtx sync.Mutex
	// meshPeers holds one mesh device per directory peer.
	meshPeers map[addr.IA]*meshPeer
	// hosts holds the one host-facing device.
	hosts *hostDevice
	// hostPeers holds the host entries the device's peers are programmed
	// from, keyed by the hosts' public keys.
	hostPeers map[PublicKey]HostEntry
}

// hostDevice is the one host-facing device: the node's key pair on the
// shared port, its peers the host entries the node owns.
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
// pair, binds the mesh socket on an ephemeral port and registers it under
// the wireguard service in its own AS, binds the shared host-facing port,
// creates one host device per offered exit with the configured peers, builds
// the router, and wires the directory surfaces: the core's store it serves
// over its own registered service socket, the route every other node
// publishes and fetches through. Run serves it.
func New(cfg Config) (*App, error) {
	if cfg.IA.IsZero() {
		return nil, fmt.Errorf("no ISD-AS configured")
	}
	if cfg.ListenPort == 0 {
		return nil, fmt.Errorf("no listen port configured")
	}
	if cfg.NewConn == nil {
		return nil, fmt.Errorf("no SCION connection builder configured")
	}
	if cfg.RegisterSvc == nil || cfg.UnregisterSvc == nil {
		return nil, fmt.Errorf("no service registration configured")
	}
	if cfg.Engine == nil || cfg.Provider == nil {
		return nil, fmt.Errorf("no trust engine or path provider configured")
	}
	if cfg.Store == nil && cfg.CoreRoute == nil {
		return nil, fmt.Errorf("neither a directory store nor a core route configured")
	}
	if err := validateSubnet(cfg.Subnet); err != nil {
		return nil, err
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
	hostConn, err := net.ListenUDP("udp",
		&net.UDPAddr{IP: cfg.ListenHost.AsSlice(), Port: int(cfg.ListenPort)})
	if err != nil {
		_ = meshConn.Close()
		return nil, fmt.Errorf("binding the host port: %w", err)
	}
	a := &App{
		cfg:       cfg,
		key:       key,
		cnt:       cnt,
		mesh:      newMeshSocket(meshConn, cfg.Provider, cnt),
		host:      newHostSocket(hostConn, cnt),
		router:    newRouter(OverlayMTU, cnt),
		meshPeers: make(map[addr.IA]*meshPeer),
		hostPeers: make(map[PublicKey]HostEntry),
		logger:    device.NewLogger(device.LogLevelError, "cion-wireguard"),
	}
	if cfg.InterfaceDown != nil {
		// The signal drops the quoted destination's cached path — the bind's
		// existing failure-and-refresh behavior, prompted by the signal
		// instead of a lost datagram.
		cfg.InterfaceDown.OnSignal(a.mesh.dropPathOf)
	}
	if err := a.register(SvcWireguard, meshConn.LocalPort()); err != nil {
		a.release()
		return nil, fmt.Errorf("registering the mesh socket: %w", err)
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
		a.dirConn = newRPCDirectoryClient(dirConn, cfg.CoreRoute, cfg.Engine, cfg.Provider)
		a.directory = a.dirConn
	}
	if cfg.DERP != nil {
		// The relay presence stands before the host device, so the device's
		// sends can return over the relay from the first datagram.
		a.bridge = newDERPBridge(derpBridgeConfig{
			Key:    key,
			Socket: a.host,
			Cnt:    cnt,
			URL:    cfg.DERP.URL,
			IPv4:   cfg.DERP.IPv4,
		})
	}
	if err := a.startHostDevice(); err != nil {
		a.release()
		return nil, err
	}
	return a, nil
}

// validateSubnet checks the slice's grammar: an IPv4 prefix the tailnet
// range contains — the space the coordination service allocates from, the
// anchor the directory already distributes.
func validateSubnet(subnet netip.Prefix) error {
	if !subnet.IsValid() || !subnet.Addr().Is4() {
		return fmt.Errorf("overlay subnet %s is not IPv4", subnet)
	}
	if !Tailnet.Contains(subnet.Addr()) || subnet.Bits() < Tailnet.Bits() {
		return fmt.Errorf("overlay subnet %s is not a slice of %s",
			subnet, Tailnet)
	}
	return nil
}

// Tailnet is the overlay's host space, the range every node's slice is a slice
// of: the tunnel carries it and nothing else — no default route is advertised
// anywhere.
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
	for i := len(a.regs) - 1; i >= 0; i-- {
		reg := a.regs[i]
		if err := a.cfg.UnregisterSvc(reg.svc, reg.port); err != nil {
			slog.Warn("WireGuard service deregistration", "service", reg.svc, "err", err)
		}
	}
	a.regs = nil
}

// release closes what New opened on a failed construction. The store stays
// the caller's: it opened it, and a construction that never returned owns
// nothing of it.
func (a *App) release() {
	a.deregisterAll()
	a.mesh.Close()
	a.host.Close()
	if a.dirConn != nil {
		_ = a.dirConn.Close()
	}
	if a.dirServe != nil {
		_ = a.dirServe.Close()
	}
}

// Router returns the overlay routing a resident service application borrows:
// the reply path its produced packets ride and the delivery installation for
// the address it serves on. Without this application there is nothing to
// borrow.
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
// the peer's entry as its endpoint and AllowedIPs — its overlay subnet, with
// 0.0.0.0/0 added when the peer is one of this node's configured exits, so
// the device's default-routed traffic finds a peer for any destination while
// WireGuard's longest-prefix peer selection keeps subnet traffic direct.
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
// and their router entries; the host entries the node owns become the host
// device's peers — a new key gains its /32, a departed key loses it — the
// same diff shape the node entries give the mesh. A later milestone's host
// removal arrives as this same diff.
func (a *App) applyDirectory(directory Directory) {
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
		go peer.pipe.drain(a.router.route)
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
	a.applyHostEntries(directory.Hosts)
	a.rebuildLocked()
}

// applyHostEntries programs the host device from the host entries the node
// owns — the entries the coordination registry distributes. The IPC diff
// adds the new keys and removes the departed ones, so a surviving peer's
// cached endpoint — the address its datagrams last arrived from, UDP or
// relay — survives the programming.
func (a *App) applyHostEntries(hosts []HostEntry) {
	if a.hosts == nil {
		return
	}
	owned := make(map[PublicKey]HostEntry, len(hosts))
	for _, host := range hosts {
		if host.IA.Equal(a.cfg.IA) {
			owned[host.PublicKey] = host
		}
	}
	var ipc strings.Builder
	for key, host := range owned {
		if _, ok := a.hostPeers[key]; ok {
			continue
		}
		ipc.WriteString("public_key=" + key.String() + "\n")
		ipc.WriteString("allowed_ip=" + netip.PrefixFrom(host.Addr, 32).String() + "\n")
	}
	for key := range a.hostPeers {
		if _, ok := owned[key]; ok {
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
	for key, host := range owned {
		if _, ok := a.hostPeers[key]; !ok {
			a.hostPeers[key] = host
			slog.Info("WireGuard host joined",
				"key", key, "addr", host.Addr, "note", host.Note)
		}
	}
	for key := range a.hostPeers {
		if _, ok := owned[key]; !ok {
			delete(a.hostPeers, key)
			slog.Info("WireGuard host departed", "key", key)
		}
	}
}

// rebuildLocked recomposes the router table from the devices; the
// application's mutex serializes rebuilds with the device set. The table
// holds the owned hosts' /32s to the host device and each node entry's
// slice to its mesh device — longest prefix first — and no default
// anywhere: a destination no slice claims counts unroutable.
func (a *App) rebuildLocked() {
	nets := make([]route, 0, len(a.meshPeers))
	for _, peer := range a.meshPeers {
		nets = append(nets, route{prefix: peer.entry.Overlay, dst: peer.pipe})
	}
	var hosts []hostRoute
	if a.hosts != nil {
		for _, host := range a.hostPeers {
			hosts = append(hosts, hostRoute{addr: host.Addr, pipe: a.hosts.pipe})
		}
	}
	a.router.rebuild(hosts, nets)
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

// HostPeers snapshots the host entries the node owns — the peers the one
// host device holds, programmed from the fetched directory.
func (a *App) HostPeers() []HostEntry {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	hosts := make([]HostEntry, 0, len(a.hostPeers))
	for _, host := range a.hostPeers {
		hosts = append(hosts, host)
	}
	return hosts
}

// Directory fetches the node's view of the registry: the core's own store
// beside it, every other node's fetched copy.
func (a *App) Directory(ctx context.Context) (Directory, error) {
	return a.directory.List(ctx)
}

// Counters snapshots the application's counters — the overlay's substitute
// for the operating system's tooling.
func (a *App) Counters() []any { return a.cnt.snapshot() }

// Registry returns the coordination surface of the core's store — nil on
// every other node, which fetches the directory over the core's route
// instead.
func (a *App) Registry() Registry {
	return a.cfg.Store
}

// Run serves the application until the context is canceled: the sockets' read
// loops, the devices' pipes through the router, the directory — served by
// the core, published and fetched by everyone — and the counters log.
func (a *App) Run(ctx context.Context) error {
	defer a.Close()
	go a.mesh.run()
	go a.host.run()
	if a.hosts != nil {
		go a.hosts.pipe.drain(a.router.route)
	}
	if a.bridge != nil {
		go a.bridge.run(ctx)
	}
	if a.cfg.Store != nil {
		a.serveDirectory(ctx)
	}
	go a.runPublish(ctx)
	go a.runSync(ctx)
	slog.Info("Serving the WireGuard application",
		"ia", a.cfg.IA, "subnet", a.cfg.Subnet,
		"listenPort", a.cfg.ListenPort,
		"publicKey", a.PublicKey())
	logTick := time.NewTicker(CountersInterval)
	defer logTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-logTick.C:
			slog.Info("WireGuard counters", a.cnt.snapshot()...)
		}
	}
}

// serveDirectory serves the core's directory on the socket New bound and
// registered under the directory service, over the application's
// authenticated channel: the control endpoint's TLS machinery, every
// publisher identified by its verified chain.
func (a *App) serveDirectory(ctx context.Context) {
	conn := a.dirServe
	go func() {
		defer func() { _ = conn.Close() }()
		if err := controlplane.ServeHTTP3(conn, a.DirectoryHandler(),
			controlplane.EndpointTLS(controlplane.EndpointTLSConfig{
				Engine: a.cfg.Engine,
			})); err != nil && ctx.Err() == nil {
			slog.Error("WireGuard directory service exited", "err", err)
		}
	}()
	slog.Info("Serving the WireGuard directory", "service", serviceName(SvcDirectory))
}

// DirectoryHandler is the core's directory HTTP handler: the ConnectRPC
// service behind the middleware that peers each request's verified chain
// into its context.
func (a *App) DirectoryHandler() http.Handler {
	path, handler := wireguardv1connect.NewDirectoryServiceHandler(
		&DirectoryService{Store: a.cfg.Store, Cnt: a.cnt})
	mux := http.NewServeMux()
	mux.Handle(path, Authenticate(handler))
	return mux
}

// Close releases the application: the devices close, the sockets retire with
// their service registrations, the flow state expires, and the store closes;
// no operating-system provisioning exists to undo.
func (a *App) Close() {
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
	a.deregisterAll()
	a.mesh.Close()
	a.host.Close()
	if a.dirConn != nil {
		_ = a.dirConn.Close()
	}
	if a.dirServe != nil {
		_ = a.dirServe.Close()
	}
	if a.cfg.Store != nil {
		_ = a.cfg.Store.Close()
	}
}
