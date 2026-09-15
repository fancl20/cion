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
	gatewayv1connect "github.com/fancl20/cion/proto/gateway/v1/gatewayv1connect"
)

// OverlayMTU is the overlay's maximum inner packet: an inner packet of 1280
// bytes plus WireGuard's data overhead (~32), the outer IPv4 and UDP headers
// (28), and a worst-case SCION header stack (~156 for a long composed path)
// stays within a standard 1500-byte MTU. The router enforces the constant —
// no kernel TUN exists to do it.
const OverlayMTU = 1280

// CION's private SCION service values (proposal 0007). The drafts' registry
// names the low values — DS 0x0001, CS 0x0002, the wildcard 0x0010 — and the
// SVC type's top bit is the multicast flag, so CION's own services take a
// private slice above both, 0x7ff1 through 0x7fff. The drafts define no
// gateway service: the values are CION's to allocate, the convention
// proto/gateway/v1 is.
const (
	// SvcGateway is the mesh transport service. Every node's gateway
	// registers its mesh socket under this value in its own AS.
	SvcGateway addr.SVC = 0x7ff1
	// SvcDirectory is the core's directory service. The core node's gateway
	// registers its directory socket under this value.
	SvcDirectory addr.SVC = 0x7ff2
)

// PersistentKeepalive is the mesh peers' keepalive interval, a code constant
// set so sessions and paths stay warm enough that path rotation is exercised
// rather than discovered at first use.
const PersistentKeepalive = 25 * time.Second

// CountersInterval is how often the gateway logs its counters — the overlay's
// substitute for the operating system's tooling, which cannot see in-process
// forwarding.
const CountersInterval = time.Minute

// HostPeer is one configured host: its public key — the operator's list, the
// gateway's membership — its overlay address, and its exit.
type HostPeer struct {
	// PublicKey is the host's WireGuard public key.
	PublicKey PublicKey
	// Addr is the host's overlay address, inside the node's subnet.
	Addr netip.Addr
	// Exit is the exit ISD-AS the host sends through; the key it sends with
	// selects it.
	Exit addr.IA
}

// Config configures the gateway application.
type Config struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// Subnet is the node's operator-assigned overlay subnet; host addresses
	// are assigned within it by the peer configuration.
	Subnet netip.Prefix
	// ListenHost is the underlay host the shared host-facing UDP port binds.
	ListenHost netip.Addr
	// ListenPort is the shared host-facing UDP port — hosts are plain
	// internet clients with a single endpoint to reach.
	ListenPort uint16
	// Egress marks an internet exit: the node runs the netstack egress only
	// when set.
	Egress bool
	// Exits lists the offered exit ISD-ASes; one host device serves each,
	// and every configured peer's exit must be among them.
	Exits []addr.IA
	// Peers lists the host public keys, addresses, and each peer's exit.
	Peers []HostPeer
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

	// Cadence overrides for tests; zero means the package constant.
	PublishInterval time.Duration
	RefreshInterval time.Duration
	PublishRetry    time.Duration
}

// Gateway is the WireGuard gateway application (proposal 0006): the mesh
// transport and directory, the host-facing devices behind their shared port,
// the in-process router between the tunnels, and — on an exit — the netstack
// egress. A gateway node holds unprivileged UDP sockets and its own state,
// and nothing else.
type Gateway struct {
	cfg Config
	key PrivateKey
	cnt *counters

	mesh   *meshSocket
	host   *hostSocket
	router *router
	egress *egress

	directory directoryClient
	dirConn   *rpcDirectoryClient
	dirServe  *scion.Conn

	// regs holds the service registrations the sockets made in their own AS,
	// for Close to undo.
	regs []svcReg

	// logger is wireguard-go's device logger.
	logger *device.Logger

	mtx sync.Mutex
	// meshPeers holds one mesh device per directory peer.
	meshPeers map[addr.IA]*meshPeer
	// hostDevices holds one device per offered exit.
	hostDevices map[addr.IA]*hostDevice
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

// hostDevice is one exit's host-facing device.
type hostDevice struct {
	exit addr.IA
	dev  *device.Device
	pipe *pipe
}

// New assembles the gateway: it loads or creates the node's WireGuard key
// pair, binds the mesh socket on an ephemeral port and registers it under
// the gateway service in its own AS, binds the shared host-facing port,
// creates one host device per offered exit with the configured peers, builds
// the router and — when the node is an exit — the netstack egress, and wires
// the directory surfaces: the core's store it serves over its own registered
// service socket, the route every other node publishes and fetches through.
// Run serves it.
func New(cfg Config) (*Gateway, error) {
	if cfg.IA.IsZero() {
		return nil, fmt.Errorf("no ISD-AS configured")
	}
	if !cfg.Subnet.IsValid() || !cfg.Subnet.Addr().Is4() {
		return nil, fmt.Errorf("overlay subnet %s is not IPv4", cfg.Subnet)
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
	if err := validatePeers(cfg); err != nil {
		return nil, err
	}
	key, err := LoadOrCreateKey(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("loading the gateway key: %w", err)
	}
	cnt := &counters{}
	meshConn, err := cfg.NewConn()
	if err != nil {
		return nil, fmt.Errorf("binding the mesh socket: %w", err)
	}
	hostConn, err := net.ListenUDP("udp",
		&net.UDPAddr{IP: cfg.ListenHost.AsSlice(), Port: int(cfg.ListenPort)})
	if err != nil {
		meshConn.Close() //nolint:errcheck
		return nil, fmt.Errorf("binding the host port: %w", err)
	}
	g := &Gateway{
		cfg:         cfg,
		key:         key,
		cnt:         cnt,
		mesh:        newMeshSocket(meshConn, cfg.Provider, cnt),
		host:        newHostSocket(hostConn, cnt),
		router:      newRouter(OverlayMTU, cnt),
		meshPeers:   make(map[addr.IA]*meshPeer),
		hostDevices: make(map[addr.IA]*hostDevice),
		logger:      device.NewLogger(device.LogLevelError, "cion-wireguard"),
	}
	if err := g.register(SvcGateway, meshConn.LocalPort()); err != nil {
		g.release()
		return nil, fmt.Errorf("registering the mesh socket: %w", err)
	}
	if cfg.Egress {
		overlayAddr, err := firstAddr(cfg.Subnet)
		if err != nil {
			g.release()
			return nil, err
		}
		e, err := newEgress(egressConfig{
			OverlayAddr:   overlayAddr,
			OverlayPrefix: cfg.Subnet,
			MTU:           OverlayMTU,
			Cnt:           cnt,
		})
		if err != nil {
			g.release()
			return nil, err
		}
		g.egress = e
		g.router.setEgress(e.Inbound)
		e.setRouter(g.router.routeFromEgress)
	}
	if cfg.Store != nil {
		g.directory = storeDirectoryClient{store: cfg.Store}
		// The core serves the directory on a socket of its own, registered
		// under the directory service the way the mesh socket is under the
		// gateway service.
		dirServe, err := cfg.NewConn()
		if err != nil {
			g.release()
			return nil, fmt.Errorf("binding the directory socket: %w", err)
		}
		g.dirServe = dirServe
		if err := g.register(SvcDirectory, dirServe.LocalPort()); err != nil {
			g.release()
			return nil, fmt.Errorf("registering the directory socket: %w", err)
		}
	} else {
		dirConn, err := cfg.NewConn()
		if err != nil {
			g.release()
			return nil, fmt.Errorf("binding the directory socket: %w", err)
		}
		g.dirConn = newRPCDirectoryClient(dirConn, cfg.CoreRoute, cfg.Engine, cfg.Provider)
		g.directory = g.dirConn
	}
	if err := g.startHostDevices(); err != nil {
		g.release()
		return nil, err
	}
	return g, nil
}

// register registers a socket's port as a SCION service in this AS and
// records the registration for Close to undo.
func (g *Gateway) register(svc addr.SVC, port uint16) error {
	if err := g.cfg.RegisterSvc(svc, port); err != nil {
		return err
	}
	g.regs = append(g.regs, svcReg{svc: svc, port: port})
	return nil
}

// deregisterAll undoes the recorded registrations, most recent first.
func (g *Gateway) deregisterAll() {
	for i := len(g.regs) - 1; i >= 0; i-- {
		reg := g.regs[i]
		if err := g.cfg.UnregisterSvc(reg.svc, reg.port); err != nil {
			slog.Warn("Gateway service deregistration", "service", reg.svc, "err", err)
		}
	}
	g.regs = nil
}

// release closes what New opened on a failed construction. The store stays
// the caller's: it opened it, and a construction that never returned owns
// nothing of it.
func (g *Gateway) release() {
	g.deregisterAll()
	g.mesh.Close()
	g.host.Close()
	if g.egress != nil {
		g.egress.link.Close()
	}
	if g.dirConn != nil {
		g.dirConn.Close() //nolint:errcheck
	}
	if g.dirServe != nil {
		g.dirServe.Close() //nolint:errcheck
	}
}

// validatePeers checks the operator's list: addresses inside the subnet,
// exits configured, one exit per key.
func validatePeers(cfg Config) error {
	exits := make(map[addr.IA]bool, len(cfg.Exits))
	for _, exit := range cfg.Exits {
		exits[exit] = true
	}
	seen := make(map[PublicKey]bool, len(cfg.Peers))
	for _, p := range cfg.Peers {
		if !cfg.Subnet.Contains(p.Addr) {
			return fmt.Errorf("host %s is outside the subnet %s", p.Addr, cfg.Subnet)
		}
		if !exits[p.Exit] {
			return fmt.Errorf("host %s uses exit %s, which the node does not offer",
				p.Addr, p.Exit)
		}
		if seen[p.PublicKey] {
			return fmt.Errorf("host key %s configured more than once", p.PublicKey)
		}
		seen[p.PublicKey] = true
	}
	return nil
}

// firstAddr returns the first usable address of a prefix — the exit node's
// own overlay address, which the netstack claims.
func firstAddr(prefix netip.Prefix) (netip.Addr, error) {
	base := prefix.Masked().Addr().As4()
	base[3]++
	return netip.AddrFrom4(base), nil
}

// startHostDevices creates one host device per offered exit, each on the
// shared port's dispatcher, with the host peers configured under exactly one
// exit's device — so the peer lookup demultiplexes the shared socket and
// reply traffic routes by the peer's address to its exit's device.
func (g *Gateway) startHostDevices() error {
	peersByExit := make(map[addr.IA][]HostPeer, len(g.cfg.Exits))
	for _, p := range g.cfg.Peers {
		peersByExit[p.Exit] = append(peersByExit[p.Exit], p)
	}
	for _, exit := range g.cfg.Exits {
		dev, pipe, err := g.newHostDevice(exit, peersByExit[exit])
		if err != nil {
			for _, hd := range g.hostDevices {
				hd.dev.Close()
				hd.pipe.Close() //nolint:errcheck
			}
			return err
		}
		g.hostDevices[exit] = &hostDevice{exit: exit, dev: dev, pipe: pipe}
	}
	return nil
}

// newHostDevice builds one exit's host-facing device: the node's key pair —
// every host device shares it, so any can decrypt a handshake while only the
// one holding the sender's public key completes it — and the hosts
// configured under this exit as /32 peers.
func (g *Gateway) newHostDevice(exit addr.IA, peers []HostPeer) (*device.Device, *pipe, error) {
	pipe := newPipe("host-"+exit.String(), OverlayMTU, g.cnt)
	dev := device.NewDevice(pipe, newHostBind(g.host), g.logger)
	var ipc strings.Builder
	ipc.WriteString("private_key=" + hex.EncodeToString(g.key[:]) + "\n")
	ipc.WriteString("listen_port=" + strconv.Itoa(int(g.host.LocalPort())) + "\n")
	ipc.WriteString("replace_peers=true\n")
	for _, p := range peers {
		ipc.WriteString("public_key=" + p.PublicKey.String() + "\n")
		ipc.WriteString("allowed_ip=" + netip.PrefixFrom(p.Addr, 32).String() + "\n")
	}
	if err := dev.IpcSet(ipc.String()); err != nil {
		dev.Close()
		pipe.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("configuring the host device for %s: %w", exit, err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		pipe.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("raising the host device for %s: %w", exit, err)
	}
	return dev, pipe, nil
}

// newMeshDevice builds one directory peer's mesh device: the node's key pair,
// the peer's entry as its endpoint and AllowedIPs — its overlay subnet, with
// 0.0.0.0/0 added when the peer is one of this node's configured exits, so
// the device's default-routed traffic finds a peer for any destination while
// WireGuard's longest-prefix peer selection keeps subnet traffic direct.
func (g *Gateway) newMeshDevice(entry Entry) (*meshPeer, error) {
	bind := newMeshBind(g.mesh)
	pipe := newPipe("mesh-"+entry.IA.String(), OverlayMTU, g.cnt)
	dev := device.NewDevice(pipe, bind, g.logger)
	var ipc strings.Builder
	ipc.WriteString("private_key=" + hex.EncodeToString(g.key[:]) + "\n")
	ipc.WriteString("replace_peers=true\n")
	ipc.WriteString("public_key=" + entry.PublicKey.String() + "\n")
	ipc.WriteString("endpoint=" + endpointString(entry.IA) + "\n")
	ipc.WriteString("allowed_ip=" + entry.Overlay.String() + "\n")
	if containsExit(g.cfg.Exits, entry.IA) {
		ipc.WriteString("allowed_ip=0.0.0.0/0\n")
	}
	ipc.WriteString("persistent_keepalive_interval=" +
		strconv.Itoa(int(PersistentKeepalive.Seconds())) + "\n")
	if err := dev.IpcSet(ipc.String()); err != nil {
		dev.Close()
		pipe.Close() //nolint:errcheck
		return nil, fmt.Errorf("configuring the mesh device for %s: %w", entry.IA, err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		pipe.Close() //nolint:errcheck
		return nil, fmt.Errorf("raising the mesh device for %s: %w", entry.IA, err)
	}
	return &meshPeer{entry: entry, dev: dev, pipe: pipe}, nil
}

// applyDirectory diffs a fetched directory against the mesh devices: new
// peers gain a device; departed peers lose theirs and their router entries.
// The node's own entry is not a peer.
func (g *Gateway) applyDirectory(entries []Entry) {
	g.mtx.Lock()
	defer g.mtx.Unlock()
	live := make(map[addr.IA]bool, len(entries))
	for _, entry := range entries {
		if entry.IA.Equal(g.cfg.IA) {
			continue
		}
		live[entry.IA] = true
		if _, ok := g.meshPeers[entry.IA]; ok {
			continue
		}
		peer, err := g.newMeshDevice(entry)
		if err != nil {
			// A directory entry that fails to raise a device queues a
			// refresh and logs rather than erroring the gateway.
			slog.Warn("Gateway mesh device", "peer", entry.IA, "err", err)
			continue
		}
		g.meshPeers[entry.IA] = peer
		go peer.pipe.drain(g.router.routeFrom(peer.pipe))
		slog.Info("Gateway mesh tunnel up", "peer", entry.IA, "subnet", entry.Overlay)
	}
	for ia, peer := range g.meshPeers {
		if live[ia] {
			continue
		}
		peer.dev.Close()
		peer.pipe.Close() //nolint:errcheck
		delete(g.meshPeers, ia)
		slog.Info("Gateway mesh tunnel down", "peer", ia)
	}
	g.rebuildLocked()
}

// rebuildLocked recomposes the router table from the devices; the gateway
// mutex serializes rebuilds with the device set.
func (g *Gateway) rebuildLocked() {
	nets := make([]route, 0, len(g.meshPeers))
	for _, peer := range g.meshPeers {
		nets = append(nets, route{prefix: peer.entry.Overlay, dst: peer.pipe})
	}
	hosts := make([]hostRoute, 0, len(g.cfg.Peers))
	exits := make(map[*pipe]*pipe, len(g.hostDevices))
	for exit, hd := range g.hostDevices {
		for _, p := range g.cfg.Peers {
			if p.Exit.Equal(exit) {
				hosts = append(hosts, hostRoute{addr: p.Addr, pipe: hd.pipe})
			}
		}
		// Exit selection is the router's default: traffic decrypted by this
		// exit's host device flows to the exit's mesh device — the local
		// exit enters the egress, whose sink the router already holds.
		if mesh := g.meshPeers[exit]; mesh != nil {
			exits[hd.pipe] = mesh.pipe
		} else {
			// The exit has no tunnel yet; default traffic drops until it
			// has one.
			exits[hd.pipe] = nil
		}
	}
	g.router.rebuild(hosts, nets, exits)
}

// PublicKey returns the node's WireGuard public key — the public key a
// host's client configuration peers with.
func (g *Gateway) PublicKey() PublicKey {
	return g.key.PublicKey()
}

// HostPort returns the shared host-facing UDP port — the one port every
// host dials.
func (g *Gateway) HostPort() uint16 {
	return g.cfg.ListenPort
}

// MeshPeers snapshots the ISD-ASes the directory has produced mesh devices
// for.
func (g *Gateway) MeshPeers() []addr.IA {
	return g.meshPeerIAs()
}

// Run serves the gateway until the context is canceled: the sockets' read
// loops, the devices' pipes through the router, the egress, the directory —
// served by the core, published and fetched by everyone — and the counters
// log.
func (g *Gateway) Run(ctx context.Context) error {
	defer g.Close()
	go g.mesh.run()
	go g.host.run()
	for _, hd := range g.hostDevices {
		go hd.pipe.drain(g.router.routeFrom(hd.pipe))
	}
	if g.egress != nil {
		go g.egress.run(ctx)
	}
	if g.cfg.Store != nil {
		g.serveDirectory(ctx)
	}
	go g.runPublish(ctx)
	go g.runSync(ctx)
	slog.Info("Serving WireGuard gateway",
		"ia", g.cfg.IA, "subnet", g.cfg.Subnet,
		"listenPort", g.cfg.ListenPort, "egress", g.cfg.Egress,
		"publicKey", g.PublicKey())
	logTick := time.NewTicker(CountersInterval)
	defer logTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-logTick.C:
			slog.Info("Gateway counters", g.cnt.snapshot()...)
		}
	}
}

// serveDirectory serves the core's directory on the socket New bound and
// registered under the directory service, over the application's
// authenticated channel: the control endpoint's TLS machinery, every
// publisher identified by its verified chain.
func (g *Gateway) serveDirectory(ctx context.Context) {
	conn := g.dirServe
	go func() {
		defer conn.Close() //nolint:errcheck
		if err := controlplane.ServeHTTP3(conn, g.DirectoryHandler(),
			controlplane.EndpointTLS(controlplane.EndpointTLSConfig{
				Engine: g.cfg.Engine,
			})); err != nil && ctx.Err() == nil {
			slog.Error("Gateway directory service exited", "err", err)
		}
	}()
	slog.Info("Serving gateway directory", "service", serviceName(SvcDirectory))
}

// DirectoryHandler is the core's directory HTTP handler: the ConnectRPC
// service behind the middleware that peers each request's verified chain
// into its context.
func (g *Gateway) DirectoryHandler() http.Handler {
	path, handler := gatewayv1connect.NewDirectoryServiceHandler(
		&DirectoryService{Store: g.cfg.Store, Cnt: g.cnt})
	mux := http.NewServeMux()
	mux.Handle(path, Authenticate(handler))
	return mux
}

// Close releases the gateway: the devices close, the sockets retire with
// their service registrations, the flow state expires, and the store closes;
// no operating-system provisioning exists to undo.
func (g *Gateway) Close() {
	g.mtx.Lock()
	defer g.mtx.Unlock()
	for _, peer := range g.meshPeers {
		peer.dev.Close()
		peer.pipe.Close() //nolint:errcheck
	}
	g.meshPeers = nil
	for _, hd := range g.hostDevices {
		hd.dev.Close()
		hd.pipe.Close() //nolint:errcheck
	}
	g.hostDevices = nil
	g.deregisterAll()
	g.mesh.Close()
	g.host.Close()
	if g.egress != nil {
		g.egress.link.Close()
	}
	if g.dirConn != nil {
		g.dirConn.Close() //nolint:errcheck
	}
	if g.dirServe != nil {
		g.dirServe.Close() //nolint:errcheck
	}
	if g.cfg.Store != nil {
		g.cfg.Store.Close() //nolint:errcheck
	}
}

func containsExit(exits []addr.IA, ia addr.IA) bool {
	for _, exit := range exits {
		if exit.Equal(ia) {
			return true
		}
	}
	return false
}
