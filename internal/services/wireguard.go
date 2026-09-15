package services

import (
	"fmt"
	"net/netip"
	"path/filepath"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	wireguardbbolt "github.com/fancl20/cion/pkg/apps/wireguard/impl/bbolt"
	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// setupWireguard assembles the WireGuard application (proposal 0006) when
// the node's configuration has a wireguard section, after the control plane
// whose path provider and trust engine it consumes: the key loads or creates
// in the application's own state, the mesh socket binds an ephemeral port
// registered as the wireguard service in this AS, host devices serve the
// configured exits behind the shared port, and the router and — when egress
// is set — the netstack egress come with them. The core node additionally
// serves the directory from its own store, over its own registered service
// socket.
func (n *node) setupWireguard() error {
	if n.cfg.Wireguard == nil {
		return nil
	}
	cfg, err := n.parseWireguardConfig()
	if err != nil {
		return err
	}
	app, err := wireguard.New(cfg)
	if err != nil {
		// The store is the node's until construction returns it.
		if cfg.Store != nil {
			cfg.Store.Close() //nolint:errcheck
		}
		return fmt.Errorf("assembling the application: %w", err)
	}
	n.wireguard = app
	return nil
}

// parseWireguardConfig validates the wireguard section into the
// application's configuration: peer addresses inside the subnet, exits
// configured, one exit per key — and the core route or store the directory
// flows through.
func (n *node) parseWireguardConfig() (wireguard.Config, error) {
	wg := n.cfg.Wireguard
	subnet, err := netip.ParsePrefix(wg.Subnet)
	if err != nil {
		return wireguard.Config{}, fmt.Errorf("parsing the wireguard subnet: %w", err)
	}
	if wg.ListenPort == 0 {
		return wireguard.Config{}, fmt.Errorf("the wireguard listen port must be set")
	}
	if !subnet.Addr().Is4() {
		return wireguard.Config{}, fmt.Errorf("the wireguard subnet %s is not IPv4", subnet)
	}
	listenHost, err := dataplane.ResolveAddrPort(n.cfg.Control)
	if err != nil {
		return wireguard.Config{}, fmt.Errorf("parsing the control address: %w", err)
	}
	exits := make([]addr.IA, 0, len(wg.Exits))
	for _, s := range wg.Exits {
		ia, err := addr.ParseIA(s)
		if err != nil {
			return wireguard.Config{}, fmt.Errorf("parsing the exit %q: %w", s, err)
		}
		exits = append(exits, ia)
	}
	peers := make([]wireguard.HostPeer, 0, len(wg.Peers))
	for _, p := range wg.Peers {
		key, err := wireguard.ParsePublicKey(p.PublicKey)
		if err != nil {
			return wireguard.Config{}, fmt.Errorf("parsing a wireguard peer key: %w", err)
		}
		address, err := netip.ParseAddr(p.Address)
		if err != nil {
			return wireguard.Config{}, fmt.Errorf("parsing the peer %s address: %w", key, err)
		}
		exit, err := addr.ParseIA(p.Exit)
		if err != nil {
			return wireguard.Config{}, fmt.Errorf("parsing the peer %s exit: %w", key, err)
		}
		peers = append(peers, wireguard.HostPeer{PublicKey: key, Addr: address, Exit: exit})
	}
	cfg := wireguard.Config{
		IA:            n.ident.ia,
		Subnet:        subnet,
		ListenHost:    listenHost.Addr(),
		ListenPort:    wg.ListenPort,
		Egress:        wg.Egress,
		Exits:         exits,
		Peers:         peers,
		StateDir:      filepath.Join(n.cfg.State, "wireguard"),
		Provider:      n.provider,
		Engine:        n.engine,
		NewConn:       func() (*scion.Conn, error) { return n.scionConn(0) },
		RegisterSvc:   n.registerSvc,
		UnregisterSvc: n.unregisterSvc,
	}
	if n.ident.asType == trust.ASTypeCore {
		// The core serves the directory from its own store, following the
		// trust DB's bbolt pattern.
		store, err := wireguardbbolt.New(
			filepath.Join(n.cfg.State, "wireguard", "directory.db"), nil)
		if err != nil {
			return wireguard.Config{}, fmt.Errorf("opening the directory store: %w", err)
		}
		cfg.Store = store
	} else {
		cfg.CoreRoute = n.directoryRoute
	}
	return cfg, nil
}

// registerSvc registers one of the application's sockets as a SCION service
// in this AS — the same registration discovery makes for the CS service over
// the data plane's provider — so the router delivers service-addressed
// packets to the socket's port on the control host the application's
// connections bind.
func (n *node) registerSvc(svc addr.SVC, port uint16) error {
	host, err := parseControlHost(n.cfg.Control)
	if err != nil {
		return err
	}
	return n.udp.AddSvc(svc, host, port)
}

// unregisterSvc deregisters a socket registerSvc registered.
func (n *node) unregisterSvc(svc addr.SVC, port uint16) error {
	host, err := parseControlHost(n.cfg.Control)
	if err != nil {
		return err
	}
	return n.udp.DelSvc(svc, host, port)
}

// parseControlHost returns the control address's host as a SCION host.
func parseControlHost(control string) (addr.Host, error) {
	ap, err := dataplane.ResolveAddrPort(control)
	if err != nil {
		return addr.Host{}, fmt.Errorf("parsing control address: %w", err)
	}
	return addr.HostIP(ap.Addr()), nil
}

// directoryRoute resolves the core's directory endpoint: the core's ISD-AS
// addressed by the directory service, over the route the enrollment core
// client rides — a neighbor core one hop, anything else the reversed
// freshest up segment.
func (n *node) directoryRoute() *scion.Addr {
	if n.coreClt == nil {
		return nil
	}
	route := n.coreRoute()
	if route == nil {
		return nil
	}
	return &scion.Addr{IA: route.IA, Service: wireguard.SvcDirectory, Path: route.Path}
}
