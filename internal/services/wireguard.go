package services

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	wireguardbbolt "github.com/fancl20/cion/pkg/apps/wireguard/impl/bbolt"
	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// setupWireguard assembles the WireGuard application (proposal 0006) when
// the node's arguments name its tailnet slice, after the control plane
// whose path provider and trust engine it consumes: the key loads or
// creates in the application's own state, the mesh socket binds an
// ephemeral port registered as the wireguard service in this AS, the one
// host device serves the shared port with its peers arriving by directory,
// and the router comes with them. The core node additionally serves the
// directory from its own store, over its own registered service socket,
// and the coordination application serves beside it (proposal 0022). No
// slice runs no application, the empty path's behavior carried over from
// the retired configuration file.
func (n *node) setupWireguard() error {
	if n.cfg.Slice == "" {
		return nil
	}
	subnet, err := netip.ParsePrefix(n.cfg.Slice)
	if err != nil {
		// Validate already parsed the slice; a second failure is the
		// argument's own.
		return fmt.Errorf("parsing --slice: %w", err)
	}
	n.subnet = subnet
	cfg, err := n.wireguardConfig(subnet)
	if err != nil {
		return err
	}
	app, err := wireguard.New(cfg)
	if err != nil {
		// The store is the node's until construction returns it.
		if cfg.Store != nil {
			_ = cfg.Store.Close()
		}
		return fmt.Errorf("assembling the application: %w", err)
	}
	n.wireguard = app
	return nil
}

// wireguardConfig builds the application's configuration from the node's
// run arguments: the slice and the shared port the arguments name, the
// directory store the core serves from, and the relay presence every node
// holds.
func (n *node) wireguardConfig(subnet netip.Prefix) (wireguard.Config, error) {
	listenHost, err := dataplane.ResolveAddrPort(n.cfg.Control)
	if err != nil {
		return wireguard.Config{}, fmt.Errorf("parsing the control address: %w", err)
	}
	cfg := wireguard.Config{
		IA:            n.ident.ia,
		Subnet:        subnet,
		ListenHost:    listenHost.Addr(),
		ListenPort:    n.cfg.HostPort,
		DERP:          n.relayPresence(),
		StateDir:      filepath.Join(n.cfg.State, "wireguard"),
		Provider:      n.pathProvider,
		Engine:        n.engine,
		NewConn:       func() (*scion.Conn, error) { return n.scionConn(0) },
		RegisterSvc:   n.registerSvc,
		UnregisterSvc: n.unregisterSvc,
		InterfaceDown: n.ifDown,
	}
	// The pacing knob the join's tail latency rides (ADR-0011): the
	// directory's fetch cadence bounds when a joined host's node programs
	// it. Zero keeps the production constants.
	if d := n.cfg.Pacing.Directory; d != 0 {
		cfg.PublishInterval = d
		cfg.RefreshInterval = d
	}
	if n.ident.asType == trust.ASTypeCore {
		// The core serves the directory from its own store, following the
		// trust DB's bbolt pattern.
		if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
			return wireguard.Config{}, fmt.Errorf("creating the application's state: %w", err)
		}
		store, err := wireguardbbolt.New(
			filepath.Join(cfg.StateDir, "directory.db"), nil)
		if err != nil {
			return wireguard.Config{}, fmt.Errorf("opening the directory store: %w", err)
		}
		cfg.Store = store
	} else {
		cfg.CoreRoute = n.directoryRoute
	}
	return cfg, nil
}

// relayPresence derives the node's relay presence: the core's coordination
// endpoint on its own HTTPS identity — the domain every node already holds.
// The integration harness overrides the placement, its loopback address and
// pinned certificate standing in for the domain and the WebPKI.
func (n *node) relayPresence() *wireguard.DERPConfig {
	// The relay's own path rides the URL: the client dials it verbatim.
	derp := &wireguard.DERPConfig{
		URL: "https://" + n.cfg.Domain + "/derp",
	}
	if o := n.cfg.Coordination; o != nil && o.DERP.URL != "" {
		derp.URL = o.DERP.URL
		derp.IPv4 = o.DERP.IPv4
		derp.CertName = o.DERP.CertName
	}
	return derp
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
