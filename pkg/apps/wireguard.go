package apps

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/pflag"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	wireguardbbolt "github.com/fancl20/cion/pkg/apps/wireguard/impl/bbolt"
	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/scion"
)

// DefaultHostPort is the host-facing port's default, the WireGuard
// ecosystem's conventional port; zero is the explicit refusal, running no
// host-serving application.
const DefaultHostPort = 51820

// wireguardEntry is the WireGuard application: the mesh transport, the
// directory, the one host device behind the shared port, and the router a
// resident service application borrows. Any node serves hosts; the shared
// port's nonzero value is the loading's required argument.
var wireguardEntry = Entry{
	Name: "wireguard",
	RegisterFlags: func(flags *pflag.FlagSet, args *Arguments) {
		flags.Uint16Var(&args.Wireguard.HostPort, "wireguard.host-port",
			DefaultHostPort,
			"the shared host-facing UDP port every host dials; the directory assigns "+
				"the node's slice of the tailnet range at its first publication "+
				"(zero runs no WireGuard or SOCKS application)")
	},
	MissingArg: func(args *Arguments) string {
		if args.Wireguard.HostPort == 0 {
			return "--wireguard.host-port is zero, the explicit refusal — " +
				"give the argument its port"
		}
		return ""
	},
	New: newWireguard,
}

// newWireguard adapts the environment into the application's own
// configuration and assembles the application over it.
func newWireguard(env *Environment, _ []Loaded) (Application, error) {
	cfg, err := wireguardConfig(env)
	if err != nil {
		return nil, err
	}
	app, err := wireguard.New(cfg)
	if err != nil {
		// The store is the entry's until construction returns it.
		if cfg.Store != nil {
			_ = cfg.Store.Close()
		}
		return nil, err
	}
	return app, nil
}

// wireguardConfig builds the application's configuration from the node's
// facts: the shared port the entry's arguments name, the relay presence
// derived from the domain, the application's own state directory, the
// core's directory store or the joiner's core route, and the pacing
// riders.
func wireguardConfig(env *Environment) (wireguard.Config, error) {
	listenHost, err := dataplane.ResolveAddrPort(env.ControlHost)
	if err != nil {
		return wireguard.Config{}, fmt.Errorf("parsing the control address: %w", err)
	}
	cfg := wireguard.Config{
		IA:            env.IA,
		ListenHost:    listenHost.Addr(),
		ListenPort:    env.Arguments.Wireguard.HostPort,
		DERP:          relayPresence(env.Domain, env.Relay),
		StateDir:      filepath.Join(env.StateRoot, "wireguard"),
		Provider:      env.Provider,
		Engine:        env.Engine,
		NewConn:       env.NewConn,
		RegisterSvc:   env.RegisterSvc,
		UnregisterSvc: env.UnregisterSvc,
		InterfaceDown: env.InterfaceDown,
	}
	// The pacing knob the join's tail latency rides: the directory's fetch
	// cadence bounds when a joined host's node programs it. Zero keeps the
	// production constants.
	if d := env.DirectoryPacing; d != 0 {
		cfg.PublishInterval = d
		cfg.RefreshInterval = d
	}
	if env.Core {
		// The core serves the directory from its own store, following the
		// trust DB's bbolt pattern.
		if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
			return wireguard.Config{}, fmt.Errorf(
				"creating the application's state: %w", err)
		}
		store, err := wireguardbbolt.New(
			filepath.Join(cfg.StateDir, "directory.db"), nil)
		if err != nil {
			return wireguard.Config{}, fmt.Errorf(
				"opening the directory store: %w", err)
		}
		cfg.Store = store
	} else {
		cfg.CoreRoute = directoryRoute(env.CoreRoute)
	}
	return cfg, nil
}

// relayPresence derives the node's relay presence: the core's coordination
// endpoint on its own HTTPS identity — the domain every node already
// holds. The harness's placement overrides it, its loopback address and
// pinned certificate standing in for the domain and the WebPKI.
func relayPresence(domain string, relay RelayPlacement) *wireguard.DERPConfig {
	// The relay's own path rides the URL: the client dials it verbatim.
	derp := &wireguard.DERPConfig{
		URL: "https://" + domain + "/derp",
	}
	if relay.URL != "" {
		derp.URL = relay.URL
		derp.IPv4 = relay.IPv4
		derp.CertName = relay.CertName
	}
	return derp
}

// directoryRoute resolves the core's directory endpoint: the core's
// ISD-AS addressed by the directory service, over the route the
// enrollment core client rides — a neighbor core one hop, anything else
// the reversed freshest up segment.
func directoryRoute(coreRoute func() *scion.Addr) func() *scion.Addr {
	return func() *scion.Addr {
		route := coreRoute()
		if route == nil {
			return nil
		}
		return &scion.Addr{
			IA: route.IA, Service: wireguard.SvcDirectory, Path: route.Path,
		}
	}
}
