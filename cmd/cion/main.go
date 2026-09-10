// Command cion runs a CION node: a SCION router with a collapsed data plane
// for a one-node AS.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/dataplane"
)

// Config is the configuration of a CION node. See configs/sample.json.
type Config struct {
	// IA is the ISD-AS identifier of this node, e.g. "1-ff00:0:1".
	IA string `json:"ia"`
	// Internal is the UDP address the router listens on for traffic from
	// hosts in the local AS, e.g. "127.0.0.1:30041".
	Internal string `json:"internal"`
	// Control is the UDP address the control service listens on and
	// advertises to neighbors, e.g. "127.0.0.1:30043".
	Control string `json:"control"`
	// Key is the hex-encoded secret key used for hop field MAC computation.
	Key string `json:"key"`
	// Interfaces are the external links to neighboring ASes.
	Interfaces []ConfigInterface `json:"interfaces"`
}

type ConfigInterface struct {
	// ID is the SCION interface ID of this link.
	ID uint16 `json:"id"`
	// Local is the UDP address to send and receive on, e.g. "192.0.2.1:50000".
	Local string `json:"local"`
	// Remote is the UDP address of the neighbor router, e.g. "192.0.2.2:50000".
	Remote string `json:"remote"`
	// NeighborIA is the ISD-AS of the neighbor, e.g. "1-ff00:0:2".
	NeighborIA string `json:"neighborIA"`
}

func main() {
	configPath := flag.String("config", "", "path to the JSON configuration file")
	flag.Parse()

	if err := run(*configPath); err != nil {
		slog.Error("CION terminated", "err", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	ia, err := addr.ParseIA(cfg.IA)
	if err != nil {
		return fmt.Errorf("parsing IA: %w", err)
	}
	key, err := hex.DecodeString(cfg.Key)
	if err != nil {
		return fmt.Errorf("decoding key: %w", err)
	}
	if len(key) == 0 {
		return fmt.Errorf("key must not be empty")
	}
	localHost, err := parseInternalHost(cfg.Internal)
	if err != nil {
		return err
	}

	metrics, err := dataplane.NewMetrics()
	if err != nil {
		return fmt.Errorf("creating metrics: %w", err)
	}
	provider := dataplane.NewUDPProvider(runConfig.BatchSize,
		runConfig.ReceiveBufferSize, runConfig.SendBufferSize)

	links := make([]dataplane.Link, 0, len(cfg.Interfaces)+1)
	internalLink, err := provider.NewInternalLink(
		cfg.Internal, queueSize, metrics.NewInterfaceMetrics(0, ia, 0),
	)
	if err != nil {
		return fmt.Errorf("creating internal link: %w", err)
	}
	links = append(links, internalLink)
	for _, iface := range cfg.Interfaces {
		link, err := provider.NewExternalLink(
			queueSize, nil, iface.Local, iface.Remote, iface.ID,
			metrics.NewInterfaceMetrics(iface.ID, ia, 0),
		)
		if err != nil {
			return fmt.Errorf("creating interface %d: %w", iface.ID, err)
		}
		links = append(links, link)
	}

	d, err := dataplane.NewDataPlane(ia, localHost, key, provider, links)
	if err != nil {
		return err
	}
	d.RunConfig = runConfig

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	discovery, err := newDiscovery(cfg, ia, key, provider)
	if err != nil {
		return err
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Panic in discovery", "panic", r)
			}
		}()
		discovery.Run(ctx)
	}()

	slog.Info("Starting CION", "ia", ia, "internal", cfg.Internal,
		"control", cfg.Control, "interfaces", len(cfg.Interfaces))
	return d.Serve(ctx)
}

// newDiscovery creates the discovery service from the node configuration.
func newDiscovery(
	cfg *Config,
	ia addr.IA,
	key []byte,
	provider *dataplane.UDPProvider,
) (*controlplane.Discovery, error) {

	links := make(map[uint16]addr.IA, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		neighborIA, err := addr.ParseIA(iface.NeighborIA)
		if err != nil {
			return nil, fmt.Errorf("parsing neighbor IA of interface %d: %w", iface.ID, err)
		}
		links[iface.ID] = neighborIA
	}
	discovery, err := controlplane.NewDiscovery(controlplane.DiscoveryConfig{
		IA:           ia,
		ControlAddr:  cfg.Control,
		MACKey:       key,
		InternalAddr: cfg.Internal,
		Links:        links,
	})
	if err != nil {
		return nil, err
	}
	if err := discovery.Register(provider); err != nil {
		return nil, fmt.Errorf("registering control service: %w", err)
	}
	return discovery, nil
}

// parseInternalHost returns the local host address derived from the internal
// address.
func parseInternalHost(internal string) (addr.Host, error) {
	ap, err := dataplane.ResolveAddrPort(internal)
	if err != nil {
		return addr.Host{}, fmt.Errorf("parsing internal address: %w", err)
	}
	return addr.HostIP(ap.Addr()), nil
}

func loadConfig(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("missing -config flag")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	cfg := &Config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if cfg.IA == "" || cfg.Internal == "" {
		return nil, fmt.Errorf("config must set ia and internal")
	}
	return cfg, nil
}

var (
	queueSize = 64

	runConfig = dataplane.RunConfig{
		NumProcessors:         max(1, runtime.NumCPU()/2),
		NumSlowPathProcessors: 1,
		BatchSize:             64,
		ReceiveBufferSize:     1 << 20,
		SendBufferSize:        1 << 20,
	}
)
