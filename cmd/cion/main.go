// Command cion runs a CION node: a SCION router with a collapsed data plane
// for a one-node AS.
package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/trust/impl/bbolt"
)

// Config is the configuration of a CION node. See configs/sample.json.
type Config struct {
	// IA is the ISD-AS identifier of this node, e.g. "20-ff00:0:1". The ISD
	// should come from the private range 16-63.
	IA string `json:"ia"`
	// ASType is the tiered role of the node: core, authoritative, or normal.
	ASType string `json:"asType"`
	// State is the directory for the node's state: key material and the
	// trust database.
	State string `json:"state"`
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
	// Domain is the DNS domain this core serves its control endpoint for
	// (core only). It is a TLS identity, never resolved.
	Domain string `json:"domain"`
	// CertFile and KeyFile are the TLS certificate for the control endpoint
	// (core only, optional). Without them the certificate is managed via
	// ACME, which needs publicly reachable TCP ports 80 and 443.
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
	// CoreDomain is the DNS domain of the core this node enrolls with
	// (non-core only).
	CoreDomain string `json:"coreDomain"`
	// AllowIAS optionally restricts enrollment to the listed ISD-ASes; the
	// core rejects and logs requests from any other ISD-AS (core only).
	AllowIAS []string `json:"allowIAS"`
}

type ConfigInterface struct {
	// ID is the SCION interface ID of this link.
	ID uint16 `json:"id"`
	// Local is the UDP address to send and receive on, e.g. "192.0.2.1:50000".
	Local string `json:"local"`
	// Remote is the UDP address of the neighbor router, e.g. "192.0.2.2:50000".
	Remote string `json:"remote"`
	// NeighborIA is the ISD-AS of the neighbor, e.g. "20-ff00:0:2".
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
	asType, err := trust.ParseASType(cfg.ASType)
	if err != nil {
		return err
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
	neighborLinks := make(map[uint16]addr.IA, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		link, err := provider.NewExternalLink(
			queueSize, nil, iface.Local, iface.Remote, iface.ID,
			metrics.NewInterfaceMetrics(iface.ID, ia, 0),
		)
		if err != nil {
			return fmt.Errorf("creating interface %d: %w", iface.ID, err)
		}
		links = append(links, link)
		neighborIA, err := addr.ParseIA(iface.NeighborIA)
		if err != nil {
			return fmt.Errorf("parsing neighbor IA of interface %d: %w", iface.ID, err)
		}
		neighborLinks[iface.ID] = neighborIA
	}

	d, err := dataplane.NewDataPlane(ia, localHost, key, provider, links)
	if err != nil {
		return err
	}
	d.RunConfig = runConfig

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	discovery, err := newDiscovery(cfg, ia, key, provider, neighborLinks)
	if err != nil {
		return err
	}

	// Trust material comes up before the network services: the database and
	// key material first, then TRC genesis and the control endpoint on the
	// core, or trust fetch and enrollment on every other node. Enrollment
	// runs in the background and waits for the first neighbor greeting to
	// learn the core's locator, so discovery runs alongside it.
	db, err := setupTrust(ctx, cfg, ia, asType, key, neighborLinks, discovery)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck

	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Panic in discovery", "panic", r)
			}
		}()
		discovery.Run(ctx)
	}()

	slog.Info("Starting CION", "ia", ia, "asType", asType, "internal", cfg.Internal,
		"control", cfg.Control, "interfaces", len(cfg.Interfaces))
	return d.Serve(ctx)
}

// setupTrust brings up the node's trust material: the trust database and AS
// key for every node, then TRC genesis, self-enrollment, and the control
// endpoint on the founding core, or enrollment against the core endpoint on
// every other node.
func setupTrust(
	ctx context.Context,
	cfg *Config,
	ia addr.IA,
	asType trust.ASType,
	key []byte,
	links map[uint16]addr.IA,
	discovery *controlplane.Discovery,
) (trust.DB, error) {

	db, err := bbolt.New(filepath.Join(cfg.State, "trust.db"), nil)
	if err != nil {
		return nil, fmt.Errorf("opening trust DB: %w", err)
	}
	asKey, err := trust.LoadOrCreateASKey(cfg.State)
	if err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("loading AS key: %w", err)
	}

	scionConn := func(port uint16) (*controlplane.SCIONConn, error) {
		bind, err := controlBind(cfg.Control, port)
		if err != nil {
			return nil, err
		}
		return controlplane.NewSCIONConn(controlplane.SCIONConnConfig{
			IA:           ia,
			Bind:         bind,
			InternalAddr: cfg.Internal,
			MACKey:       key,
			Links:        links,
		})
	}

	if asType != trust.ASTypeCore {
		// The client socket takes an ephemeral port on the control address;
		// the local router delivers the core's replies to it.
		conn, err := scionConn(0)
		if err != nil {
			db.Close() //nolint:errcheck
			return nil, err
		}
		core, err := controlplane.NewCoreClient(controlplane.CoreClientConfig{
			Domain: cfg.CoreDomain,
			Conn:   conn,
		})
		if err != nil {
			db.Close() //nolint:errcheck
			return nil, err
		}
		go func() {
			defer handleControlPanic()
			runEnrollment(ctx, ia, core, db, asKey, discovery)
		}()
		return db, nil
	}

	keys, err := trust.LoadOrCreateCoreKeys(cfg.State)
	if err != nil {
		db.Close() //nolint:errcheck
		return nil, err
	}
	trc, err := trust.Genesis(ctx, db, ia, keys)
	if err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("TRC genesis: %w", err)
	}
	issuer, err := trust.NewIssuer(ia, keys, trc)
	if err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("creating issuer: %w", err)
	}
	if _, err := selfEnroll(ctx, db, issuer, ia, asKey); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("self-enrolling core: %w", err)
	}

	allowAS, err := parseAllowIAS(cfg.AllowIAS)
	if err != nil {
		db.Close() //nolint:errcheck
		return nil, err
	}
	svc := &controlplane.TrustService{DB: db, Issuer: issuer, AllowAS: allowAS}
	tlsConf, err := controlplane.ManageTLSCert(ctx, controlplane.TLSCertConfig{
		Domain:   cfg.Domain,
		CertFile: cfg.CertFile,
		KeyFile:  cfg.KeyFile,
		Storage:  filepath.Join(cfg.State, "certs"),
	})
	if err != nil {
		db.Close() //nolint:errcheck
		return nil, err
	}
	// The endpoint serves on the control address's host with the fixed
	// endpoint port.
	conn, err := scionConn(controlplane.EndpointPort)
	if err != nil {
		db.Close() //nolint:errcheck
		return nil, err
	}
	go func() {
		defer handleControlPanic()
		if err := controlplane.ServeHTTP3(conn, controlplane.NewServer(svc).Handler,
			tlsConf); err != nil {

			slog.Error("Control endpoint exited", "err", err)
		}
	}()
	slog.Info("Serving control endpoint", "trc", trc.TRC.ID, "domain", cfg.Domain)
	return db, nil
}

// runEnrollment enrolls this node against the core once its locator is
// learned from a neighbor greeting. With several neighbors, each is tried in
// turn: only the core's endpoint presents a certificate for the configured
// domain, so enrollment against any other neighbor fails the TLS handshake.
func runEnrollment(
	ctx context.Context,
	ia addr.IA,
	core *controlplane.CoreClient,
	db trust.DB,
	asKey crypto.Signer,
	discovery *controlplane.Discovery,
) {

	ticker := time.NewTicker(enrollInterval)
	defer ticker.Stop()
	for {
		for _, n := range discovery.Neighbors() {
			core.SetCore(n.IA,
				netip.AddrPortFrom(n.ControlAddr.Addr(), controlplane.EndpointPort))
			if _, err := trust.Enroll(ctx, db, core, ia, asKey); err != nil {
				slog.Warn("Enrollment against neighbor failed",
					"neighbor", n.IA, "err", err)
				continue
			}
			slog.Info("Enrolled with core", "core_ia", n.IA)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// enrollInterval is the pause between enrollment attempts; a node whose
// links do not include the core keeps trying until multi-hop paths exist.
const enrollInterval = 5 * time.Second

// selfEnroll issues the core's own certificate chain locally, through the
// same issuer that serves enrollment requests.
func selfEnroll(
	ctx context.Context,
	db trust.DB,
	issuer *trust.Issuer,
	ia addr.IA,
	asKey crypto.Signer,
) ([]*x509.Certificate, error) {

	csr, err := trust.CreateCSR(ia, asKey)
	if err != nil {
		return nil, err
	}
	chain, err := issuer.IssueChain(csr)
	if err != nil {
		return nil, err
	}
	if _, err := db.InsertChain(ctx, chain); err != nil {
		return nil, err
	}
	return chain, nil
}

func handleControlPanic() {
	if r := recover(); r != nil {
		slog.Error("Panic in control plane", "panic", r)
	}
}

func parseAllowIAS(ias []string) (map[addr.IA]bool, error) {
	if len(ias) == 0 {
		return nil, nil
	}
	allow := make(map[addr.IA]bool, len(ias))
	for _, s := range ias {
		ia, err := addr.ParseIA(s)
		if err != nil {
			return nil, fmt.Errorf("parsing allowlisted ISD-AS %q: %w", s, err)
		}
		allow[ia] = true
	}
	return allow, nil
}

// controlBind returns the "host:port" address for the control endpoint: the
// control address's host with the given port.
func controlBind(control string, port uint16) (string, error) {
	ap, err := dataplane.ResolveAddrPort(control)
	if err != nil {
		return "", fmt.Errorf("parsing control address: %w", err)
	}
	return netip.AddrPortFrom(ap.Addr(), port).String(), nil
}

// newDiscovery creates the discovery service from the node configuration.
func newDiscovery(
	cfg *Config,
	ia addr.IA,
	key []byte,
	provider *dataplane.UDPProvider,
	links map[uint16]addr.IA,
) (*controlplane.Discovery, error) {

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
	if cfg.ASType == "" || cfg.State == "" {
		return nil, fmt.Errorf("config must set asType and state")
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
