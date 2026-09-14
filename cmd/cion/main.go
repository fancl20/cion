// Command cion runs a CION node: a SCION router with a collapsed data plane
// for a one-node AS.
package main

import (
	"context"
	"crypto"
	"crypto/tls"
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
	"strings"
	"syscall"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/apps/ping"
	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/pathdb"
	pathdbbbolt "github.com/fancl20/cion/pkg/pathdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/scion"
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

	if err := run(*configPath, flag.Args()); err != nil {
		slog.Error("CION terminated", "err", err)
		os.Exit(1)
	}
}

func run(configPath string, args []string) error {
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

	// Trust material and the path layer come up before the network
	// services: the databases and key material first, then TRC genesis and
	// the control endpoint on the core or the enrollment loop on every
	// other node, the trust engine, the two segment stores, and the
	// beaconer. Enrollment and beaconing run in the background; discovery
	// runs alongside them.
	node, err := setupControlPlane(ctx, cfg, ia, asType, key, neighborLinks, discovery)
	if err != nil {
		return err
	}
	defer node.Close()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Panic in discovery", "panic", r)
			}
		}()
		discovery.Run(ctx)
	}()
	go func() {
		defer handleControlPanic()
		node.beaconer.Run(ctx)
	}()

	// The ping subcommand rides the assembled node — its packets cross the
	// data plane and its paths come from the node's own beaconing — instead
	// of serving forever.
	if len(args) > 0 {
		if args[0] != "ping" {
			return fmt.Errorf("unknown subcommand %q", args[0])
		}
		go func() {
			defer handleControlPanic()
			_ = d.Serve(ctx)
		}()
		return runPing(ctx, node, args[1:])
	}

	slog.Info("Starting CION", "ia", ia, "asType", asType, "internal", cfg.Internal,
		"control", cfg.Control, "interfaces", len(cfg.Interfaces))
	return d.Serve(ctx)
}

// runPing runs the ping subcommand: a pinger on the node's own assembly,
// printing one line per reply and a loss summary.
func runPing(ctx context.Context, node *controlPlaneNode, args []string) error {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
	count := fs.Int("count", 4, "number of requests")
	interval := fs.Duration("interval", time.Second, "time between requests")
	wait := fs.Duration("wait", 2*time.Second, "wait per reply")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("ping needs a destination: cion -config node.json ping 20-ff00:0:2,[host]")
	}
	dst, host, err := parsePingTarget(fs.Arg(0))
	if err != nil {
		return err
	}
	bind, err := controlBind(node.cfg.Control, 0)
	if err != nil {
		return err
	}
	conn, err := scion.NewConn(scion.ConnConfig{
		IA:           node.ia,
		Bind:         bind,
		InternalAddr: node.cfg.Internal,
		MACKey:       node.key,
		Links:        node.links,
	})
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	fmt.Printf("cion ping %s,%s\n", dst, host)
	report, err := ping.Run(ctx, ping.Config{
		Conn:     conn,
		Provider: node.provider,
		Dst:      dst,
		DstHost:  host,
		Count:    *count,
		Interval: *interval,
		Wait:     *wait,
		Log:      func(f string, a ...any) { fmt.Printf(f+"\n", a...) },
	})
	if err != nil {
		return err
	}
	if report.Loss() > 0 {
		return fmt.Errorf("%d of %d requests lost", report.Loss(), report.Sent)
	}
	return nil
}

// parsePingTarget splits a "20-ff00:0:2,192.0.2.10" destination into the
// ISD-AS and the underlay host the destination's responder is bound to.
func parsePingTarget(s string) (dst addr.IA, host netip.Addr, err error) {
	iaStr, hostStr, ok := strings.Cut(s, ",")
	if !ok {
		return dst, host, fmt.Errorf("destination %q must be isd-as,[host]", s)
	}
	dst, err = addr.ParseIA(iaStr)
	if err != nil {
		return dst, host, fmt.Errorf("parsing ISD-AS: %w", err)
	}
	host, err = netip.ParseAddr(hostStr)
	if err != nil {
		return dst, host, fmt.Errorf("parsing host address: %w", err)
	}
	return dst, host, nil
}

// controlPlaneNode holds the state a running node's control plane needs to
// release at shutdown, and the pieces its applications consume.
type controlPlaneNode struct {
	cfg      *Config
	ia       addr.IA
	key      []byte
	links    map[uint16]addr.IA
	provider *scion.PathProvider
	trustDB  trust.DB
	pathDB   pathdb.DB
	peerClt  *controlplane.PeerClient
	beaconer *controlplane.Beaconer
}

func (n *controlPlaneNode) Close() {
	n.peerClt.Close() //nolint:errcheck
	n.pathDB.Close()  //nolint:errcheck
	n.trustDB.Close() //nolint:errcheck
}

// setupControlPlane brings up the node's control plane per proposal 0004:
// the trust database and AS key for every node; TRC genesis, synchronous
// self-enrollment, and the WebPKI channel on the founding core, or the
// enrollment loop against the core on every other node; the control
// endpoint on every node; the trust engine; the beacon store and path
// database; and the beaconing originator (core) or
// receiver/propagator/registrant (non-core).
func setupControlPlane(
	ctx context.Context,
	cfg *Config,
	ia addr.IA,
	asType trust.ASType,
	key []byte,
	links map[uint16]addr.IA,
	discovery *controlplane.Discovery,
) (*controlPlaneNode, error) {

	trustDB, err := bbolt.New(filepath.Join(cfg.State, "trust.db"), nil)
	if err != nil {
		return nil, fmt.Errorf("opening trust DB: %w", err)
	}
	asKey, err := trust.LoadOrCreateASKey(cfg.State)
	if err != nil {
		trustDB.Close() //nolint:errcheck
		return nil, fmt.Errorf("loading AS key: %w", err)
	}
	pathDB, err := pathdbbbolt.New(filepath.Join(cfg.State, "path.db"), nil)
	if err != nil {
		trustDB.Close() //nolint:errcheck
		return nil, fmt.Errorf("opening path DB: %w", err)
	}

	scionConn := func(port uint16) (*scion.Conn, error) {
		bind, err := controlBind(cfg.Control, port)
		if err != nil {
			return nil, err
		}
		return scion.NewConn(scion.ConnConfig{
			IA:           ia,
			Bind:         bind,
			InternalAddr: cfg.Internal,
			MACKey:       key,
			Links:        links,
		})
	}

	// The path provider resolves routes; its consumers below close the
	// cycle through the beaconer, the lookup service, and this route.
	var pathProvider *scion.PathProvider
	coreRoute := func() *scion.Addr {
		coreIA, coreEndpoint, ok := discovery.CoreEndpoint()
		if !ok {
			return nil
		}
		// The one-hop path when the core is a neighbor...
		for _, n := range discovery.Neighbors() {
			if n.IA.Equal(coreIA) {
				return &scion.Addr{
					IA:   coreIA,
					Addr: netip.AddrPortFrom(n.ControlAddr.Addr(), controlplane.EndpointPort),
				}
			}
		}
		// ...else the reversed freshest up segment, which exists from
		// beaconing alone, or the bootstrap route before the TRC is pinned.
		// Local state only: resolving a route inside a dial must not spawn
		// RPCs over the transport being dialed.
		if pathProvider != nil {
			if path, err := pathProvider.LocalPath(coreIA); err == nil {
				return &scion.Addr{IA: coreIA, Addr: coreEndpoint, Path: path}
			}
		}
		return nil
	}

	var (
		issuer  *trust.Issuer
		coreClt *controlplane.CoreClient
	)
	if asType == trust.ASTypeCore {
		keys, err := trust.LoadOrCreateCoreKeys(cfg.State)
		if err != nil {
			trustDB.Close() //nolint:errcheck
			pathDB.Close()  //nolint:errcheck
			return nil, err
		}
		trc, err := trust.Genesis(ctx, trustDB, ia, keys)
		if err != nil {
			trustDB.Close() //nolint:errcheck
			pathDB.Close()  //nolint:errcheck
			return nil, fmt.Errorf("TRC genesis: %w", err)
		}
		issuer, err = trust.NewIssuer(ia, keys, trc)
		if err != nil {
			trustDB.Close() //nolint:errcheck
			pathDB.Close()  //nolint:errcheck
			return nil, fmt.Errorf("creating issuer: %w", err)
		}
		// The synchronous startup self-enrollment is the core chain
		// lifecycle's first pass.
		if _, err := selfEnroll(ctx, trustDB, issuer, ia, asKey); err != nil {
			trustDB.Close() //nolint:errcheck
			pathDB.Close()  //nolint:errcheck
			return nil, fmt.Errorf("self-enrolling core: %w", err)
		}
	} else {
		// The client socket takes an ephemeral port on the control address;
		// the local router delivers the core's replies to it.
		conn, err := scionConn(0)
		if err != nil {
			trustDB.Close() //nolint:errcheck
			pathDB.Close()  //nolint:errcheck
			return nil, err
		}
		coreClt, err = controlplane.NewCoreClient(controlplane.CoreClientConfig{
			Domain:  cfg.CoreDomain,
			Conn:    conn,
			Locator: coreRoute,
		})
		if err != nil {
			trustDB.Close() //nolint:errcheck
			pathDB.Close()  //nolint:errcheck
			return nil, err
		}
	}

	// The provider behind the engine is DB-first: non-core nodes fall back
	// to the core's endpoint over the SCION-native transport; the core uses
	// none, since its DB holds every chain it issued.
	remote := trust.Remote(nil)
	if coreClt != nil {
		remote = coreClt
	}
	trustProvider := &trust.NetworkProvider{DB: trustDB, Remote: remote}
	engine := trust.NewEngine(ia, asKey, trustProvider)

	cores := func(isd addr.ISD) []addr.IA {
		ias, err := engine.CoreASes(isd)
		if err != nil {
			slog.Warn("Enumerating core ASes from the pinned TRC", "err", err)
			return nil
		}
		return ias
	}

	peerConn, err := scionConn(0)
	if err != nil {
		trustDB.Close() //nolint:errcheck
		pathDB.Close()  //nolint:errcheck
		return nil, err
	}
	peerClt := controlplane.NewPeerClient(controlplane.PeerClientConfig{
		Engine: engine,
		Conn:   peerConn,
		PathTo: func(dst addr.IA) *spath.Decoded {
			path, err := pathProvider.LocalPath(dst)
			if err != nil {
				return nil
			}
			return path
		},
	})

	lookup := controlplane.NewLookupService()
	lookup.IA = ia
	lookup.DB = pathDB
	lookup.IsCore = asType == trust.ASTypeCore
	lookup.Cores = cores
	lookup.Fetch = peerClt.Segments
	lookup.CoreRoute = coreRoute

	store := controlplane.NewBeaconStore()
	beaconer, err := controlplane.NewBeaconer(controlplane.BeaconerConfig{
		IA:        ia,
		Engine:    engine,
		MACKey:    key,
		Store:     store,
		DB:        pathDB,
		Links:     links,
		Neighbors: discovery.Neighbors,
		Sender:    peerClt,
		CoreRoute: coreRoute,
		Core:      asType == trust.ASTypeCore,
	})
	if err != nil {
		peerClt.Close() //nolint:errcheck
		trustDB.Close() //nolint:errcheck
		pathDB.Close()  //nolint:errcheck
		return nil, err
	}

	pathProvider = &scion.PathProvider{
		IA:        ia,
		DB:        pathDB,
		Lookup:    lookup.Down,
		Bootstrap: beaconer.BootstrapRoute,
		Cores:     cores,
	}

	// Every node serves its ConnectRPC services over HTTP/3 on the endpoint
	// port, since beacons terminate on each node's SegmentCreationService.
	// The core's endpoint additionally serves the bootstrap channel for
	// clients offering its domain as the TLS server name.
	var webPKIConf *tls.Config
	if asType == trust.ASTypeCore {
		webPKIConf, err = controlplane.ManageTLSCert(ctx, controlplane.TLSCertConfig{
			Domain:   cfg.Domain,
			CertFile: cfg.CertFile,
			KeyFile:  cfg.KeyFile,
			Storage:  filepath.Join(cfg.State, "certs"),
		})
		if err != nil {
			peerClt.Close() //nolint:errcheck
			trustDB.Close() //nolint:errcheck
			pathDB.Close()  //nolint:errcheck
			return nil, err
		}
	}
	endpointConn, err := scionConn(controlplane.EndpointPort)
	if err != nil {
		peerClt.Close() //nolint:errcheck
		trustDB.Close() //nolint:errcheck
		pathDB.Close()  //nolint:errcheck
		return nil, err
	}
	allowAS, err := parseAllowIAS(cfg.AllowIAS)
	if err != nil {
		peerClt.Close() //nolint:errcheck
		trustDB.Close() //nolint:errcheck
		pathDB.Close()  //nolint:errcheck
		return nil, err
	}

	// Every node answers SCMP echo requests on its endhost port — the
	// network's health probe, served by the first application consuming the
	// path library beside the control plane.
	pingConn, err := scionConn(dataplane.EndhostPort)
	if err != nil {
		peerClt.Close() //nolint:errcheck
		trustDB.Close() //nolint:errcheck
		pathDB.Close()  //nolint:errcheck
		return nil, fmt.Errorf("binding the ping responder (the control address's host must not share the internal link's port): %w", err)
	}
	responder := &ping.Responder{Conn: pingConn}
	go func() {
		defer handleControlPanic()
		responder.Run(ctx)
	}()
	svc := &controlplane.Services{
		TrustService: &controlplane.TrustService{
			DB:      trustDB,
			Issuer:  issuer,
			AllowAS: allowAS,
		},
		SegmentService: &controlplane.SegmentService{
			Beaconer: beaconer,
			Lookup:   lookup,
		},
	}
	go func() {
		defer handleControlPanic()
		if err := controlplane.ServeHTTP3(endpointConn, controlplane.NewServer(svc).Handler,
			controlplane.EndpointTLS(controlplane.EndpointTLSConfig{
				Domain: cfg.Domain,
				WebPKI: webPKIConf,
				Engine: engine,
			})); err != nil {

			slog.Error("Control endpoint exited", "err", err)
		}
	}()

	// The chain lifecycle keeps a valid chain on every node — the core
	// included — by re-enrolling before expiry.
	if asType == trust.ASTypeCore {
		endpoint := endpointConn.LocalAddr().(*scion.Addr).Addr
		discovery.SetCoreEndpoint(ia, endpoint)
		go func() {
			defer handleControlPanic()
			controlplane.RunCoreEnrollment(ctx, controlplane.EnrollmentConfig{
				IA:     ia,
				DB:     trustDB,
				Key:    asKey,
				Issuer: issuer,
			})
		}()
	} else {
		go func() {
			defer handleControlPanic()
			controlplane.RunEnrollment(ctx, controlplane.EnrollmentConfig{
				IA:     ia,
				DB:     trustDB,
				Key:    asKey,
				Remote: coreClt,
			})
		}()
	}

	slog.Info("Serving control endpoint", "port", controlplane.EndpointPort)
	return &controlPlaneNode{
		cfg:      cfg,
		ia:       ia,
		key:      key,
		links:    links,
		provider: pathProvider,
		trustDB:  trustDB,
		pathDB:   pathDB,
		peerClt:  peerClt,
		beaconer: beaconer,
	}, nil
}

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
