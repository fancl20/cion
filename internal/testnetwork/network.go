// Package testnetwork is the integration tests' topology harness: the fully
// wired nodes of pkg/controlplane/network_test.go's harness, extended per
// proposal 0006 with the WireGuard application and per proposal 0008 with
// the link store, moved where the applications' own integration tests can
// assemble beside them — the harness imports the control plane, so the
// control plane's package cannot host it.
package testnetwork

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	wireguardbbolt "github.com/fancl20/cion/pkg/apps/wireguard/impl/bbolt"
	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/links"
	linkbbolt "github.com/fancl20/cion/pkg/links/impl/bbolt"
	"github.com/fancl20/cion/pkg/pathdb"
	pathdbbbolt "github.com/fancl20/cion/pkg/pathdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
	trustbbolt "github.com/fancl20/cion/pkg/trust/impl/bbolt"
)

// Test intervals, fast enough for the integration tests to watch the loops.
const (
	DiscoveryGap = 30 * time.Millisecond
	Propagation  = 100 * time.Millisecond
	Registration = 200 * time.Millisecond
	EnrollRetry  = 100 * time.Millisecond
	// WireguardCadence paces the application's publication and directory
	// refresh.
	WireguardPublish = 200 * time.Millisecond
	WireguardRefresh = 200 * time.Millisecond
	WireguardRetry   = 100 * time.Millisecond
	TestTimeout      = 20 * time.Second
)

// TestDomain is the DNS identity of the core endpoint in tests; its
// certificate is signed by a test CA that stands in for the WebPKI.
const TestDomain = "cion-core.test"

// Node is one fully-wired node of a test topology — the same components the
// run command wires in internal/services: data plane, the link store,
// discovery, trust, the control endpoint, the beaconer, and — when
// configured — the WireGuard application.
type Node struct {
	IA        addr.IA
	Internal  string
	ControlIP netip.Addr
	Links     func() map[uint16]addr.IA
	Store     links.DB
	MACKey    []byte
	TrustDB   trust.DB
	PathDB    pathdb.DB
	Engine    *trust.Engine
	Beaconer  *controlplane.Beaconer
	StoreBcn  *controlplane.BeaconStore
	CoreClt   *controlplane.CoreClient
	PeerClt   *controlplane.PeerClient
	Provider  *scion.PathProvider
	Lookup    *controlplane.LookupService
	Discovery *controlplane.Discovery
	Wireguard *wireguard.App
	cancel    context.CancelFunc
}

// NewConn returns a SCION connection of the node, bound to the control
// address's host with the given port.
func (n *Node) NewConn(t *testing.T, port uint16) *scion.Conn {
	t.Helper()
	conn, err := scion.NewConn(scion.ConnConfig{
		IA:           n.IA,
		Bind:         netip.AddrPortFrom(n.ControlIP, port).String(),
		InternalAddr: n.Internal,
		MACKey:       n.MACKey,
		Links:        n.Links,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck
	return conn
}

// Link is one seeded external link of a node: both endpoints' addresses
// recorded in each side's store, the shape a restart serves.
type Link struct {
	Local    string
	Remote   string
	Neighbor addr.IA
}

// WebPKI is the test certificate authority anchoring the endpoint's TLS
// certificate.
type WebPKI struct {
	pool     *x509.CertPool
	certFile string
	keyFile  string
}

// NewWebPKI creates the CA and the server certificate for TestDomain,
// returning the certificate files and the pool trusting the CA.
func NewWebPKI(t *testing.T) *WebPKI {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cion test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: TestDomain},
		DNSNames:     []string{TestDomain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert,
		serverKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &WebPKI{pool: pool, certFile: certFile, keyFile: keyFile}
}

// WireguardOptions configures a node's WireGuard application; nil runs
// none.
type WireguardOptions struct {
	// Subnet is the node's overlay subnet.
	Subnet string
	// Egress marks an internet exit.
	Egress bool
	// Exits lists the offered exit ISD-ASes.
	Exits []addr.IA
	// Peers lists the host public keys with address and exit.
	Peers []wireguard.HostPeer
	// ListenPort is the shared host-facing port; 0 takes an ephemeral one.
	ListenPort uint16
}

// NodeConfig configures StartNode.
type NodeConfig struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// Host is the loopback host the node's addresses sit on, so several
	// nodes share one test host even with the fixed ports.
	Host netip.Addr
	// StateDir persists the node's state; "" uses a fresh temporary one.
	StateDir string
	// Links are the node's seeded external links, recorded in its store as
	// established — the shape a restart serves.
	Links []Link
	// Core marks the founding core node.
	Core bool
	// WPKI anchors the bootstrap channel's certificate.
	WPKI *WebPKI
	// Wireguard starts the WireGuard application when set.
	Wireguard *WireguardOptions
}

// StartNode brings up a node with the given configuration. The core serves
// the WebPKI bootstrap channel for TestDomain alongside the SCION-native
// channel; non-core nodes enroll against it.
func StartNode(t *testing.T, cfg NodeConfig) *Node {
	t.Helper()
	ia, host, linksCfg, core, wpki := cfg.IA, cfg.Host, cfg.Links, cfg.Core, cfg.WPKI
	stateDir := cfg.StateDir

	metrics, err := dataplane.NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	provider := dataplane.NewUDPProvider(64, 0, 0)
	// Every address of the node sits on its own loopback address, so several
	// nodes share one test host even with the fixed endpoint port.
	internal, control := FreeUDPAddrOn(t, host), FreeUDPAddrOn(t, host)
	controlAddr, err := netip.ParseAddrPort(control)
	if err != nil {
		t.Fatal(err)
	}
	if stateDir == "" {
		stateDir = t.TempDir()
	}
	trustDB, err := trustbbolt.New(filepath.Join(stateDir, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pathDB, err := pathdbbbolt.New(filepath.Join(stateDir, "path.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	linkStore, err := linkbbolt.New(filepath.Join(stateDir, "links.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	macKey, err := trust.LoadOrCreateForwardingKey(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	asKey, err := trust.LoadOrCreateASKey(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range linksCfg {
		local, err := netip.ParseAddrPort(l.Local)
		if err != nil {
			t.Fatal(err)
		}
		remote, err := netip.ParseAddrPort(l.Remote)
		if err != nil {
			t.Fatal(err)
		}
		// Idempotent by remote address: a restarted node re-serves the
		// persisted entry rather than duplicating it.
		if existing, err := linkStore.ByRemote(context.Background(), remote); err != nil {
			t.Fatal(err)
		} else if existing != nil {
			continue
		}
		if err := linkStore.Insert(context.Background(), &links.Link{
			NeighborIA: l.Neighbor,
			Local:      local,
			Remote:     remote,
			State:      links.StateEstablished,
		}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := linkStore.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	serving := links.Serving(entries)

	dLinks := []dataplane.Link{}
	il, err := provider.NewInternalLink(internal, 64,
		metrics.NewInterfaceMetrics(0, ia, 0))
	if err != nil {
		t.Fatal(err)
	}
	dLinks = append(dLinks, il)
	for _, l := range serving {
		el, err := provider.NewExternalLink(64, nil, l.Local.String(), l.Remote.String(),
			l.IfID, metrics.NewInterfaceMetrics(l.IfID, ia, 0))
		if err != nil {
			t.Fatal(err)
		}
		dLinks = append(dLinks, el)
	}
	local := addr.HostIP(controlAddr.Addr())
	d, err := dataplane.NewDataPlane(ia, local, macKey, provider, dLinks)
	if err != nil {
		t.Fatal(err)
	}
	d.RunConfig = dataplane.RunConfig{NumProcessors: 2, NumSlowPathProcessors: 1, BatchSize: 64}
	discovery, err := controlplane.NewDiscovery(controlplane.DiscoveryConfig{
		IA:           ia,
		ControlAddr:  control,
		MACKey:       macKey,
		InternalAddr: internal,
		Store:        linkStore,
		Interval:     DiscoveryGap,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := discovery.Register(provider); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		provider.Stop()
		discovery.Close() //nolint:errcheck
	})
	// The link store's file lock releases with the node's cancellation, so
	// a restarted node — the same state directory — opens it instead of
	// blocking on it.
	go func() {
		<-ctx.Done()
		linkStore.Close() //nolint:errcheck
	}()
	go func() { _ = d.Serve(ctx) }()
	go discovery.Run(ctx)

	scionConn := func(port uint16) *scion.Conn {
		bind := netip.AddrPortFrom(controlAddr.Addr(), port).String()
		conn, err := scion.NewConn(scion.ConnConfig{
			IA:           ia,
			Bind:         bind,
			InternalAddr: internal,
			MACKey:       macKey,
			Links:        linkTableOf(linkStore),
		})
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}

	var issuer *trust.Issuer
	var coreClt *controlplane.CoreClient
	if core {
		keys, err := trust.LoadOrCreateCoreKeys(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		trc, err := trust.Genesis(ctx, trustDB, ia, keys)
		if err != nil {
			t.Fatal(err)
		}
		issuer, err = trust.NewIssuer(ia, keys, trc)
		if err != nil {
			t.Fatal(err)
		}
		if err := selfEnroll(ctx, trustDB, issuer, ia, asKey); err != nil {
			t.Fatal(err)
		}
	} else {
		coreClt, err = controlplane.NewCoreClient(controlplane.CoreClientConfig{
			Domain:  TestDomain,
			Conn:    scionConn(0),
			RootCAs: wpki.pool,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	var pathProvider *scion.PathProvider
	coreRoute := func() *scion.Addr {
		coreIA, coreEndpoint, ok := discovery.CoreEndpoint()
		if !ok {
			return nil
		}
		for _, n := range discovery.Neighbors() {
			if n.IA.Equal(coreIA) {
				return &scion.Addr{IA: coreIA,
					Addr: netip.AddrPortFrom(n.ControlAddr.Addr(), controlplane.EndpointPort)}
			}
		}
		if pathProvider != nil {
			if path, err := pathProvider.LocalPath(coreIA); err == nil {
				return &scion.Addr{IA: coreIA, Addr: coreEndpoint, Path: path}
			}
		}
		return nil
	}
	if coreClt != nil {
		coreClt.SetLocator(coreRoute)
	}

	remote := trust.Remote(nil)
	if coreClt != nil {
		remote = coreClt
	}
	engine := trust.NewEngine(ia, asKey, &trust.NetworkProvider{DB: trustDB, Remote: remote})
	cores := func(isd addr.ISD) []addr.IA {
		ias, err := engine.CoreASes(isd)
		if err != nil {
			return nil
		}
		return ias
	}

	peerClt := controlplane.NewPeerClient(controlplane.PeerClientConfig{
		Engine: engine,
		Conn:   scionConn(0),
		PathTo: func(dst addr.IA) *spath.Decoded {
			if pathProvider == nil {
				return nil
			}
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
	lookup.IsCore = core
	lookup.Cores = cores
	lookup.Fetch = peerClt.Segments
	lookup.CoreRoute = coreRoute

	store := controlplane.NewBeaconStore()
	beaconer, err := controlplane.NewBeaconer(controlplane.BeaconerConfig{
		IA:                   ia,
		Engine:               engine,
		MACKey:               macKey,
		Store:                store,
		DB:                   pathDB,
		Links:                linkTableOf(linkStore),
		Neighbors:            discovery.Neighbors,
		Sender:               peerClt,
		CoreRoute:            coreRoute,
		Core:                 core,
		PropagationInterval:  Propagation,
		RegistrationInterval: Registration,
		SendTimeout:          time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	pathProvider = &scion.PathProvider{
		IA:        ia,
		DB:        pathDB,
		Lookup:    lookup.Down,
		Bootstrap: beaconer.BootstrapRoute,
		Cores:     cores,
	}

	var webPKIConf *tls.Config
	if core {
		conf, err := controlplane.ManageTLSCert(ctx, controlplane.TLSCertConfig{
			Domain:   TestDomain,
			CertFile: wpki.certFile,
			KeyFile:  wpki.keyFile,
		})
		if err != nil {
			t.Fatal(err)
		}
		webPKIConf = conf
	}
	endpointConn := scionConn(controlplane.EndpointPort)
	// The HTTP/3 server serves until its socket closes; releasing it lets a
	// re-run of the suite (go test -count) bind the fixed port again.
	t.Cleanup(func() { endpointConn.Close() }) //nolint:errcheck
	svc := &controlplane.Services{
		TrustService: &controlplane.TrustService{DB: trustDB, Issuer: issuer},
		SegmentService: &controlplane.SegmentService{
			Beaconer: beaconer,
			Lookup:   lookup,
		},
	}
	go func() {
		defer handlePanic()
		if err := controlplane.ServeHTTP3(endpointConn, controlplane.NewServer(svc).Handler,
			controlplane.EndpointTLS(controlplane.EndpointTLSConfig{
				Domain: TestDomain,
				WebPKI: webPKIConf,
				Engine: engine,
			})); err != nil {
			t.Logf("control endpoint exited: %v", err)
		}
	}()

	if core {
		endpoint := endpointConn.LocalAddr().(*scion.Addr).Addr
		discovery.SetCoreEndpoint(ia, endpoint)
		go func() {
			defer handlePanic()
			controlplane.RunCoreEnrollment(ctx, controlplane.EnrollmentConfig{
				IA: ia, DB: trustDB, Key: asKey, Issuer: issuer,
				RetryInterval: EnrollRetry, Timeout: time.Second,
			})
		}()
	} else {
		go func() {
			defer handlePanic()
			controlplane.RunEnrollment(ctx, controlplane.EnrollmentConfig{
				IA: ia, DB: trustDB, Key: asKey, Remote: coreClt,
				RetryInterval: EnrollRetry, Timeout: time.Second,
			})
		}()
	}
	go func() {
		defer handlePanic()
		beaconer.Run(ctx)
	}()

	node := &Node{
		IA:        ia,
		Internal:  internal,
		ControlIP: controlAddr.Addr(),
		Links:     linkTableOf(linkStore),
		Store:     linkStore,
		MACKey:    macKey,
		TrustDB:   trustDB,
		PathDB:    pathDB,
		Engine:    engine,
		Beaconer:  beaconer,
		StoreBcn:  store,
		CoreClt:   coreClt,
		PeerClt:   peerClt,
		Provider:  pathProvider,
		Lookup:    lookup,
		Discovery: discovery,
		cancel:    cancel,
	}

	if cfg.Wireguard != nil {
		node.startWireguard(t, ctx, *cfg.Wireguard, stateDir, scionConn, coreRoute, controlAddr, provider)
	}
	return node
}

// linkTableOf snapshots a link store into the interface-ID-to-neighbor map
// the data plane consumers read.
func linkTableOf(store links.DB) func() map[uint16]addr.IA {
	return func() map[uint16]addr.IA {
		entries, err := store.All(context.Background())
		if err != nil {
			return nil
		}
		return links.Links(entries)
	}
}

// startWireguard starts the node's WireGuard application: the mesh
// transport, the host devices behind their shared port, the router and
// egress, and the directory — served by the core, published and fetched by
// everyone — per the node assembly's own wiring.
func (n *Node) startWireguard(
	t *testing.T,
	ctx context.Context,
	opts WireguardOptions,
	stateDir string,
	scionConn func(uint16) *scion.Conn,
	coreRoute func() *scion.Addr,
	controlAddr netip.AddrPort,
	provider *dataplane.UDPProvider,
) {

	t.Helper()
	wgState := filepath.Join(stateDir, "wireguard")
	wgCfg := wireguard.Config{
		IA:         n.IA,
		Subnet:     netip.MustParsePrefix(opts.Subnet),
		ListenHost: controlAddr.Addr(),
		ListenPort: opts.ListenPort,
		Egress:     opts.Egress,
		Exits:      opts.Exits,
		Peers:      opts.Peers,
		StateDir:   wgState,
		Provider:   n.Provider,
		Engine:     n.Engine,
		NewConn: func() (*scion.Conn, error) {
			return scionConn(0), nil
		},
		RegisterSvc: func(svc addr.SVC, port uint16) error {
			return provider.AddSvc(svc, addr.HostIP(controlAddr.Addr()), port)
		},
		UnregisterSvc: func(svc addr.SVC, port uint16) error {
			return provider.DelSvc(svc, addr.HostIP(controlAddr.Addr()), port)
		},
		PublishInterval: WireguardPublish,
		RefreshInterval: WireguardRefresh,
		PublishRetry:    WireguardRetry,
	}
	if opts.ListenPort == 0 {
		wgCfg.ListenPort = freeUDPPort(t)
	}
	if n.CoreClt == nil {
		// The core serves the directory from its own store.
		if err := os.MkdirAll(wgState, 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := wireguardbbolt.New(filepath.Join(wgState, "directory.db"), nil)
		if err != nil {
			t.Fatal(err)
		}
		wgCfg.Store = store
	} else {
		wgCfg.CoreRoute = func() *scion.Addr {
			route := coreRoute()
			if route == nil {
				return nil
			}
			return &scion.Addr{IA: route.IA, Service: wireguard.SvcDirectory, Path: route.Path}
		}
	}
	app, err := wireguard.New(wgCfg)
	if err != nil {
		t.Fatal(err)
	}
	n.Wireguard = app
	go func() {
		defer handlePanic()
		if err := app.Run(ctx); err != nil {
			t.Logf("wireguard exited: %v", err)
		}
	}()
}

// freeUDPPort reserves an ephemeral port and releases it for the caller.
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	c.Close()
	return port
}

// FreeUDPAddrOn returns a free UDP address on the given host.
func FreeUDPAddrOn(t *testing.T, ip netip.Addr) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().String()
}

func selfEnroll(
	ctx context.Context, db trust.DB, issuer *trust.Issuer,
	ia addr.IA, key crypto.Signer) error {

	csr, err := trust.CreateCSR(ia, key)
	if err != nil {
		return err
	}
	chain, err := issuer.IssueChain(csr)
	if err != nil {
		return err
	}
	_, err = db.InsertChain(ctx, chain)
	return err
}

// StartPingResponder serves echo replies on the node's endhost port, the
// loop the daemon's own core runs beside the control endpoint (ADR 0007) —
// the harness wires it by hand, its nodes not being the daemon's assembly.
func StartPingResponder(t *testing.T, n *Node) {
	t.Helper()
	conn := n.NewConn(t, dataplane.EndhostPort)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck
	go func() {
		for {
			echo, from, err := conn.ReadEchoFrom()
			if err != nil {
				return
			}
			if echo.Reply {
				continue
			}
			if err := conn.WriteEchoReplyTo(from, echo.Identifier, echo.Seq,
				echo.Payload); err != nil {
				return
			}
		}
	}()
}

// handlePanic absorbs a background loop's panic, the way the node assembly's
// own runner does — one loop's bug must not take the test binary down.
func handlePanic() {
	if r := recover(); r != nil {
		slog.Error("Panic in testnetwork", "panic", r)
	}
}

// Poll waits for cond to hold, failing the test at the timeout.
func Poll(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(TestTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
