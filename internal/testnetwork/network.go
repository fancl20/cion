// Package testnetwork is the integration tests' topology harness: the fully
// wired nodes of pkg/controlplane/network_test.go's harness, extended per
// proposal 0006 with the WireGuard gateway application, moved where the
// gateway's own integration tests can assemble beside them — the harness
// imports the control plane, so the control plane's package cannot host it.
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

	"github.com/fancl20/cion/pkg/apps/ping"
	"github.com/fancl20/cion/pkg/apps/wireguard"
	gatewaybbolt "github.com/fancl20/cion/pkg/apps/wireguard/impl/bbolt"
	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/dataplane"
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
	// GatewayCadence paces the gateway's publication and directory refresh.
	GatewayPublish = 200 * time.Millisecond
	GatewayRefresh = 200 * time.Millisecond
	GatewayRetry   = 100 * time.Millisecond
	TestTimeout    = 20 * time.Second
)

// TestDomain is the DNS identity of the core endpoint in tests; its
// certificate is signed by a test CA that stands in for the WebPKI.
const TestDomain = "cion-core.test"

// MACKey is the forwarding key the harness's data planes verify against.
var MACKey = []byte("0123456789abcdef")

// Node is one fully-wired node of a test topology — the same components the
// run command wires in internal/services: data plane, discovery, trust, the
// control endpoint, the beaconer, and — when configured — the gateway
// application.
type Node struct {
	IA        addr.IA
	Internal  string
	ControlIP netip.Addr
	Links     map[uint16]addr.IA
	TrustDB   trust.DB
	PathDB    pathdb.DB
	Engine    *trust.Engine
	Beaconer  *controlplane.Beaconer
	Store     *controlplane.BeaconStore
	CoreClt   *controlplane.CoreClient
	PeerClt   *controlplane.PeerClient
	Provider  *scion.PathProvider
	Lookup    *controlplane.LookupService
	Discovery *controlplane.Discovery
	Gateway   *wireguard.Gateway
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
		MACKey:       MACKey,
		Links:        n.Links,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck
	return conn
}

// Link is one external link of a node.
type Link struct {
	IfID     uint16
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

// GatewayOptions configures a node's gateway application; nil runs none.
type GatewayOptions struct {
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
	// Links are the node's external links.
	Links []Link
	// Core marks the founding core node.
	Core bool
	// WPKI anchors the bootstrap channel's certificate.
	WPKI *WebPKI
	// Gateway starts the gateway application when set.
	Gateway *GatewayOptions
}

// StartNode brings up a node with the given configuration. The core serves
// the WebPKI bootstrap channel for TestDomain alongside the SCION-native
// channel; non-core nodes enroll against it.
func StartNode(t *testing.T, cfg NodeConfig) *Node {
	t.Helper()
	ia, host, links, core, wpki := cfg.IA, cfg.Host, cfg.Links, cfg.Core, cfg.WPKI
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
	il, err := provider.NewInternalLink(internal, 64,
		metrics.NewInterfaceMetrics(0, ia, 0))
	if err != nil {
		t.Fatal(err)
	}
	dLinks := []dataplane.Link{il}
	neighborLinks := make(map[uint16]addr.IA, len(links))
	for _, l := range links {
		el, err := provider.NewExternalLink(64, nil, l.Local, l.Remote, l.IfID,
			metrics.NewInterfaceMetrics(l.IfID, ia, 0))
		if err != nil {
			t.Fatal(err)
		}
		dLinks = append(dLinks, el)
		neighborLinks[l.IfID] = l.Neighbor
	}
	local := addr.HostIP(controlAddr.Addr())
	d, err := dataplane.NewDataPlane(ia, local, MACKey, provider, dLinks)
	if err != nil {
		t.Fatal(err)
	}
	d.RunConfig = dataplane.RunConfig{NumProcessors: 2, NumSlowPathProcessors: 1, BatchSize: 64}
	discovery, err := controlplane.NewDiscovery(controlplane.DiscoveryConfig{
		IA:           ia,
		ControlAddr:  control,
		MACKey:       MACKey,
		InternalAddr: internal,
		Links:        neighborLinks,
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
	go func() { _ = d.Serve(ctx) }()
	go discovery.Run(ctx)

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
	asKey, err := trust.LoadOrCreateASKey(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	scionConn := func(port uint16) *scion.Conn {
		bind := netip.AddrPortFrom(controlAddr.Addr(), port).String()
		conn, err := scion.NewConn(scion.ConnConfig{
			IA:           ia,
			Bind:         bind,
			InternalAddr: internal,
			MACKey:       MACKey,
			Links:        neighborLinks,
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
		MACKey:               MACKey,
		Store:                store,
		DB:                   pathDB,
		Links:                neighborLinks,
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
		Links:     neighborLinks,
		TrustDB:   trustDB,
		PathDB:    pathDB,
		Engine:    engine,
		Beaconer:  beaconer,
		Store:     store,
		CoreClt:   coreClt,
		PeerClt:   peerClt,
		Provider:  pathProvider,
		Lookup:    lookup,
		Discovery: discovery,
		cancel:    cancel,
	}

	if cfg.Gateway != nil {
		node.startGateway(t, ctx, *cfg.Gateway, stateDir, scionConn, coreRoute, controlAddr)
	}
	return node
}

// startGateway starts the node's gateway application: the mesh transport,
// the host devices behind their shared port, the router and egress, and the
// directory — served by the core, published and fetched by everyone — per
// the node assembly's own wiring.
func (n *Node) startGateway(
	t *testing.T,
	ctx context.Context,
	opts GatewayOptions,
	stateDir string,
	scionConn func(uint16) *scion.Conn,
	coreRoute func() *scion.Addr,
	controlAddr netip.AddrPort,
) {

	t.Helper()
	gwState := filepath.Join(stateDir, "gateway")
	gwCfg := wireguard.Config{
		IA:         n.IA,
		Subnet:     netip.MustParsePrefix(opts.Subnet),
		ListenHost: controlAddr.Addr(),
		ListenPort: opts.ListenPort,
		Egress:     opts.Egress,
		Exits:      opts.Exits,
		Peers:      opts.Peers,
		StateDir:   gwState,
		Provider:   n.Provider,
		Engine:     n.Engine,
		NewConn: func(port uint16) (*scion.Conn, error) {
			return scionConn(port), nil
		},
		PublishInterval: GatewayPublish,
		RefreshInterval: GatewayRefresh,
		PublishRetry:    GatewayRetry,
	}
	if opts.ListenPort == 0 {
		gwCfg.ListenPort = freeUDPPort(t)
	}
	if n.CoreClt == nil {
		// The core serves the directory from its own store.
		if err := os.MkdirAll(gwState, 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := gatewaybbolt.New(filepath.Join(gwState, "directory.db"), nil)
		if err != nil {
			t.Fatal(err)
		}
		gwCfg.Store = store
	} else {
		gwCfg.CoreRoute = func() *scion.Addr {
			route := coreRoute()
			if route == nil {
				return nil
			}
			route.Addr = netip.AddrPortFrom(route.Addr.Addr(), controlplane.DirectoryPort)
			return route
		}
	}
	gateway, err := wireguard.New(gwCfg)
	if err != nil {
		t.Fatal(err)
	}
	n.Gateway = gateway
	go func() {
		defer handlePanic()
		if err := gateway.Run(ctx); err != nil {
			t.Logf("gateway exited: %v", err)
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

// StartPingResponder serves echo replies on the node's endhost port, as the
// daemon does beside the control endpoint.
func StartPingResponder(t *testing.T, n *Node) {
	t.Helper()
	responder := &ping.Responder{Conn: n.NewConn(t, dataplane.EndhostPort)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go responder.Run(ctx)
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
