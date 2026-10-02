// Package testnetwork is the integration tests' topology harness: the fully
// wired nodes, WireGuard application and link store included, where the
// applications' own integration tests assemble beside them — the harness
// imports the control plane, so the control plane's package cannot host
// it.
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
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	wireguardbbolt "github.com/fancl20/cion/pkg/apps/wireguard/impl/bbolt"
	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/modules/links"
	linkbbolt "github.com/fancl20/cion/pkg/modules/links/impl/bbolt"
	"github.com/fancl20/cion/pkg/modules/pathdb"
	pathdbbbolt "github.com/fancl20/cion/pkg/modules/pathdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	trustbbolt "github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/webpki"
)

// Test intervals, fast enough for the integration tests to watch the loops.
const (
	Propagation  = 100 * time.Millisecond
	Registration = 200 * time.Millisecond
	EnrollRetry  = 100 * time.Millisecond
	// WireguardCadence paces the application's publication and directory
	// refresh.
	WireguardPublish = 200 * time.Millisecond
	WireguardRefresh = 200 * time.Millisecond
	WireguardRetry   = 100 * time.Millisecond
	TestTimeout      = 20 * time.Second
	// RestartTimeout budgets the restart lab's convergence: the reboot puts
	// the joiner's loop through serial stages — re-rendezvous, a fresh
	// prompt, the press, the chain — whose wall-clock pacing stretches
	// several-fold on a loaded runner under the race detector, where the
	// fixed TestTimeout missed a pipeline still progressing.
	RestartTimeout = 3 * TestTimeout
)

// TestDomain is the DNS identity of the core endpoint in tests; its
// certificate is signed by a test CA that stands in for the WebPKI.
const TestDomain = "cion-core.test"

// Node is one fully-wired node of a test topology — the same components the
// run command wires in internal/services: data plane, the link store, the
// BFD health monitor, trust, the control endpoint, the beaconer, and — when
// configured — the WireGuard application.
type Node struct {
	IA        addr.IA
	Internal  string
	ControlIP netip.Addr
	Links     func() map[uint16]addr.IA
	Store     links.DB
	MACKey    []byte
	Monitor   *controlplane.HealthMonitor
	TrustDB   trustdb.DB
	PathDB    pathdb.DB
	Engine    *trust.Engine
	Beaconer  *controlplane.Beaconer
	StoreBcn  *controlplane.BeaconStore
	CoreClt   *webpki.CoreClient
	PeerClt   *controlplane.PeerClient
	Provider  *scion.PathProvider
	Lookup    *controlplane.LookupService
	Wireguard *wireguard.App
	// WireguardStore is the core's directory store — the registry the
	// coordination application writes host entries into. Nil on non-cores.
	WireguardStore wireguard.DirectoryStore
	cancel         context.CancelFunc
	// underlayDone closes when the data plane's Serve returned — its
	// underlay sockets released with it.
	underlayDone chan struct{}
}

// WaitUnderlayReleased waits the node's data plane out: Serve returned, the
// underlay addresses released — a restarted node rebinds the recorded link
// addresses against no holder of its previous incarnation.
func (n *Node) WaitUnderlayReleased() {
	<-n.underlayDone
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
	t.Cleanup(func() { _ = conn.Close() })
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
	caFile   string
}

// NewWebPKI creates the CA and the server certificate for TestDomain,
// returning the certificate files and the pool trusting the CA.
func NewWebPKI(t *testing.T) *WebPKI {
	t.Helper()
	wpki, err := mintWebPKI(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return wpki
}

// mintWebPKI creates the CA and the server certificate for TestDomain in
// the given directory, returning the certificate files, the pool trusting
// the CA, and the CA's own certificate file.
func mintWebPKI(dir string) (*WebPKI, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: TestDomain},
		DNSNames:     []string{TestDomain},
		// The loopback address beside the name: the coordination endpoint is an
		// internet-facing surface, and the harness's tailnet clients dial it by
		// address.
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert,
		serverKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return nil, err
	}
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &WebPKI{
		pool:     pool,
		certFile: certFile,
		keyFile:  keyFile,
		caFile:   filepath.Join(dir, "ca.pem"),
	}, nil
}

// WireguardOptions configures a node's WireGuard application; nil runs
// none. The node's slice of the tailnet range is the directory's
// assignment, answered at the first publication.
type WireguardOptions struct {
	// ListenPort is the shared host-facing port; 0 takes an ephemeral one.
	ListenPort uint16
	// DERP names the relay presence the node holds, when the harness runs
	// one beside the plain UDP leg; nil runs none.
	DERP *wireguard.DERPConfig
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
	// GenesisCores lists fellow core ISD-ASes the founding core's genesis
	// TRC names beside itself. Nil founds a single-core ISD.
	GenesisCores []addr.IA
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
	// nodes share one test host even with the fixed endpoint port. The
	// internal link's address is rebound, so it comes from the pinned band.
	internal, control := PinnedUDPAddrOn(t, host), FreeUDPAddrOn(t, host)
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

	// The BFD health monitor the daemon's own assembly builds: a session per
	// serving link, the store its source either way.
	monitor, err := controlplane.NewHealthMonitor(controlplane.HealthMonitorConfig{
		IA:     ia,
		MACKey: macKey,
		Store:  linkStore,
	})
	if err != nil {
		t.Fatal(err)
	}

	dLinks := []dataplane.Link{}
	il, err := provider.NewInternalLink(internal, 64,
		metrics.NewInterfaceMetrics(0, ia, 0))
	if err != nil {
		t.Fatal(err)
	}
	dLinks = append(dLinks, il)
	for _, l := range serving {
		el, err := provider.NewExternalLink(64, monitor.Session(l), l.Local.String(),
			l.Remote.String(), l.IfID, metrics.NewInterfaceMetrics(l.IfID, ia, 0))
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
	// The CS service maps to the control endpoint's socket — the registered
	// service the drafts' service routing delivers to, the endpoint
	// answering the drafts' resolution beside its own protocol.
	if err := provider.AddSvc(addr.SvcCS, addr.HostIP(controlAddr.Addr()),
		controlplane.EndpointPort); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	// The data plane's serve loop joins the node's cleanup: a hung loop is a
	// test failure with a stack, not a silent tenant past the test.
	serveDone := make(chan error, 1)
	// The control-plane clients and the conns they dial through close with
	// the node too, each client before its conn: their QUIC transports
	// otherwise park a goroutine pair and an open socket past every lab
	// that spawned them.
	var closers []io.Closer
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("the data plane's Serve returned %v, want nil", err)
			}
		case <-time.After(TestTimeout):
			t.Error("the data plane's Serve did not return after cancellation")
		}
		for _, c := range closers {
			_ = c.Close()
		}
		provider.Stop()
	})
	// The link store's file lock releases with the node's cancellation, so
	// a restarted node — the same state directory — opens it instead of
	// blocking on it.
	go func() {
		<-ctx.Done()
		_ = linkStore.Close()
	}()
	underlayDone := make(chan struct{})
	go func() {
		serveDone <- d.Serve(ctx)
		close(underlayDone)
	}()
	go func() {
		defer handlePanic()
		monitor.Run(ctx)
	}()

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

	endpointConn := scionConn(controlplane.EndpointPort)
	// The HTTP/3 server serves until its socket closes; releasing it lets a
	// re-run of the suite (go test -count) bind the fixed port again.
	t.Cleanup(func() { _ = endpointConn.Close() })

	var issuer *trust.Issuer
	var coreClt *webpki.CoreClient
	if core {
		keys, err := trust.LoadOrCreateCoreKeys(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		trc, err := trust.Genesis(ctx, trustDB, ia, keys, cfg.GenesisCores...)
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
		coreConn := scionConn(0)
		// The resolution exchange reads its own conn: one shared with the
		// client's QUIC transport would race it for the socket's packets.
		resolutionConn := scionConn(0)
		coreClt, err = webpki.NewCoreClient(webpki.CoreClientConfig{
			Domain:  TestDomain,
			Conn:    coreConn,
			RootCAs: wpki.pool,
			ResolveService: func(ctx context.Context, peer *scion.Addr) (netip.AddrPort, error) {
				return controlplane.ResolveService(ctx, resolutionConn, peer)
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		closers = append(closers, coreClt, coreConn, resolutionConn)
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
	// issuers enumerates the cores a root certificate in the pinned TRC
	// names — the nodes that can serve a chain renewal — the assembly's own
	// enrollment route selects by.
	issuers := func(isd addr.ISD) map[addr.IA]bool {
		ias, err := engine.IssuerASes(isd)
		if err != nil {
			return nil
		}
		set := make(map[addr.IA]bool, len(ias))
		for _, ia := range ias {
			set[ia] = true
		}
		return set
	}

	var pathProvider *scion.PathProvider
	var beaconer *controlplane.Beaconer
	// coreRoute returns the drafts' route to the core, routed to the issuers:
	// the one-hop shortcut when an issuer core is a neighbor with its verdict
	// up, else the reversed freshest up segment ending at one — or the
	// bootstrap beacon's route, before any is verified — addressed to the
	// core's control service.
	coreRoute := func() *scion.Addr {
		for ifID, neighborIA := range linkTableOf(linkStore)() {
			if neighborIA.IsZero() || !issuers(neighborIA.ISD())[neighborIA] {
				continue
			}
			if monitor.Up(ifID) {
				return &scion.Addr{IA: neighborIA, Service: addr.SvcCS, IfID: ifID}
			}
		}
		for _, core := range []func() addr.IA{
			func() addr.IA { return freshestUpCore(pathDB, issuers) },
			beaconer.BootstrapCore,
		} {
			if coreIA := core(); !coreIA.IsZero() {
				if path, err := pathProvider.LocalPath(coreIA); err == nil {
					return &scion.Addr{IA: coreIA, Service: addr.SvcCS, Path: path}
				}
			}
		}
		return nil
	}
	if coreClt != nil {
		coreClt.SetLocator(coreRoute)
	}

	peerConn := scionConn(0)
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
	closers = append(closers, peerClt, peerConn)

	lookup := controlplane.NewLookupService()
	lookup.IA = ia
	lookup.DB = pathDB
	lookup.IsCore = core
	lookup.Cores = cores
	lookup.Fetch = peerClt.Segments
	lookup.CoreRoute = coreRoute

	store := controlplane.NewBeaconStore()
	beaconer, err = controlplane.NewBeaconer(controlplane.BeaconerConfig{
		IA:                   ia,
		Engine:               engine,
		MACKey:               macKey,
		Store:                store,
		DB:                   pathDB,
		Links:                linkTableOf(linkStore),
		Verdicts:             monitor.Verdicts,
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
		manager, err := webpki.PrepareTLSCert(ctx, webpki.TLSCertConfig{
			Domain:   TestDomain,
			CertFile: wpki.certFile,
			KeyFile:  wpki.keyFile,
		})
		if err != nil {
			t.Fatal(err)
		}
		webPKIConf = manager.TLSConfig()
	}
	svc := &controlplane.Services{
		TrustService: &controlplane.TrustService{DB: trustDB, Issuer: issuer},
		SegmentService: &controlplane.SegmentService{
			Beaconer: beaconer,
			Lookup:   lookup,
		},
	}
	// The endpoint serves until its socket closes at cleanup — a daemon
	// whose goroutine can outlive the test — so it reports through the
	// package logger, never `t`.
	go func() {
		defer handlePanic()
		if err := controlplane.ServeHTTP3(endpointConn, controlplane.NewServer(svc).Handler,
			controlplane.EndpointTLS(controlplane.EndpointTLSConfig{
				Domain: TestDomain,
				WebPKI: webPKIConf,
				Engine: engine,
			})); err != nil {
			slog.Debug("control endpoint exited", "err", err)
		}
	}()

	if core {
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
		Monitor:   monitor,
		TrustDB:   trustDB,
		PathDB:    pathDB,
		Engine:    engine,
		Beaconer:  beaconer,
		StoreBcn:  store,
		CoreClt:   coreClt,
		PeerClt:   peerClt,
		Provider:  pathProvider,
		Lookup:    lookup,
		cancel:    cancel,

		underlayDone: underlayDone,
	}

	if cfg.Wireguard != nil {
		node.startWireguard(t, ctx, *cfg.Wireguard, stateDir, scionConn, coreRoute, controlAddr, provider)
	}
	return node
}

// freshestUpCore returns the origin of the freshest up segment the node has
// verified that ends at an issuer core; zero when none is stored.
func freshestUpCore(db pathdb.DB, issuers func(addr.ISD) map[addr.IA]bool) addr.IA {
	segs, err := db.Get(context.Background(), pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil {
		return 0
	}
	var core addr.IA
	var best time.Time
	for _, seg := range segs {
		if !issuers(seg.FirstIA().ISD())[seg.FirstIA()] {
			continue
		}
		if core.IsZero() || seg.PCB.Timestamp().After(best) {
			core, best = seg.FirstIA(), seg.PCB.Timestamp()
		}
	}
	return core
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
// transport, the one host device behind its shared port, the router, and
// the directory — served by the core, published and fetched by everyone —
// per the node assembly's own wiring.
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
		ListenHost: controlAddr.Addr(),
		ListenPort: opts.ListenPort,
		DERP:       opts.DERP,
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
	if wgCfg.Store != nil {
		n.WireguardStore = wgCfg.Store
	}
	// The application's loop reports through the package logger like the
	// endpoint's: both outlive the test's own thread.
	go func() {
		defer handlePanic()
		if err := app.Run(ctx); err != nil {
			slog.Debug("wireguard application exited", "err", err)
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
	_ = c.Close()
	return port
}

// FreeUDPAddrOn returns a free UDP address on the given host.
func FreeUDPAddrOn(t *testing.T, ip netip.Addr) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return c.LocalAddr().String()
}

// The pinned port band: the addresses a node rebinds — a link-set's pinned
// locals, the internal link — are drawn from below the kernel's ephemeral
// range, where no bind(:0), the node's own control conns included, ever
// lands. A rebound address drawn from the ephemeral range instead is free
// at the draw yet any later bind(:0) can take it, and the node's own
// rebind then fails.
const (
	pinnedPortBase = 20000
	pinnedPortSpan = 5000
)

// pinnedPortDraws names the band's next port, so concurrent draws differ.
var pinnedPortDraws atomic.Uint32

// PinnedUDPAddrOn returns a UDP address on the given host for the node to
// rebind: the band's next free port, probed by binding it and released for
// the node's own bind. The release is safe — nothing that binds :0 draws
// from the band.
func PinnedUDPAddrOn(t *testing.T, ip netip.Addr) string {
	t.Helper()
	for range pinnedPortSpan {
		addr := netip.AddrPortFrom(ip, pinnedPortBase+uint16(pinnedPortDraws.Add(1)%pinnedPortSpan))
		c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		return addr.String()
	}
	t.Fatalf("the pinned port band on %v is drawn dry", ip)
	return ""
}

func selfEnroll(
	ctx context.Context, db trustdb.DB, issuer *trust.Issuer,
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

// StartPingResponder serves echo replies on the node's endhost port, the loop
// the daemon's own core runs beside the control endpoint — the harness wires
// it by hand, its nodes not being the daemon's assembly.
func StartPingResponder(t *testing.T, n *Node) {
	t.Helper()
	conn := n.NewConn(t, dataplane.EndhostPort)
	t.Cleanup(func() { _ = conn.Close() })
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
	PollFor(t, TestTimeout, what, cond)
}

// PollFor is Poll under an explicit budget, for labs whose convergence
// outgrows TestTimeout on a loaded runner.
func PollFor(t *testing.T, budget time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
