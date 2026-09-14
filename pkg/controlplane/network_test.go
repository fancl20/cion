package controlplane

import (
	"context"
	"crypto"
	"crypto/tls"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/pathdb"
	pathdbbbolt "github.com/fancl20/cion/pkg/pathdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/trust/impl/bbolt"
)

// Test intervals, fast enough for the integration tests to watch the loops.
const (
	netDiscoveryGap = 30 * time.Millisecond
	netPropagation  = 100 * time.Millisecond
	netRegistration = 200 * time.Millisecond
	netEnrollRetry  = 100 * time.Millisecond
	netTestTimeout  = 20 * time.Second
)

// netNode is one fully-wired node of a test topology — the same components
// run() wires in cmd/cion: data plane, discovery, trust, the control
// endpoint, and the beaconer.
type netNode struct {
	ia        addr.IA
	internal  string
	controlIP netip.Addr
	links     map[uint16]addr.IA
	stateDir  string
	trustDB   trust.DB
	pathDB    pathdb.DB
	engine    *trust.Engine
	beaconer  *Beaconer
	coreClt   *CoreClient
	peerClt   *PeerClient
	provider  *scion.PathProvider
	lookup    *LookupService
	discovery *Discovery
	cancel    context.CancelFunc
}

// newNetConn returns a SCION connection of the node, bound to the control
// address's host with the given port.
func (n *netNode) newNetConn(t *testing.T, port uint16) *scion.Conn {
	t.Helper()
	conn, err := scion.NewConn(scion.ConnConfig{
		IA:           n.ia,
		Bind:         netip.AddrPortFrom(n.controlIP, port).String(),
		InternalAddr: n.internal,
		MACKey:       testMACKeyBytes,
		Links:        n.links,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck
	return conn
}

// netLink is one external link of a node.
type netLink struct {
	ifID     uint16
	local    string
	remote   string
	neighbor addr.IA
}

// startNetNode brings up a node with the given links. The core serves the
// WebPKI bootstrap channel for testDomain alongside the SCION-native
// channel; non-core nodes enroll against it.
func startNetNode(
	t *testing.T,
	ia addr.IA,
	host netip.Addr,
	stateDir string,
	links []netLink,
	core bool,
	wpki *webPKI,
) *netNode {

	t.Helper()
	metrics, err := dataplane.NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	provider := dataplane.NewUDPProvider(64, 0, 0)
	// Every address of the node sits on its own loopback address, so several
	// nodes share one test host even with the fixed endpoint port.
	internal, control := freeUDPAddrOn(t, host), freeUDPAddrOn(t, host)
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
		el, err := provider.NewExternalLink(64, nil, l.local, l.remote, l.ifID,
			metrics.NewInterfaceMetrics(l.ifID, ia, 0))
		if err != nil {
			t.Fatal(err)
		}
		dLinks = append(dLinks, el)
		neighborLinks[l.ifID] = l.neighbor
	}
	local := addr.HostIP(controlAddr.Addr())
	d, err := dataplane.NewDataPlane(ia, local, testMACKeyBytes, provider, dLinks)
	if err != nil {
		t.Fatal(err)
	}
	d.RunConfig = dataplane.RunConfig{NumProcessors: 2, NumSlowPathProcessors: 1, BatchSize: 64}
	discovery, err := NewDiscovery(DiscoveryConfig{
		IA:           ia,
		ControlAddr:  control,
		MACKey:       testMACKeyBytes,
		InternalAddr: internal,
		Links:        neighborLinks,
		Interval:     netDiscoveryGap,
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
	trustDB, err := bbolt.New(filepath.Join(stateDir, "trust.db"), nil)
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
			MACKey:       testMACKeyBytes,
			Links:        neighborLinks,
		})
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}

	var issuer *trust.Issuer
	var coreClt *CoreClient
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
		if err := selfEnrollNet(ctx, trustDB, issuer, ia, asKey); err != nil {
			t.Fatal(err)
		}
	} else {
		coreClt, err = NewCoreClient(CoreClientConfig{
			Domain:  testDomain,
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
					Addr: netip.AddrPortFrom(n.ControlAddr.Addr(), EndpointPort)}
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

	peerClt := NewPeerClient(PeerClientConfig{
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

	lookup := NewLookupService()
	lookup.IA = ia
	lookup.DB = pathDB
	lookup.IsCore = core
	lookup.Cores = cores
	lookup.Fetch = peerClt.Segments
	lookup.CoreRoute = coreRoute

	store := NewBeaconStore()
	beaconer, err := NewBeaconer(BeaconerConfig{
		IA:                   ia,
		Engine:               engine,
		MACKey:               testMACKeyBytes,
		Store:                store,
		DB:                   pathDB,
		Links:                neighborLinks,
		Neighbors:            discovery.Neighbors,
		Sender:               peerClt,
		CoreRoute:            coreRoute,
		Core:                 core,
		PropagationInterval:  netPropagation,
		RegistrationInterval: netRegistration,
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
		conf, err := ManageTLSCert(ctx, TLSCertConfig{
			Domain:   testDomain,
			CertFile: wpki.certFile,
			KeyFile:  wpki.keyFile,
		})
		if err != nil {
			t.Fatal(err)
		}
		webPKIConf = conf
	}
	endpointConn := scionConn(EndpointPort)
	// The HTTP/3 server serves until its socket closes; releasing it lets a
	// re-run of the suite (go test -count) bind the fixed port again.
	t.Cleanup(func() { endpointConn.Close() }) //nolint:errcheck
	svc := &Services{
		TrustService: &TrustService{DB: trustDB, Issuer: issuer},
		SegmentService: &SegmentService{
			Beaconer: beaconer,
			Lookup:   lookup,
		},
	}
	go func() {
		defer handlePanic()
		if err := ServeHTTP3(endpointConn, NewServer(svc).Handler,
			EndpointTLS(EndpointTLSConfig{
				Domain: testDomain,
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
			RunCoreEnrollment(ctx, EnrollmentConfig{
				IA: ia, DB: trustDB, Key: asKey, Issuer: issuer,
				RetryInterval: netEnrollRetry, Timeout: time.Second,
			})
		}()
	} else {
		go func() {
			defer handlePanic()
			RunEnrollment(ctx, EnrollmentConfig{
				IA: ia, DB: trustDB, Key: asKey, Remote: coreClt,
				RetryInterval: netEnrollRetry, Timeout: time.Second,
			})
		}()
	}
	go func() {
		defer handlePanic()
		beaconer.Run(ctx)
	}()

	return &netNode{
		ia:        ia,
		internal:  internal,
		controlIP: controlAddr.Addr(),
		links:     neighborLinks,
		trustDB:   trustDB,
		pathDB:    pathDB,
		engine:    engine,
		beaconer:  beaconer,
		coreClt:   coreClt,
		peerClt:   peerClt,
		provider:  pathProvider,
		lookup:    lookup,
		discovery: discovery,
		cancel:    cancel,
	}
}

func selfEnrollNet(
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

// poll waits for cond to hold, failing the test at the timeout.
func poll(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(netTestTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestLineTopology is the integration test of proposal 0004: a three-node
// line topology — the core A, the middle B, and C below with no A–C link —
// where beacons propagate A→B→C with signatures verified at each hop, C
// enrolls through the reversed beacon over B, C registers a down segment at
// A through B, and the provider resolves an end-to-end path from C to A.
func TestLineTopology(t *testing.T) {
	wpki := newTestWebPKI(t)
	ipA := netip.MustParseAddr("127.0.0.2")
	ipB := netip.MustParseAddr("127.0.0.3")
	ipC := netip.MustParseAddr("127.0.0.4")
	extA, extB1 := freeUDPAddrOn(t, ipA), freeUDPAddrOn(t, ipB)
	extB2, extC := freeUDPAddrOn(t, ipB), freeUDPAddrOn(t, ipC)

	a := startNetNode(t, coreIATest, ipA, "", []netLink{
		{ifID: 1, local: extA, remote: extB1, neighbor: nodeIATest},
	}, true, wpki)
	b := startNetNode(t, nodeIATest, ipB, "", []netLink{
		{ifID: 1, local: extB1, remote: extA, neighbor: coreIATest},
		{ifID: 2, local: extB2, remote: extC, neighbor: iaLineC},
	}, false, wpki)
	c := startNetNode(t, iaLineC, ipC, "", []netLink{
		{ifID: 1, local: extC, remote: extB2, neighbor: nodeIATest},
	}, false, wpki)
	ctx := context.Background()

	// Beacons propagate A→B→C with signatures verified at each hop: the
	// beacon store only ever holds verified PCBs.
	poll(t, "beacons at C", func() bool {
		return c.beaconer.store.Len() > 0
	})
	poll(t, "beacons at B", func() bool {
		return b.beaconer.store.Len() > 0
	})

	// C enrolls through the reversed beacon over B: no direct A–C link
	// exists, so the enrollment fetch rides the bootstrap route.
	poll(t, "C enrolled through B", func() bool {
		chains, err := c.trustDB.Chains(ctx, trust.ChainQuery{IA: iaLineC})
		return err == nil && len(chains) > 0
	})
	trc, err := c.trustDB.SignedTRC(ctx, cppki.TRCID{ISD: coreIATest.ISD(), Base: 1, Serial: 1})
	if err != nil {
		t.Fatal(err)
	}
	if trc.IsZero() {
		t.Fatal("C did not pin the TRC")
	}

	// C registers a down segment at A through B: A's path database holds the
	// segment to C.
	poll(t, "down segment at A", func() bool {
		segs, err := a.pathDB.Get(ctx, pathdb.Query{
			Type: pathdb.SegmentTypeDown, DstIA: iaLineC})
		return err == nil && len(segs) > 0
	})

	// The provider resolves an end-to-end path from C to A: the reversed up
	// segment [A, B, C].
	poll(t, "path from C to A", func() bool {
		path, err := c.provider.Path(ctx, coreIATest)
		return err == nil && path != nil && len(path.HopFields) == 3
	})
	path, err := c.provider.Path(ctx, coreIATest)
	if err != nil {
		t.Fatal(err)
	}
	if path.InfoFields[0].ConsDir {
		t.Error("route to the core is not reversed")
	}

	// B keeps its own up segment, and its provider reaches the core over it.
	poll(t, "B up segment", func() bool {
		segs, err := b.pathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
		return err == nil && len(segs) > 0
	})

	// The up segments C terminates carry the full line's signatures; verify
	// one end to end through C's engine.
	ups, err := c.pathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil || len(ups) == 0 {
		t.Fatalf("no up segments at C: %v", err)
	}
	for i := range ups[0].PCB.Entries {
		if _, err := c.engine.Verify(ctx,
			ups[0].PCB.Entries[i].Signed, ups[0].PCB.AssociatedData(i)...); err != nil {
			t.Fatalf("up segment entry %d does not verify: %v", i, err)
		}
	}
	if !ups[0].FirstIA().Equal(coreIATest) || !ups[0].LastIA().Equal(iaLineC) {
		t.Errorf("up segment = %v..%v, want the full line",
			ups[0].FirstIA(), ups[0].LastIA())
	}
}

// TestRestartedNodeServesUpSegments checks that a restarted node serves up
// segments from the persistent path database before the next beaconing
// period.
func TestRestartedNodeServesUpSegments(t *testing.T) {
	wpki := newTestWebPKI(t)
	// Loopback addresses of its own, so the still-running endpoints of
	// earlier tests keep their fixed ports.
	ipA := netip.MustParseAddr("127.0.0.5")
	ipB1 := netip.MustParseAddr("127.0.0.6")
	ipB2 := netip.MustParseAddr("127.0.0.7")
	dir := t.TempDir()
	extA, extB1 := freeUDPAddrOn(t, ipA), freeUDPAddrOn(t, ipB1)

	startNetNode(t, coreIATest, ipA, "", []netLink{
		{ifID: 1, local: extA, remote: extB1, neighbor: nodeIATest},
	}, true, wpki)
	b := startNetNode(t, nodeIATest, ipB1, dir, []netLink{
		{ifID: 1, local: extB1, remote: extA, neighbor: coreIATest},
	}, false, wpki)
	ctx := context.Background()

	poll(t, "B up segment", func() bool {
		segs, err := b.pathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
		return err == nil && len(segs) > 0
	})

	// Stop B's loops and release its databases; a restarted node — the same
	// state directory, a fresh underlay presence — serves the up segments
	// before the next beaconing period.
	b.cancel()
	if err := b.peerClt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.pathDB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.trustDB.Close(); err != nil {
		t.Fatal(err)
	}
	extB2 := freeUDPAddrOn(t, ipB2)
	b2 := startNetNode(t, nodeIATest, ipB2, dir, []netLink{
		{ifID: 1, local: extB2, remote: extA, neighbor: coreIATest},
	}, false, wpki)
	segs, err := b2.pathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) == 0 {
		t.Fatal("restarted node serves no up segments before the next beaconing period")
	}
	path, err := b2.provider.Path(ctx, coreIATest)
	if err != nil {
		t.Fatalf("restarted node cannot route to the core: %v", err)
	}
	if len(path.HopFields) != 2 {
		t.Errorf("route to the core = %d hops, want 2", len(path.HopFields))
	}
}
