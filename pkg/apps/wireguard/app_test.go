package wireguard

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// recordingDirectory records publications and serves a directory it holds.
type recordingDirectory struct {
	published chan Entry
	entries   []Entry
}

func (d *recordingDirectory) Publish(ctx context.Context, entry Entry) error {
	select {
	case d.published <- entry:
	default:
	}
	return nil
}

func (d *recordingDirectory) List(context.Context) ([]Entry, error) {
	return d.entries, nil
}

// flippableTrustDB serves no chains until it serves one; the publish loop
// reads it while the test flips it.
type flippableTrustDB struct {
	mtx   sync.Mutex
	chain [][]*x509.Certificate
}

func (d *flippableTrustDB) Chains(context.Context, trust.ChainQuery) ([][]*x509.Certificate, error) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	return d.chain, nil
}

// enroll produces the node's chain.
func (d *flippableTrustDB) enroll(chain []*x509.Certificate) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	d.chain = [][]*x509.Certificate{chain}
}
func (d *flippableTrustDB) InsertChain(context.Context, []*x509.Certificate) (bool, error) {
	return false, nil
}
func (d *flippableTrustDB) SignedTRC(context.Context, cppki.TRCID) (cppki.SignedTRC, error) {
	return cppki.SignedTRC{}, nil
}
func (d *flippableTrustDB) InsertTRC(context.Context, cppki.SignedTRC) (bool, error) {
	return false, nil
}
func (d *flippableTrustDB) Close() error { return nil }

// recordingRegs records the service registrations the application makes.
type recordingRegs struct {
	mtx  sync.Mutex
	live map[addr.SVC]uint16
}

func (r *recordingRegs) register(svc addr.SVC, port uint16) error {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	if r.live == nil {
		r.live = make(map[addr.SVC]uint16)
	}
	r.live[svc] = port
	return nil
}

func (r *recordingRegs) unregister(svc addr.SVC, port uint16) error {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	if r.live[svc] == port {
		delete(r.live, svc)
	}
	return nil
}

func (r *recordingRegs) registered(svc addr.SVC) (uint16, bool) {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	port, ok := r.live[svc]
	return port, ok
}

// newTestWireguard assembles an application around throwaway sockets: a SCION conn
// submitting to a sink, the shared host port on an ephemeral one, and the
// core's store-side directory.
func newTestWireguard(
	t *testing.T, ia addr.IA, exits []addr.IA, peers []HostPeer, db *flippableTrustDB,
) (*App, *recordingDirectory) {
	t.Helper()
	internal, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = internal.Close() })
	// Reserve an ephemeral host port, then release it for the application
	// to bind — the port only needs to be free at construction.
	hostPort, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	listenPort := uint16(hostPort.LocalAddr().(*net.UDPAddr).Port)
	_ = hostPort.Close()
	provider := &scion.PathProvider{IA: ia, DB: &memDB{}}
	directory := &recordingDirectory{published: make(chan Entry, 16)}
	regs := &recordingRegs{}
	a, err := New(Config{
		IA:         ia,
		Subnet:     netip.MustParsePrefix("10.64.1.0/24"),
		ListenHost: netip.MustParseAddr("127.0.0.1"),
		ListenPort: listenPort,
		Exits:      exits,
		Peers:      peers,
		StateDir:   t.TempDir(),
		Provider:   provider,
		Engine:     trust.NewEngine(ia, nil, &trust.NetworkProvider{DB: db}),
		Store:      directory,
		NewConn: func() (*scion.Conn, error) {
			return scion.NewConn(scion.ConnConfig{
				IA:           ia,
				Bind:         "127.0.0.1:0",
				InternalAddr: internal.LocalAddr().String(),
				MACKey:       testMACKey,
				Links:        func() map[uint16]addr.IA { return map[uint16]addr.IA{1: addr.MustIAFrom(20, 2)} },
			})
		},
		RegisterSvc:     regs.register,
		UnregisterSvc:   regs.unregister,
		PublishInterval: time.Hour,
		PublishRetry:    20 * time.Millisecond,
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The deregistration check registers before Close so it runs after it.
	t.Cleanup(func() {
		if port, ok := regs.registered(SvcWireguard); ok {
			t.Errorf("the mesh service registration for port %d outlived Close", port)
		}
		if port, ok := regs.registered(SvcDirectory); ok {
			t.Errorf("the directory service registration for port %d outlived Close", port)
		}
	})
	t.Cleanup(a.Close)
	if _, ok := regs.registered(SvcWireguard); !ok {
		t.Error("the mesh socket was not registered under the wireguard service")
	}
	if _, ok := regs.registered(SvcDirectory); !ok {
		t.Error("the core's directory socket was not registered under the directory service")
	}
	return a, directory
}

// TestWireguardPublishesOnceEnrolled checks the publication cadence: the loop
// retries while enrollment has produced no chain, and publishes once one
// exists.
func TestWireguardPublishesOnceEnrolled(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000211)
	db := &flippableTrustDB{}
	a, directory := newTestWireguard(t, ia, nil, nil, db)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.runPublish(ctx)

	select {
	case <-directory.published:
		t.Fatal("published without a certificate chain")
	case <-time.After(100 * time.Millisecond):
	}

	// Enrollment produces the node's chain; the retrying loop publishes.
	db.enroll([]*x509.Certificate{iaSubjectCert(t, ia)})
	select {
	case entry := <-directory.published:
		if !entry.IA.Equal(ia) {
			t.Errorf("published entry for %s, want %s", entry.IA, ia)
		}
		if entry.Overlay.String() != "10.64.1.0/24" {
			t.Errorf("published subnet %s, want 10.64.1.0/24", entry.Overlay)
		}
		if entry.PublicKey == (PublicKey{}) {
			t.Error("published no public key")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publication never happened after enrollment")
	}
}

// TestWireguardAppliesDirectoryDiff checks the mesh device lifecycle: new peers
// gain a device, departed peers lose theirs and their router entries.
func TestWireguardAppliesDirectoryDiff(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000221)
	peer1 := addr.MustIAFrom(20, 0xff0000000231)
	peer2 := addr.MustIAFrom(20, 0xff0000000232)
	a, _ := newTestWireguard(t, ia, nil, nil, &flippableTrustDB{})

	entry := func(peer addr.IA, subnet string) Entry {
		return Entry{
			IA:        peer,
			PublicKey: mustPubKey(byte(peer.AS())),
			Overlay:   netip.MustParsePrefix(subnet),
		}
	}
	e1 := entry(peer1, "10.64.11.0/24")
	e2 := entry(peer2, "10.64.12.0/24")

	a.applyDirectory([]Entry{e1})
	if len(a.meshPeers) != 1 || a.meshPeers[peer1] == nil {
		t.Fatalf("peers after the first directory = %v, want %s", a.meshPeers, peer1)
	}
	a.applyDirectory([]Entry{e1, e2})
	if len(a.meshPeers) != 2 {
		t.Fatalf("peers after the second directory = %d, want 2", len(a.meshPeers))
	}
	a.applyDirectory([]Entry{e2})
	if len(a.meshPeers) != 1 || a.meshPeers[peer2] == nil {
		t.Fatalf("departed peer kept its device: %v", a.meshPeers)
	}

	// The router table follows: the surviving peer's subnet routes to its
	// device, and the departed peer's entries are gone. (Packet delivery
	// itself the router tests cover; a live device's reader would consume
	// anything routed here before a test could observe it.)
	if len(a.router.nets) != 1 {
		t.Fatalf("router holds %d mesh routes, want 1", len(a.router.nets))
	}
	if got := a.router.nets[0].prefix; got.String() != e2.Overlay.String() {
		t.Errorf("mesh route = %s, want the survivor's %s", got, e2.Overlay)
	}
	if a.router.nets[0].dst != a.meshPeers[peer2].pipe {
		t.Error("the mesh route does not point at the survivor's device")
	}
}

// TestWireguardValidatesConfig checks the configuration the node assembly
// feeds: peer addresses inside the subnet, exits configured, one exit per
// key.
func TestWireguardValidatesConfig(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000241)
	exit := addr.MustIAFrom(20, 0xff0000000242)
	other := addr.MustIAFrom(20, 0xff0000000243)
	internal, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	t.Cleanup(func() { _ = internal.Close() })
	base := Config{
		IA:         ia,
		Subnet:     netip.MustParsePrefix("10.64.1.0/24"),
		ListenHost: netip.MustParseAddr("127.0.0.1"),
		ListenPort: 51820,
		Exits:      []addr.IA{exit},
		Peers: []HostPeer{{
			PublicKey: mustPubKey(1),
			Addr:      netip.MustParseAddr("10.64.1.10"),
			Exit:      exit,
		}},
		StateDir: t.TempDir(),
		Provider: &scion.PathProvider{IA: ia},
		Engine:   trust.NewEngine(ia, nil, nil),
		Store:    &fakeStore{},
		NewConn: func() (*scion.Conn, error) {
			return scion.NewConn(scion.ConnConfig{
				IA:           ia,
				Bind:         "127.0.0.1:0",
				InternalAddr: internal.LocalAddr().String(),
				MACKey:       testMACKey,
				Links:        func() map[uint16]addr.IA { return map[uint16]addr.IA{1: addr.MustIAFrom(20, 2)} },
			})
		},
		RegisterSvc:   func(addr.SVC, uint16) error { return nil },
		UnregisterSvc: func(addr.SVC, uint16) error { return nil },
	}

	if _, err := New(base); err != nil {
		t.Fatalf("a valid configuration was rejected: %v", err)
	}

	outside := base
	outside.Peers = []HostPeer{{
		PublicKey: mustPubKey(2),
		Addr:      netip.MustParseAddr("10.65.9.9"),
		Exit:      exit,
	}}
	if _, err := New(outside); err == nil {
		t.Error("a peer outside the subnet was accepted")
	}

	unconfigured := base
	unconfigured.Peers = []HostPeer{{
		PublicKey: mustPubKey(3),
		Addr:      netip.MustParseAddr("10.64.1.11"),
		Exit:      other,
	}}
	if _, err := New(unconfigured); err == nil {
		t.Error("a peer with an unconfigured exit was accepted")
	}

	duplicate := base
	duplicate.Peers = append(duplicate.Peers, HostPeer{
		PublicKey: mustPubKey(1),
		Addr:      netip.MustParseAddr("10.64.1.12"),
		Exit:      exit,
	})
	if _, err := New(duplicate); err == nil {
		t.Error("the same host key under two peers was accepted")
	}

	noDirectory := base
	noDirectory.Store = nil
	if _, err := New(noDirectory); err == nil {
		t.Error("an application with neither store nor core route was accepted")
	}

	noRegistration := base
	noRegistration.RegisterSvc = nil
	if _, err := New(noRegistration); err == nil {
		t.Error("an application with no service registration was accepted")
	}
}

func (d *recordingDirectory) Close() error { return nil }
