package wireguard

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// recordingDirectory records publications and serves a directory it holds,
// assigning slices the store's way — first free /24 by address order, kept
// per ISD-AS — with answer as the override the bad-assignment test sets.
type recordingDirectory struct {
	published chan Entry
	entries   []Entry
	answer    netip.Prefix
}

func (d *recordingDirectory) Publish(_ context.Context, entry Entry) (Entry, error) {
	subnet, err := AssignSlice(entry.IA, d.entries)
	if err != nil {
		return Entry{}, err
	}
	if d.answer.IsValid() {
		subnet = d.answer
	}
	claim := entry
	entry.Overlay = subnet
	for i := range d.entries {
		if d.entries[i].IA.Equal(entry.IA) {
			d.entries[i] = entry
			d.record(claim)
			return entry, nil
		}
	}
	d.entries = append(d.entries, entry)
	d.record(claim)
	return entry, nil
}

// record hands the published claim — no slice in it — to the test.
func (d *recordingDirectory) record(entry Entry) {
	select {
	case d.published <- entry:
	default:
	}
}

func (d *recordingDirectory) PublishHost(context.Context, HostEntry) error {
	return nil
}

func (d *recordingDirectory) List(context.Context) (Directory, error) {
	return Directory{Nodes: d.entries}, nil
}

func (d *recordingDirectory) Close() error { return nil }

// stallingDirectory holds every publication until released — a
// publication in flight when the stop comes — signals the first one's
// arrival, and records its close.
type stallingDirectory struct {
	recordingDirectory
	arrived chan struct{}
	arrive  sync.Once
	release chan struct{}
	closed  atomic.Bool
}

func (d *stallingDirectory) Publish(ctx context.Context, entry Entry) (Entry, error) {
	d.arrive.Do(func() { close(d.arrived) })
	<-d.release
	return d.recordingDirectory.Publish(ctx, entry)
}

func (d *stallingDirectory) Close() error {
	d.closed.Store(true)
	return nil
}

// flippableTrustDB serves no chains until it serves one; the publish loop
// reads it while the test flips it.
type flippableTrustDB struct {
	mtx   sync.Mutex
	chain [][]*x509.Certificate
}

func (d *flippableTrustDB) Chains(context.Context, trustdb.ChainQuery) ([][]*x509.Certificate, error) {
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
func (d *flippableTrustDB) DeleteExpiredChains(context.Context, time.Time) (int, error) {
	return 0, nil
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

// testHost is a loopback host no other package's tests bind, for the host
// ports the episodes reserve: go test runs the packages in parallel, and on
// a shared host a released reservation could be taken before New binds it.
var testHost = netip.MustParseAddr("127.0.0.128")

// freeHostPort returns a port on testHost picked by the kernel and released
// for New to bind as the shared host port.
func freeHostPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(testHost, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// newTestWireguard assembles an application around throwaway sockets: a SCION conn
// submitting to a sink, the shared host port on an ephemeral one, and the
// core's store-side directory. The mutations edit the configuration before
// the assembly.
func newTestWireguard(
	t *testing.T, ia addr.IA, db *flippableTrustDB, mutate ...func(*Config),
) (*App, *recordingDirectory) {
	t.Helper()
	internal, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = internal.Close() })
	provider := &scion.PathProvider{IA: ia, DB: &memDB{}}
	directory := &recordingDirectory{published: make(chan Entry, 16)}
	regs := &recordingRegs{}
	cfg := Config{
		IA:         ia,
		ListenHost: testHost,
		ListenPort: freeHostPort(t),
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
	}
	for _, m := range mutate {
		m(&cfg)
	}
	a, err := New(cfg)
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
	if _, ok := regs.registered(SvcDirectory); cfg.Store != nil && !ok {
		t.Error("the core's directory socket was not registered under the directory service")
	}
	return a, directory
}

// TestWireguardPublishesOnceEnrolled checks the publication cadence: the loop
// retries while enrollment has produced no chain, publishes once one exists
// — claiming no slice — and holds the answered assignment as the node's.
func TestWireguardPublishesOnceEnrolled(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000211)
	db := &flippableTrustDB{}
	a, directory := newTestWireguard(t, ia, db)

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
		if entry.Overlay.IsValid() {
			t.Errorf("the publication claimed the slice %s, want none", entry.Overlay)
		}
		if entry.PublicKey == (PublicKey{}) {
			t.Error("published no public key")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publication never happened after enrollment")
	}
	// The answer is the node's slice, and every wait returns it.
	answer, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	subnet, err := a.Subnet(answer)
	if err != nil {
		t.Fatalf("the assignment never arrived: %v", err)
	}
	if want := "100.64.0.0/24"; subnet.String() != want {
		t.Errorf("assigned slice = %s, want the first free %s", subnet, want)
	}
}

// TestWireguardRefusesBadAssignment checks the answer's fail-fast check: an
// assignment that is not a /24 of the tailnet range never becomes the node's
// slice — the publication retries instead, the core's bug surfacing at the
// seam nearest it.
func TestWireguardRefusesBadAssignment(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000212)
	db := &flippableTrustDB{}
	a, directory := newTestWireguard(t, ia, db)
	directory.answer = netip.MustParsePrefix("10.0.0.0/24")
	db.enroll([]*x509.Certificate{iaSubjectCert(t, ia)})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.runPublish(ctx)

	wait, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := a.Subnet(wait); err == nil {
		t.Error("an assignment outside the tailnet range became the node's slice")
	}
}

// TestWireguardAppliesDirectoryDiff checks the mesh device lifecycle: new peers
// gain a device, departed peers lose theirs and their router entries.
func TestWireguardAppliesDirectoryDiff(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000221)
	peer1 := addr.MustIAFrom(20, 0xff0000000231)
	peer2 := addr.MustIAFrom(20, 0xff0000000232)
	a, _ := newTestWireguard(t, ia, &flippableTrustDB{})

	entry := func(peer addr.IA, subnet string) Entry {
		return Entry{
			IA:        peer,
			PublicKey: mustPubKey(byte(peer.AS())),
			Overlay:   netip.MustParsePrefix(subnet),
		}
	}
	e1 := entry(peer1, "100.64.11.0/24")
	e2 := entry(peer2, "100.64.12.0/24")

	a.applyDirectory(t.Context(), Directory{Nodes: []Entry{e1}})
	if len(a.meshPeers) != 1 || a.meshPeers[peer1] == nil {
		t.Fatalf("peers after the first directory = %v, want %s", a.meshPeers, peer1)
	}
	a.applyDirectory(t.Context(), Directory{Nodes: []Entry{e1, e2}})
	if len(a.meshPeers) != 2 {
		t.Fatalf("peers after the second directory = %d, want 2", len(a.meshPeers))
	}
	a.applyDirectory(t.Context(), Directory{Nodes: []Entry{e2}})
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

// TestWireguardAppliesHostEntries checks the host device's diff (proposal
// 0022): an owned entry's key gains its /32 on the one host device, a
// departed key loses it, and a foreign-owned key changes nothing — exactly
// as the mesh diff treats the node's own entry.
func TestWireguardAppliesHostEntries(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000221)
	other := addr.MustIAFrom(20, 0xff0000000233)
	a, _ := newTestWireguard(t, ia, &flippableTrustDB{})

	owned := func(key byte, addr string) HostEntry {
		return HostEntry{
			PublicKey: mustPubKey(key),
			Addr:      netip.MustParseAddr(addr),
			IA:        ia,
		}
	}
	foreign := HostEntry{
		PublicKey: mustPubKey(0x99),
		Addr:      netip.MustParseAddr("100.64.33.7"),
		IA:        other,
	}

	// A foreign-owned entry changes nothing.
	a.applyDirectory(t.Context(), Directory{Hosts: []HostEntry{foreign}})
	if len(a.hostPeers) != 0 {
		t.Fatalf("a foreign host programmed the device: %v", a.hostPeers)
	}

	// An owned entry gains its /32; the router table follows.
	h1 := owned(1, "100.64.1.2")
	a.applyDirectory(t.Context(), Directory{Hosts: []HostEntry{h1, foreign}})
	if len(a.hostPeers) != 1 || a.hostPeers[h1.PublicKey].Addr != h1.Addr {
		t.Fatalf("owned hosts after the first directory = %v, want the one", a.hostPeers)
	}
	if len(a.router.hosts) != 1 || a.router.hosts[h1.Addr] != a.hosts.pipe {
		t.Fatalf("router hosts = %v, want the one to the host device", a.router.hosts)
	}

	// A second owned key joins; the first departs with the second fetch.
	h2 := owned(2, "100.64.1.3")
	a.applyDirectory(t.Context(), Directory{Hosts: []HostEntry{h1, h2}})
	if len(a.hostPeers) != 2 {
		t.Fatalf("owned hosts after the second directory = %d, want 2", len(a.hostPeers))
	}
	a.applyDirectory(t.Context(), Directory{Hosts: []HostEntry{h2}})
	if len(a.hostPeers) != 1 || a.hostPeers[h2.PublicKey].Addr != h2.Addr {
		t.Fatalf("the departed host kept its peer: %v", a.hostPeers)
	}
	if len(a.router.hosts) != 1 {
		t.Fatalf("router holds %d host routes after the departure, want 1",
			len(a.router.hosts))
	}
	// The snapshot the application exposes matches.
	if snap := a.HostPeers(); len(snap) != 1 || snap[0] != h2 {
		t.Fatalf("the host snapshot = %v, want the survivor", snap)
	}
}

// TestWireguardRunJoinsItsLoops checks the stop: once its context is
// canceled, Run returns only after its loops have — a publication in flight
// held to its end, a mesh peer's drain, the relay presence blocked in Recv
// against a relay that sends nothing, the sockets' readers, the directory
// service — and it releases nothing New bound but the directory socket its
// service closed. Close then releases the rest: the store, and the host
// port, which binds again at once.
func TestWireguardRunJoinsItsLoops(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000251)
	db := &flippableTrustDB{}
	db.enroll([]*x509.Certificate{iaSubjectCert(t, ia)})
	store := &stallingDirectory{arrived: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(store.release) })
	relay := newSilentRelay(t)
	a, _ := newTestWireguard(t, ia, db, func(cfg *Config) {
		cfg.Store = store
		cfg.DERP = relay
	})
	t.Cleanup(release)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	returned := make(chan error, 1)
	go func() { returned <- a.Run(ctx) }()

	// A sync pass's diff raises the peer's device and its drain.
	a.applyDirectory(ctx, Directory{Nodes: []Entry{{
		IA:        addr.MustIAFrom(20, 0xff0000000252),
		PublicKey: mustPubKey(0x52),
		Overlay:   netip.MustParsePrefix("100.64.52.0/24"),
	}}})
	if len(a.MeshPeers()) != 1 {
		t.Fatal("the peer's mesh device did not come up")
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	bound := time.After(10 * time.Second)
	for !relayConnected(a.bridge) {
		select {
		case <-tick.C:
		case <-bound:
			t.Fatal("the relay presence never connected")
		}
	}
	select {
	case <-store.arrived:
	case <-bound:
		t.Fatal("no publication reached the store")
	}

	cancel()
	select {
	case <-returned:
		t.Fatal("Run returned while a publication was in flight")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	select {
	case err := <-returned:
		if err != nil {
			t.Errorf("Run = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return once its loops could")
	}
	if relayConnected(a.bridge) {
		t.Error("the relay presence held its connection after Run returned")
	}
	for name, done := range map[string]chan struct{}{
		"mesh": a.mesh.done, "host": a.host.done,
	} {
		select {
		case <-done:
		default:
			t.Errorf("the %s socket's reader outlived Run", name)
		}
	}
	assertReadsClosed(t, "the directory socket after Run", a.dirServe)
	hostAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(testHost, a.HostPort()))
	if held, err := net.ListenUDP("udp", hostAddr); err == nil {
		_ = held.Close()
		t.Error("Run released the host port New bound")
	}
	if store.closed.Load() {
		t.Error("Run closed the store its borrower serves from")
	}

	a.Close()
	held, err := net.ListenUDP("udp", hostAddr)
	if err != nil {
		t.Fatalf("binding the host port after Close: %v", err)
	}
	_ = held.Close()
	if !store.closed.Load() {
		t.Error("Close left the store open")
	}
}

// TestWireguardClosesTheDirectoryClientConn checks every other node's
// directory client: Close closes the SCION conn beneath its transport, Run
// or no Run.
func TestWireguardClosesTheDirectoryClientConn(t *testing.T) {
	a, _ := newTestWireguard(t, addr.MustIAFrom(20, 0xff0000000253),
		&flippableTrustDB{}, func(cfg *Config) {
			cfg.Store = nil
			cfg.CoreRoute = func() *scion.Addr { return nil }
		})
	a.Close()
	assertReadsClosed(t, "the directory client's conn after Close", a.dirConn.conn)
}

// assertReadsClosed checks that a read on the conn reports it closed; the
// read deadline set first turns an open conn's wait into a timeout.
func assertReadsClosed(t *testing.T, what string, conn *scion.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now())
	if _, _, err := conn.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a read on %s = %v, want net.ErrClosed", what, err)
	}
}

// TestWireguardValidatesAssignment checks the answer's fail-fast grammar:
// only a /24 the tailnet range contains becomes the node's slice.
func TestWireguardValidatesAssignment(t *testing.T) {
	if err := validateAssignment(netip.MustParsePrefix("100.64.1.0/24")); err != nil {
		t.Fatalf("a /24 of the tailnet range was refused: %v", err)
	}
	for _, bad := range []netip.Prefix{
		{},
		netip.MustParsePrefix("10.64.1.0/24"),
		netip.MustParsePrefix("100.64.0.0/16"),
		netip.MustParsePrefix("2001:db8::/64"),
	} {
		if err := validateAssignment(bad); err == nil {
			t.Errorf("the assignment %s was accepted", bad)
		}
	}
}
