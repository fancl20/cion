package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"hash"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto"

	"github.com/fancl20/cion/pkg/pathdb"
	pathdbbbolt "github.com/fancl20/cion/pkg/pathdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/trust/impl/bbolt"
)

// macFactory builds forwarding-key MAC hashers, as the data plane does.
func macFactory() func() hash.Hash {
	return func() hash.Hash {
		mac, _ := scrypto.InitMac([]byte(testMACKey))
		return mac
	}
}

// fakeSender records the beacon and registration RPCs the beaconer sends.
type fakeSender struct {
	mtx           sync.Mutex
	beacons       []sentBeacon
	registrations []sentRegistration
}

type sentBeacon struct {
	peer *scion.Addr
	pcb  *cppb.PathSegment
}

type sentRegistration struct {
	peer     *scion.Addr
	segments []*cppb.PathSegment
}

func (s *fakeSender) Beacon(ctx context.Context, peer *scion.Addr, pcb *cppb.PathSegment) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.beacons = append(s.beacons, sentBeacon{peer: peer, pcb: pcb})
	return nil
}

func (s *fakeSender) RegisterSegments(
	ctx context.Context, peer *scion.Addr, segments []*cppb.PathSegment) error {

	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.registrations = append(s.registrations, sentRegistration{peer: peer, segments: segments})
	return nil
}

// beaconFixture is a three-AS line — the core A, the middle B under test,
// and C below — with engines anchored in one TRC and a path database.
type beaconFixture struct {
	db       trust.DB
	pathDB   pathdb.DB
	engines  map[addr.IA]*trust.Engine
	store    *BeaconStore
	sender   *fakeSender
	beaconer *Beaconer
}

var (
	iaLineC = addr.MustIAFrom(20, 0xff0000000003)
	iaLineD = addr.MustIAFrom(20, 0xff0000000004)
)

func newBeaconFixture(t *testing.T) *beaconFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := bbolt.New(filepath.Join(dir, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() }) //nolint:errcheck
	pathDB, err := pathdbbbolt.New(filepath.Join(dir, "path.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pathDB.Close() }) //nolint:errcheck

	keys, err := trust.LoadOrCreateCoreKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	trc, err := trust.Genesis(context.Background(), db, coreIATest, keys)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := trust.NewIssuer(coreIATest, keys, trc)
	if err != nil {
		t.Fatal(err)
	}
	provider := &trust.NetworkProvider{DB: db}
	engines := make(map[addr.IA]*trust.Engine)
	for _, ia := range []addr.IA{coreIATest, nodeIATest, iaLineC} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := trust.CreateCSR(ia, key)
		if err != nil {
			t.Fatal(err)
		}
		chain, err := issuer.IssueChain(csr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.InsertChain(context.Background(), chain); err != nil {
			t.Fatal(err)
		}
		engines[ia] = trust.NewEngine(ia, key, provider)
	}

	// B's two links: interface 1 to the core A, interface 2 to C.
	links := func() map[uint16]addr.IA {
		return map[uint16]addr.IA{1: coreIATest, 2: iaLineC}
	}
	neighbors := func() map[uint16]Neighbor {
		return map[uint16]Neighbor{
			1: {IA: coreIATest, ControlAddr: netip.MustParseAddrPort("192.0.2.10:30043")},
			2: {IA: iaLineC, ControlAddr: netip.MustParseAddrPort("192.0.2.20:30043")},
		}
	}
	store := NewBeaconStore()
	sender := &fakeSender{}
	coreRoute := func() *scion.Addr {
		return &scion.Addr{IA: coreIATest, Addr: netip.MustParseAddrPort("192.0.2.10:30044")}
	}
	beaconer, err := NewBeaconer(BeaconerConfig{
		IA:        nodeIATest,
		Engine:    engines[nodeIATest],
		MACKey:    []byte(testMACKey),
		Store:     store,
		DB:        pathDB,
		Links:     links,
		Neighbors: neighbors,
		Sender:    sender,
		CoreRoute: coreRoute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &beaconFixture{
		db: db, pathDB: pathDB, engines: engines, store: store,
		sender: sender, beaconer: beaconer,
	}
}

// lineBeacon builds the beacon the core A sends to B: [A] with next B.
func lineBeacon(t *testing.T, f *beaconFixture, now time.Time) *segment.PCB {
	t.Helper()
	pcb, err := segment.NewPCB(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := pcb.AppendEntry(context.Background(), coreIATest, segment.EntryOptions{
		Next:       nodeIATest,
		EgressIfID: 1,
	}, macFactory(), f.engines[coreIATest]); err != nil {
		t.Fatal(err)
	}
	return pcb
}

// extendedBeacon builds the beacon B would forward to C: [A, B].
func extendedBeacon(t *testing.T, f *beaconFixture, now time.Time) *segment.PCB {
	t.Helper()
	pcb := lineBeacon(t, f, now)
	if err := pcb.AppendEntry(context.Background(), nodeIATest, segment.EntryOptions{
		Next:        iaLineC,
		IngressIfID: 1,
		EgressIfID:  2,
	}, macFactory(), f.engines[nodeIATest]); err != nil {
		t.Fatal(err)
	}
	return pcb
}

func TestHandleBeaconAccepts(t *testing.T) {
	f := newBeaconFixture(t)
	pcb := lineBeacon(t, f, time.Now())

	if err := f.beaconer.HandleBeacon(context.Background(), pcb, 1); err != nil {
		t.Fatalf("handle beacon: %v", err)
	}
	if got := f.store.Len(); got != 1 {
		t.Errorf("store length = %d, want 1", got)
	}
}

// TestHandleBeaconChecks covers each Section 2.3.1 reception check with its
// respective malformed beacon.
func TestHandleBeaconChecks(t *testing.T) {
	cases := map[string]struct {
		build   func(*testing.T, *beaconFixture, time.Time) *segment.PCB
		ingress uint16
	}{
		"wrong neighbor IA": {ingress: 1, build: func(t *testing.T, f *beaconFixture, now time.Time) *segment.PCB {
			// The beacon [A, B] arrives on B's link to A, but its last
			// entry names B, not the link's neighbor A.
			return extendedBeacon(t, f, now)
		}},
		"unknown interface": {ingress: 9, build: func(t *testing.T, f *beaconFixture, now time.Time) *segment.PCB {
			return lineBeacon(t, f, now)
		}},
		"expired hop": {ingress: 1, build: func(t *testing.T, f *beaconFixture, now time.Time) *segment.PCB {
			// Older than the six-hour hop validity.
			return lineBeacon(t, f, now.Add(-8*time.Hour))
		}},
		"future timestamp": {ingress: 1, build: func(t *testing.T, f *beaconFixture, now time.Time) *segment.PCB {
			return lineBeacon(t, f, now.Add(clockSkewAllowance*2))
		}},
		"broken continuity": {ingress: 1, build: func(t *testing.T, f *beaconFixture, now time.Time) *segment.PCB {
			// The core's entry promises C as the next AS, but B's entry
			// follows anyway: the entries do not chain.
			pcb, err := segment.NewPCB(now)
			if err != nil {
				t.Fatal(err)
			}
			if err := pcb.AppendEntry(context.Background(), coreIATest, segment.EntryOptions{
				Next: iaLineC, EgressIfID: 1,
			}, macFactory(), f.engines[coreIATest]); err != nil {
				t.Fatal(err)
			}
			if err := pcb.AppendEntry(context.Background(), nodeIATest, segment.EntryOptions{
				Next: iaLineC, IngressIfID: 1, EgressIfID: 2,
			}, macFactory(), f.engines[nodeIATest]); err != nil {
				t.Fatal(err)
			}
			return pcb
		}},
		"bad signature": {ingress: 1, build: func(t *testing.T, f *beaconFixture, now time.Time) *segment.PCB {
			pcb := lineBeacon(t, f, now)
			// Tamper with the signature; the parsed entry shares the wire
			// message's signed component.
			pcb.Entries[0].Signed.Signature[0] ^= 0xff
			return pcb
		}},
		"own IA on segment": {ingress: 1, build: func(t *testing.T, f *beaconFixture, now time.Time) *segment.PCB {
			pcb := lineBeacon(t, f, now)
			if err := pcb.AppendEntry(context.Background(), nodeIATest, segment.EntryOptions{
				Next: iaLineC, IngressIfID: 1, EgressIfID: 2,
			}, macFactory(), f.engines[nodeIATest]); err != nil {
				t.Fatal(err)
			}
			return pcb
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBeaconFixture(t)
			pcb := tc.build(t, f, time.Now())
			// Re-parse so checks see the wire form of the mutations.
			reparsed, err := segment.ParsePCB(pcb.PB)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.beaconer.HandleBeacon(context.Background(), reparsed, tc.ingress); err == nil {
				t.Error("malformed beacon accepted")
			}
			if got := f.store.Len(); got != 0 {
				t.Errorf("store length = %d, want 0", got)
			}
		})
	}
}

// TestHandleBeaconWithoutTRC checks the bootstrapping subtlety: a node that
// has not pinned the TRC records the beacon as its enrollment route but
// never stores it.
func TestHandleBeaconWithoutTRC(t *testing.T) {
	f := newBeaconFixture(t)
	ctx := context.Background()

	// A fresh node's engine: no TRC pinned, no chains.
	freshDB, err := bbolt.New(filepath.Join(t.TempDir(), "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer freshDB.Close() //nolint:errcheck
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fresh := trust.NewEngine(nodeIATest, key, &trust.NetworkProvider{DB: freshDB})
	beaconer, err := NewBeaconer(BeaconerConfig{
		IA:     nodeIATest,
		Engine: fresh,
		MACKey: []byte(testMACKey),
		Store:  f.store,
		DB:     f.pathDB,
		Links:  func() map[uint16]addr.IA { return map[uint16]addr.IA{1: coreIATest} },
	})
	if err != nil {
		t.Fatal(err)
	}

	pcb := lineBeacon(t, f, time.Now())
	if err := beaconer.HandleBeacon(ctx, pcb, 1); err != nil {
		t.Fatalf("unverified beacon rejected outright: %v", err)
	}
	if got := f.store.Len(); got != 0 {
		t.Errorf("store length = %d, want 0 (never stored unverified)", got)
	}
	route := beaconer.BootstrapRoute(coreIATest)
	if route == nil {
		t.Fatal("bootstrap route not recorded")
	}
	// The route is the reversed [A] beacon extended with the node's own hop:
	// two hops, against the construction direction.
	if route.InfoFields[0].ConsDir || len(route.HopFields) != 2 {
		t.Fatalf("bootstrap route = %d hops (consDir %v), want 2 reversed",
			len(route.HopFields), route.InfoFields[0].ConsDir)
	}
	// The route serves only its originating core.
	if beaconer.BootstrapRoute(iaLineC) != nil {
		t.Error("bootstrap route served a destination it does not originate from")
	}
	// The node's own hop leads, so its router can verify and forward it.
	if route.HopFields[0].ExpTime != segment.HopExpTime {
		t.Error("bootstrap route does not start with the node's own hop")
	}
}

// TestPropagateOnce checks ADR-0004's propagation rule: every external
// interface except the one the beacon arrived on, and except interfaces
// whose neighbor the TRC names as a core.
func TestPropagateOnce(t *testing.T) {
	f := newBeaconFixture(t)
	ctx := context.Background()

	pcb := lineBeacon(t, f, time.Now())
	if err := f.beaconer.HandleBeacon(ctx, pcb, 1); err != nil {
		t.Fatal(err)
	}
	f.beaconer.propagateOnce(ctx)

	f.sender.mtx.Lock()
	defer f.sender.mtx.Unlock()
	if len(f.sender.beacons) != 1 {
		t.Fatalf("sent beacons = %d, want 1 (skipping ingress and core links)", len(f.sender.beacons))
	}
	sent := f.sender.beacons[0]
	if !sent.peer.IA.Equal(iaLineC) {
		t.Errorf("beacon sent to %v, want %v", sent.peer.IA, iaLineC)
	}
	if sent.peer.Addr.Port() != EndpointPort {
		t.Errorf("beacon sent to port %d, want %d", sent.peer.Addr.Port(), EndpointPort)
	}
	parsed, err := segment.ParsePCB(sent.pcb)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Entries) != 2 {
		t.Fatalf("propagated entries = %d, want 2", len(parsed.Entries))
	}
	if !parsed.LastIA().Equal(nodeIATest) {
		t.Errorf("last entry = %v, want the propagating node", parsed.LastIA())
	}
	if parsed.Entries[0].Hop.ConsEgress != 1 || parsed.Entries[1].Hop.ConsIngress != 1 {
		t.Error("hop fields do not record the traversal interfaces")
	}
	if parsed.Entries[1].Hop.ConsEgress != 2 {
		t.Errorf("egress = %d, want 2", parsed.Entries[1].Hop.ConsEgress)
	}
	// The extended beacon must verify.
	for i := range parsed.Entries {
		if _, err := f.engines[iaLineC].Verify(ctx,
			parsed.Entries[i].Signed, parsed.AssociatedData(i)...); err != nil {
			t.Fatalf("propagated entry %d does not verify: %v", i, err)
		}
	}
}

// TestRegisterOnce checks termination per Section 3.1.1 and registration per
// Sections 3.1.2 and 3.1.3: the up segment lands in the local path database,
// the down segment at the core.
func TestRegisterOnce(t *testing.T) {
	f := newBeaconFixture(t)
	ctx := context.Background()

	pcb := lineBeacon(t, f, time.Now())
	if err := f.beaconer.HandleBeacon(ctx, pcb, 1); err != nil {
		t.Fatal(err)
	}
	f.beaconer.registerOnce(ctx)

	ups, err := f.pathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 1 {
		t.Fatalf("up segments = %d, want 1", len(ups))
	}
	up := ups[0]
	if !up.FirstIA().Equal(coreIATest) || !up.LastIA().Equal(nodeIATest) {
		t.Errorf("up segment = %v..%v, want %v..%v",
			up.FirstIA(), up.LastIA(), coreIATest, nodeIATest)
	}
	last := up.PCB.Entries[len(up.PCB.Entries)-1]
	if !last.Next.IsZero() || last.Hop.ConsEgress != 0 {
		t.Error("up segment's terminating entry sets next AS or egress")
	}

	f.sender.mtx.Lock()
	defer f.sender.mtx.Unlock()
	if len(f.sender.registrations) != 1 {
		t.Fatalf("registrations = %d, want 1", len(f.sender.registrations))
	}
	reg := f.sender.registrations[0]
	if !reg.peer.IA.Equal(coreIATest) {
		t.Errorf("registered with %v, want the core", reg.peer.IA)
	}
	if len(reg.segments) != 1 {
		t.Fatalf("registered segments = %d, want 1", len(reg.segments))
	}
}

// TestHandleRegistration checks the receiving core's checks (Section 3.1.3).
func TestHandleRegistration(t *testing.T) {
	f := newBeaconFixture(t)
	ctx := context.Background()

	// A down segment registered by B: the [A] beacon it received,
	// terminated by B's final entry.
	terminated := lineBeacon(t, f, time.Now())
	if err := terminated.AppendEntry(ctx, nodeIATest, segment.EntryOptions{
		IngressIfID: 1,
	}, macFactory(), f.engines[nodeIATest]); err != nil {
		t.Fatal(err)
	}

	// The core under test.
	coreBeaconer, err := NewBeaconer(BeaconerConfig{
		IA:     coreIATest,
		Engine: f.engines[coreIATest],
		MACKey: []byte(testMACKey),
		Store:  NewBeaconStore(),
		DB:     f.pathDB,
		Links:  func() map[uint16]addr.IA { return map[uint16]addr.IA{1: nodeIATest} },
		Core:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := coreBeaconer.HandleRegistration(ctx, terminated.PB); err != nil {
		t.Fatalf("handle registration: %v", err)
	}
	downs, err := f.pathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeDown, DstIA: nodeIATest})
	if err != nil {
		t.Fatal(err)
	}
	if len(downs) != 1 {
		t.Fatalf("down segments = %d, want 1", len(downs))
	}

	// A segment not originating at this core is rejected: [B, C] signed by
	// B and C, with B — not a core — first.
	foreign, err := segment.NewPCB(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := foreign.AppendEntry(ctx, nodeIATest, segment.EntryOptions{
		Next: iaLineC, EgressIfID: 1,
	}, macFactory(), f.engines[nodeIATest]); err != nil {
		t.Fatal(err)
	}
	if err := foreign.AppendEntry(ctx, iaLineC, segment.EntryOptions{
		IngressIfID: 1,
	}, macFactory(), f.engines[iaLineC]); err != nil {
		t.Fatal(err)
	}
	if err := coreBeaconer.HandleRegistration(ctx, foreign.PB); err == nil {
		t.Error("registration of a foreign-origin segment accepted")
	}
}

// TestBeaconerPausesOnDownInterface checks the verdict's read: a down
// interface originates and propagates nothing — the endpoint is identity
// the map serves however stale, and the monitor's verdict is the pause.
func TestBeaconerPausesOnDownInterface(t *testing.T) {
	f := newBeaconFixture(t)
	ctx := context.Background()

	// Interface 2 — toward C — is verdict-down.
	f.beaconer.verdicts = func() map[uint16]bool {
		return map[uint16]bool{1: true, 2: false}
	}

	pcb := lineBeacon(t, f, time.Now())
	if err := f.beaconer.HandleBeacon(ctx, pcb, 1); err != nil {
		t.Fatal(err)
	}
	f.beaconer.propagateOnce(ctx)
	f.sender.mtx.Lock()
	sent := len(f.sender.beacons)
	f.sender.mtx.Unlock()
	if sent != 0 {
		t.Fatalf("propagated %d beacons over a down interface, want 0", sent)
	}

	// The core's origination pauses the same way.
	core, err := NewBeaconer(BeaconerConfig{
		IA:        coreIATest,
		Engine:    f.engines[coreIATest],
		MACKey:    []byte(testMACKey),
		Store:     NewBeaconStore(),
		DB:        f.pathDB,
		Links:     func() map[uint16]addr.IA { return map[uint16]addr.IA{1: nodeIATest} },
		Neighbors: func() map[uint16]Neighbor { return map[uint16]Neighbor{} },
		Verdicts:  func() map[uint16]bool { return map[uint16]bool{1: false} },
		Sender:    f.sender,
		CoreRoute: func() *scion.Addr { return nil },
		Core:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	core.originateOnce(ctx)
	f.sender.mtx.Lock()
	sent = len(f.sender.beacons)
	f.sender.mtx.Unlock()
	if sent != 0 {
		t.Fatalf("originated %d beacons on a down interface, want 0", sent)
	}

	// The verdict's up edge resumes: a missing verdict — no session —
	// treats the link as up, as a node restarts with every link up.
	f.beaconer.verdicts = func() map[uint16]bool { return map[uint16]bool{} }
	f.beaconer.propagateOnce(ctx)
	f.sender.mtx.Lock()
	sent = len(f.sender.beacons)
	f.sender.mtx.Unlock()
	if sent != 1 {
		t.Fatalf("propagated %d beacons after the up edge, want 1", sent)
	}
}
