package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"hash"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto"

	"github.com/fancl20/cion/pkg/modules/pathdb"
	pathdbbbolt "github.com/fancl20/cion/pkg/modules/pathdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
	"github.com/fancl20/cion/pkg/trust"
)

// macFactory builds forwarding-key MAC hashers, as the data plane does.
func macFactory() func() hash.Hash {
	return func() hash.Hash {
		mac, _ := scrypto.InitMac([]byte(testMACKey))
		return mac
	}
}

// fakeSender records the beacon and registration RPCs the beaconer sends; a
// peer in failFor answers with a dial's failure.
type fakeSender struct {
	mtx           sync.Mutex
	beacons       []sentBeacon
	registrations []sentRegistration
	failFor       map[addr.IA]error
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
	if err := s.failFor[peer.IA]; err != nil {
		return err
	}
	s.registrations = append(s.registrations, sentRegistration{peer: peer, segments: segments})
	return nil
}

// beaconFixture is a three-AS line — the core A, the middle B under test,
// and C below — with engines anchored in one TRC and a path database.
type beaconFixture struct {
	db       trustdb.DB
	pathDB   pathdb.DB
	engines  map[addr.IA]*trust.Engine
	store    *BeaconStore
	sender   *fakeSender
	beaconer *Beaconer
}

var (
	iaLineC = addr.MustIAFrom(20, 0xff0000000003)
	iaLineD = addr.MustIAFrom(20, 0xff0000000004)
	// iaCore2Test is the fellow core the fixture's genesis TRC names beside
	// the founder: the second origin whose beacons the store keys apart.
	iaCore2Test = addr.MustIAFrom(20, 0xff0000000005)
)

func newBeaconFixture(t *testing.T) *beaconFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := bbolt.New(filepath.Join(dir, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	pathDB, err := pathdbbbolt.New(filepath.Join(dir, "path.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pathDB.Close() })

	keys, err := trust.LoadOrCreateCoreKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	trc, err := trust.Genesis(context.Background(), db, coreIATest, keys, iaCore2Test)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := trust.NewIssuer(coreIATest, keys, trc)
	if err != nil {
		t.Fatal(err)
	}
	provider := &trust.NetworkProvider{DB: db}
	engines := make(map[addr.IA]*trust.Engine)
	for _, ia := range []addr.IA{coreIATest, iaCore2Test, nodeIATest, iaLineC} {
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

	// B's three links: interface 1 to the core A, interface 2 to C,
	// interface 3 to the fellow core A2.
	links := func() map[uint16]addr.IA {
		return map[uint16]addr.IA{1: coreIATest, 2: iaLineC, 3: iaCore2Test}
	}
	store := NewBeaconStore()
	sender := &fakeSender{}
	beaconer, err := NewBeaconer(BeaconerConfig{
		IA:     nodeIATest,
		Engine: engines[nodeIATest],
		MACKey: []byte(testMACKey),
		Store:  store,
		DB:     pathDB,
		Links:  links,
		Sender: sender,
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

// core2Beacon builds the beacon the fellow core A2 sends to B: [A2] with
// next B, arriving over B's link 3.
func core2Beacon(t *testing.T, f *beaconFixture, now time.Time) *segment.PCB {
	t.Helper()
	pcb, err := segment.NewPCB(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := pcb.AppendEntry(context.Background(), iaCore2Test, segment.EntryOptions{
		Next:       nodeIATest,
		EgressIfID: 1,
	}, macFactory(), f.engines[iaCore2Test]); err != nil {
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

// originatedSegment builds a one-entry beacon of the given origin with the
// given segment ID: the store's episodes read the origin, the ID, and the
// timestamps, and one signed entry carries all three.
func originatedSegment(
	t *testing.T, f *beaconFixture, origin addr.IA, id uint16, now time.Time) *segment.PCB {

	t.Helper()
	pcb, err := segment.PCBWithID(now, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := pcb.AppendEntry(context.Background(), origin, segment.EntryOptions{
		EgressIfID: 1,
	}, macFactory(), f.engines[origin]); err != nil {
		t.Fatal(err)
	}
	return pcb
}

// TestBeaconStoreKeysByOrigin checks the store's key widened by the origin:
// two candidates of distinct origins over one ingress and one segment ID are
// two candidates — both stored, both returned by BestSet — while one origin's
// re-origination of its own segment holds a single slot whatever its
// freshness, and a beacon of another origin never replaces its namesake.
func TestBeaconStoreKeysByOrigin(t *testing.T) {
	f := newBeaconFixture(t)
	now := time.Now()

	fromCore := originatedSegment(t, f, coreIATest, 7, now)
	fromNode := originatedSegment(t, f, nodeIATest, 7, now.Add(time.Second))
	f.store.Insert(1, fromCore)
	f.store.Insert(1, fromNode)
	if got := f.store.Len(); got != 2 {
		t.Fatalf("store length = %d, want 2: distinct origins are distinct candidates", got)
	}
	stored := map[addr.IA]time.Time{}
	for _, cand := range f.store.BestSet(2) {
		stored[cand.PCB.FirstIA()] = cand.PCB.Timestamp()
	}
	if len(stored) != 2 {
		t.Fatalf("BestSet origins = %v, want both", stored)
	}

	// One origin's fresher re-origination replaces its own entry alone.
	fresher := originatedSegment(t, f, nodeIATest, 7, now.Add(2*time.Second))
	f.store.Insert(1, fresher)
	if got := f.store.Len(); got != 2 {
		t.Fatalf("store length after re-origination = %d, want 2: one segment, one slot", got)
	}
	stored = map[addr.IA]time.Time{}
	for _, cand := range f.store.BestSet(2) {
		stored[cand.PCB.FirstIA()] = cand.PCB.Timestamp()
	}
	if !stored[nodeIATest].Equal(fresher.Timestamp()) {
		t.Errorf("node's entry = %v, want the fresher re-origination %v",
			stored[nodeIATest], fresher.Timestamp())
	}

	// A staler re-origination never replaces the fresher entry.
	f.store.Insert(1, originatedSegment(t, f, nodeIATest, 7, now))
	stored = map[addr.IA]time.Time{}
	for _, cand := range f.store.BestSet(2) {
		stored[cand.PCB.FirstIA()] = cand.PCB.Timestamp()
	}
	if !stored[nodeIATest].Equal(fresher.Timestamp()) {
		t.Errorf("node's entry = %v, want the fresher to stand past the staler write",
			stored[nodeIATest])
	}
}

// TestBeaconStoreCapBoundsWidenedKeys checks that the per-interface cap
// bounds the origin-widened keys as one set: candidates of alternating
// origins over one ingress count together against the bound, and the stalest
// leave first.
func TestBeaconStoreCapBoundsWidenedKeys(t *testing.T) {
	f := newBeaconFixture(t)
	now := time.Now()
	origins := []addr.IA{coreIATest, nodeIATest}
	for i := range storePerInterface + 2 {
		f.store.Insert(1, originatedSegment(t, f, origins[i%len(origins)],
			uint16(i), now.Add(time.Duration(i)*time.Second)))
	}
	if got := f.store.Len(); got != storePerInterface {
		t.Fatalf("store length = %d, want the per-interface bound %d over both origins together",
			got, storePerInterface)
	}
	ids := map[uint16]bool{}
	for _, cand := range f.store.BestSet(storePerInterface) {
		ids[cand.PCB.ID()] = true
	}
	if ids[0] || ids[1] {
		t.Errorf("the stalest candidates (ids 0, 1) survived the bound: %v", ids)
	}
}

// fabricatedBeacon builds the beacon of a fabricating neighbor: the entry
// claims the core's name but C's key signs it — a signature valid against
// C's TRC-anchored chain, a claim it has no right to make — followed by an
// honest entry of the fabricator itself, so every check but the binding
// passes: the last entry names the arrival link's neighbor, the origin
// names a core, and the entries chain.
func fabricatedBeacon(t *testing.T, f *beaconFixture, now time.Time) *segment.PCB {
	t.Helper()
	pcb, err := segment.NewPCB(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := pcb.AppendEntry(context.Background(), coreIATest, segment.EntryOptions{
		Next:       nodeIATest,
		EgressIfID: 1,
	}, macFactory(), f.engines[iaLineC]); err != nil {
		t.Fatal(err)
	}
	if err := pcb.AppendEntry(context.Background(), nodeIATest, segment.EntryOptions{
		Next:        iaLineC,
		IngressIfID: 1,
		EgressIfID:  2,
	}, macFactory(), f.engines[nodeIATest]); err != nil {
		t.Fatal(err)
	}
	return pcb
}

// TestHandleBeaconFabricatedIdentity checks the identity binding at
// reception: an entry signed by a chain naming another ISD-AS than the
// entry claims fails verification with both identities in the error, and
// the beacon never reaches the store.
func TestHandleBeaconFabricatedIdentity(t *testing.T) {
	f := newBeaconFixture(t)
	pcb := fabricatedBeacon(t, f, time.Now())

	// The fabricated [A, B] is delivered as C sees propagation from B: on
	// C's link to B, whose neighbor the honest last entry names. B itself
	// would refuse it at the arrival check — the last entry names B, not
	// B's neighbor A — before the binding is reached.
	reparsed, err := segment.ParsePCB(pcb.PB)
	if err != nil {
		t.Fatal(err)
	}
	underC, err := NewBeaconer(BeaconerConfig{
		IA:     iaLineC,
		Engine: f.engines[iaLineC],
		MACKey: []byte(testMACKey),
		Store:  f.store,
		DB:     f.pathDB,
		Links:  func() map[uint16]addr.IA { return map[uint16]addr.IA{2: nodeIATest} },
	})
	if err != nil {
		t.Fatal(err)
	}
	err = underC.HandleBeacon(context.Background(), reparsed, 2)
	if err == nil {
		t.Fatal("fabricated beacon accepted")
	}
	if msg := err.Error(); !strings.Contains(msg, coreIATest.String()) ||
		!strings.Contains(msg, iaLineC.String()) {

		t.Errorf("error = %q, want the claimed and the signing identity both named", msg)
	}
	if got := f.store.Len(); got != 0 {
		t.Errorf("store length = %d, want 0", got)
	}
}

// TestHandleBeaconNonCoreOrigin checks the origin rule at
// reception: a beacon whose first entry names a non-core — C originating on
// its link to B — is dropped with the origin named, before signature
// verification spends work on it.
func TestHandleBeaconNonCoreOrigin(t *testing.T) {
	f := newBeaconFixture(t)

	pcb, err := segment.NewPCB(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := pcb.AppendEntry(context.Background(), iaLineC, segment.EntryOptions{
		Next:       nodeIATest,
		EgressIfID: 2,
	}, macFactory(), f.engines[iaLineC]); err != nil {
		t.Fatal(err)
	}
	reparsed, err := segment.ParsePCB(pcb.PB)
	if err != nil {
		t.Fatal(err)
	}
	err = f.beaconer.HandleBeacon(context.Background(), reparsed, 2)
	if err == nil || !strings.Contains(err.Error(), iaLineC.String()) {
		t.Fatalf("error = %v, want the non-core origin named", err)
	}
	if got := f.store.Len(); got != 0 {
		t.Errorf("store length = %d, want 0", got)
	}

	// The refusal is the whole of it: a stored nothing terminates into
	// nothing, and no up segment ever reaches the path database.
	f.beaconer.registerOnce(context.Background())
	ups, err := f.pathDB.Get(context.Background(), pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 0 {
		t.Errorf("up segments = %d, want 0", len(ups))
	}
}

// TestHandleBeaconNonCoreOriginWaivedWithoutTRC checks the bootstrap
// tolerance the origin rule carries: a node that has not pinned the TRC
// accepts a non-core's beacon as its route candidate exactly as today — the
// check the pinned TRC arms.
func TestHandleBeaconNonCoreOriginWaivedWithoutTRC(t *testing.T) {
	f := newBeaconFixture(t)
	ctx := context.Background()

	freshDB, err := bbolt.New(filepath.Join(t.TempDir(), "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = freshDB.Close() }()
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
		Links:  func() map[uint16]addr.IA { return map[uint16]addr.IA{2: iaLineC} },
	})
	if err != nil {
		t.Fatal(err)
	}

	pcb, err := segment.NewPCB(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := pcb.AppendEntry(ctx, iaLineC, segment.EntryOptions{
		Next:       nodeIATest,
		EgressIfID: 2,
	}, macFactory(), f.engines[iaLineC]); err != nil {
		t.Fatal(err)
	}
	if err := beaconer.HandleBeacon(ctx, pcb, 2); err != nil {
		t.Fatalf("non-core beacon refused without a pinned TRC: %v", err)
	}
	if got := f.store.Len(); got != 0 {
		t.Errorf("store length = %d, want 0 (never stored unverified)", got)
	}
	if beaconer.BootstrapRoute(iaLineC) == nil {
		t.Error("bootstrap route not recorded")
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
	defer func() { _ = freshDB.Close() }()
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

// TestBootstrapAlternatesOrigins checks the bootstrap slot's per-origin
// keeping and alternation: a node that has not pinned the TRC records each
// origin's freshest unverified beacon, BootstrapCore alternates across the
// origins with the freshest first, and BootstrapRoute serves each origin
// its own route — one origin's fresher beacons cannot starve the other's.
func TestBootstrapAlternatesOrigins(t *testing.T) {
	f := newBeaconFixture(t)
	ctx := context.Background()

	// A fresh node's engine: no TRC pinned, no chains.
	freshDB, err := bbolt.New(filepath.Join(t.TempDir(), "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = freshDB.Close() }()
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
		Links: func() map[uint16]addr.IA {
			return map[uint16]addr.IA{1: coreIATest, 3: iaCore2Test}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// The two cores' beacons, the fellow core's the fresher.
	now := time.Now()
	if err := beaconer.HandleBeacon(ctx, lineBeacon(t, f, now), 1); err != nil {
		t.Fatal(err)
	}
	if err := beaconer.HandleBeacon(ctx, core2Beacon(t, f, now.Add(time.Second)), 3); err != nil {
		t.Fatal(err)
	}

	// The fresher origin leads and the calls alternate, so a retrying
	// enrollment reaches every origin the beacons name.
	for i, want := range []addr.IA{iaCore2Test, coreIATest, iaCore2Test} {
		if got := beaconer.BootstrapCore(); !got.Equal(want) {
			t.Errorf("bootstrap core %d = %v, want %v", i, got, want)
		}
	}

	// Each origin's route serves its own beacon alone.
	if beaconer.BootstrapRoute(coreIATest) == nil {
		t.Error("the founder's bootstrap route missing")
	}
	if beaconer.BootstrapRoute(iaCore2Test) == nil {
		t.Error("the fellow core's bootstrap route missing")
	}
	if beaconer.BootstrapRoute(iaLineC) != nil {
		t.Error("a bootstrap route served an origin no beacon named")
	}
}

// TestPropagateOnce checks the propagation rule: every external
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
	if sent.peer.Service != addr.SvcCS {
		t.Errorf("beacon sent to service %#x, want the CS service %#x",
			uint16(sent.peer.Service), uint16(addr.SvcCS))
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

// TestCoreTierBeaconerRunsTheCoreLoops checks the core tier's loops on the
// beaconer the widened selection builds: it originates on every link — the
// core link included — propagates its stored candidates to non-core
// neighbors alone, and terminates the beacons received over core links into
// core segments, registering none. A normal node's loops are
// TestPropagateOnce's and TestRegisterOnce's, unchanged.
func TestCoreTierBeaconerRunsTheCoreLoops(t *testing.T) {
	f := newBeaconFixture(t)
	ctx := context.Background()

	// The core A under test: the child B on link 1, the fellow core A2 on
	// link 2.
	links := func() map[uint16]addr.IA {
		return map[uint16]addr.IA{1: nodeIATest, 2: iaCore2Test}
	}
	core, err := NewBeaconer(BeaconerConfig{
		IA:     coreIATest,
		Engine: f.engines[coreIATest],
		MACKey: []byte(testMACKey),
		Store:  f.store,
		DB:     f.pathDB,
		Links:  links,
		Sender: f.sender,
		Core:   true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Origination reaches every link, the core link included: the drafts'
	// own sentence for cores, which originate over core and parent-child
	// links alike.
	core.originateOnce(ctx)
	originated := snapshotBeacons(t, f)
	peers := make(map[addr.IA]bool)
	for _, sent := range originated {
		peers[sent.peer.IA] = true
		if sent.peer.Service != addr.SvcCS {
			t.Errorf("beacon to %v = service %#x, want the CS service",
				sent.peer.IA, uint16(sent.peer.Service))
		}
		parsed, err := segment.ParsePCB(sent.pcb)
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed.Entries) != 1 || !parsed.FirstIA().Equal(coreIATest) {
			t.Errorf("originated beacon = %v, want the core's own single entry", parsed.Entries)
		}
	}
	if !peers[nodeIATest] || !peers[iaCore2Test] {
		t.Fatalf("origination reached %v, want the child and the core link alike", peers)
	}

	// The fellow core's beacon arrives over the core link and propagates to
	// the non-core neighbor alone — beacons never travel toward a core.
	fromCore2, err := segment.NewPCB(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := fromCore2.AppendEntry(ctx, iaCore2Test, segment.EntryOptions{
		Next:       coreIATest,
		EgressIfID: 1,
	}, macFactory(), f.engines[iaCore2Test]); err != nil {
		t.Fatal(err)
	}
	if err := core.HandleBeacon(ctx, fromCore2, 2); err != nil {
		t.Fatalf("handle core beacon: %v", err)
	}
	core.propagateOnce(ctx)
	propagated := snapshotBeacons(t, f)[len(originated):]
	if len(propagated) != 1 {
		t.Fatalf("propagated %d beacons, want 1 to the non-core neighbor alone", len(propagated))
	}
	if !propagated[0].peer.IA.Equal(nodeIATest) {
		t.Errorf("propagated to %v, want the non-core neighbor", propagated[0].peer.IA)
	}
	parsed, err := segment.ParsePCB(propagated[0].pcb)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Entries) != 2 || !parsed.FirstIA().Equal(iaCore2Test) ||
		!parsed.LastIA().Equal(coreIATest) {

		t.Errorf("propagated beacon = %v, want [A2, A]", parsed.Entries)
	}

	// Termination: the core-link beacon becomes a core segment in the core's
	// own database, and no up segment or registration leaves the core.
	core.registerCoreOnce(ctx)
	segs, err := f.pathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeCore})
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 || !segs[0].FirstIA().Equal(iaCore2Test) ||
		!segs[0].LastIA().Equal(coreIATest) {

		t.Fatalf("core segments = %v, want [A2, A] alone", segs)
	}
	if ups, err := f.pathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp}); err != nil {
		t.Fatal(err)
	} else if len(ups) != 0 {
		t.Errorf("up segments = %d, want 0: the core registers none", len(ups))
	}
	f.sender.mtx.Lock()
	regs := len(f.sender.registrations)
	f.sender.mtx.Unlock()
	if regs != 0 {
		t.Errorf("registrations = %d, want 0: core segments stay local", regs)
	}
}

// snapshotBeacons returns the sender's recorded beacons under the lock.
func snapshotBeacons(t *testing.T, f *beaconFixture) []sentBeacon {
	t.Helper()
	f.sender.mtx.Lock()
	defer f.sender.mtx.Unlock()
	return append([]sentBeacon(nil), f.sender.beacons...)
}

// TestRegisterOnceRegistersPerOrigin checks the registration's per-origin
// send: candidates of two origins terminate and store as up segments, then
// each origin's down segments register at that core's own address — the peer
// client's dial resolving the route per destination — and one origin's
// failed dial leaves the other's registration delivered, the next pass
// retrying the failed one.
func TestRegisterOnceRegistersPerOrigin(t *testing.T) {
	f := newBeaconFixture(t)
	ctx := context.Background()

	// B stands under two cores: [A] over link 1, [A2] over link 3.
	if err := f.beaconer.HandleBeacon(ctx, lineBeacon(t, f, time.Now()), 1); err != nil {
		t.Fatal(err)
	}
	if err := f.beaconer.HandleBeacon(ctx, core2Beacon(t, f, time.Now()), 3); err != nil {
		t.Fatal(err)
	}
	f.beaconer.registerOnce(ctx)

	// The up segments store inside the same pass: both origins stand in the
	// database the registrations dial through.
	ups, err := f.pathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeUp})
	if err != nil {
		t.Fatal(err)
	}
	origins := make(map[addr.IA]bool)
	for _, up := range ups {
		origins[up.FirstIA()] = true
	}
	if len(origins) != 2 || !origins[coreIATest] || !origins[iaCore2Test] {
		t.Fatalf("up segment origins = %v, want both cores'", origins)
	}

	// Each origin's down segments register at that core's own address.
	f.sender.mtx.Lock()
	regs := append([]sentRegistration(nil), f.sender.registrations...)
	f.sender.mtx.Unlock()
	if len(regs) != 2 {
		t.Fatalf("registrations = %d, want one per origin", len(regs))
	}
	sent := make(map[addr.IA]*cppb.PathSegment)
	for _, reg := range regs {
		if !reg.peer.IA.Equal(coreIATest) && !reg.peer.IA.Equal(iaCore2Test) {
			t.Errorf("registered with %v, want a core", reg.peer.IA)
			continue
		}
		if reg.peer.Service != addr.SvcCS {
			t.Errorf("registered with %v = service %#x, want the CS service",
				reg.peer.IA, uint16(reg.peer.Service))
		}
		if len(reg.segments) != 1 {
			t.Fatalf("registration to %v = %d segments, want 1", reg.peer.IA, len(reg.segments))
		}
		sent[reg.peer.IA] = reg.segments[0]
	}
	for origin, pb := range sent {
		parsed, err := segment.ParsePCB(pb)
		if err != nil {
			t.Fatal(err)
		}
		if !parsed.FirstIA().Equal(origin) {
			t.Errorf("registration to %v = segment of %v, want its own origin's",
				origin, parsed.FirstIA())
		}
	}

	// One origin's dial fails — a core the node holds no route to; the
	// other's registration is delivered regardless, and the next pass
	// retries the failed one.
	f.sender.mtx.Lock()
	f.sender.failFor = map[addr.IA]error{iaCore2Test: errors.New("no route")}
	f.sender.mtx.Unlock()
	f.sender.mtx.Lock()
	f.sender.registrations = nil
	f.sender.mtx.Unlock()
	f.beaconer.registerOnce(ctx)
	f.sender.mtx.Lock()
	regs = append([]sentRegistration(nil), f.sender.registrations...)
	f.sender.failFor = nil
	f.sender.registrations = nil
	f.sender.mtx.Unlock()
	if len(regs) != 1 || !regs[0].peer.IA.Equal(coreIATest) {
		t.Fatalf("registrations under one failed dial = %v, want the other core's alone", regs)
	}
	f.beaconer.registerOnce(ctx)
	f.sender.mtx.Lock()
	regs = append([]sentRegistration(nil), f.sender.registrations...)
	f.sender.mtx.Unlock()
	if len(regs) != 2 {
		t.Fatalf("registrations after the retry = %d, want both origins' again", len(regs))
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

// TestHandleRegistrationFabricatedIdentity checks the binding of proposal
// 0015 at registration: a down segment whose first entry claims this core
// but is signed by another's key is refused, so the core's down-segment
// store inherits no fabrication — checkRegistered's origin claim is the
// signer's own now.
func TestHandleRegistrationFabricatedIdentity(t *testing.T) {
	f := newBeaconFixture(t)
	ctx := context.Background()

	// The fabricated down segment: [A claimed but signed by C, B terminated],
	// registered at the core A.
	fab, err := segment.NewPCB(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := fab.AppendEntry(ctx, coreIATest, segment.EntryOptions{
		Next:       nodeIATest,
		EgressIfID: 1,
	}, macFactory(), f.engines[iaLineC]); err != nil {
		t.Fatal(err)
	}
	if err := fab.AppendEntry(ctx, nodeIATest, segment.EntryOptions{
		IngressIfID: 1,
	}, macFactory(), f.engines[nodeIATest]); err != nil {
		t.Fatal(err)
	}

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
	if err := coreBeaconer.HandleRegistration(ctx, fab.PB); err == nil {
		t.Fatal("registration of a fabricated segment accepted")
	}
	downs, err := f.pathDB.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeDown})
	if err != nil {
		t.Fatal(err)
	}
	if len(downs) != 0 {
		t.Errorf("down segments = %d, want 0", len(downs))
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
		IA:       coreIATest,
		Engine:   f.engines[coreIATest],
		MACKey:   []byte(testMACKey),
		Store:    NewBeaconStore(),
		DB:       f.pathDB,
		Links:    func() map[uint16]addr.IA { return map[uint16]addr.IA{1: nodeIATest} },
		Verdicts: func() map[uint16]bool { return map[uint16]bool{1: false} },
		Sender:   f.sender,
		Core:     true,
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
