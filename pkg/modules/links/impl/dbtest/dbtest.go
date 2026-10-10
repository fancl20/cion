// Package dbtest implements the shared contract tests for neighbor table
// database implementations, following the path DB's testing harness
// (pkg/modules/pathdb/impl/dbtest).
package dbtest

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/links"
)

// TestableDB extends the link DB interface with the reset the harness needs.
type TestableDB interface {
	links.DB
	// Prepare resets the internal state so the DB is empty and ready to be
	// tested.
	Prepare(*testing.T, context.Context)
	// Reopen closes and reopens the database at the same location.
	Reopen(*testing.T, context.Context)
}

// Run tests an implementation of the links.DB interface; an implementation
// has at least one test that calls this suite.
func Run(t *testing.T, db TestableDB) {
	tests := map[string]func(*testing.T, TestableDB){
		"insert and read":        testInsertRead,
		"update":                 testUpdate,
		"lookups":                testLookups,
		"allocate skips live":    testAllocateSkipsLive,
		"preset interface id":    testPresetIfID,
		"persist across open":    testPersist,
		"one live per neighbor":  testOneLivePerNeighbor,
		"one serving per remote": testOneServingPerRemote,
	}
	for name, test := range tests {
		t.Run("DB: "+name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			db.Prepare(t, ctx)
			// The close is deferred so a failing test's runtime.Goexit still
			// releases the database — a leaked handle would block the next
			// subtest's open on the file lock.
			defer func() { _ = db.Close() }()
			test(t, db)
		})
	}
}

var (
	iaA = addr.MustIAFrom(20, 0xfd0000000001)
	iaB = addr.MustIAFrom(20, 0xfd0000000002)
	iaC = addr.MustIAFrom(20, 0xfd0000000003)
)

// fixtures counts the entry fixtures built, each taking its own pair of
// link addresses: the table refuses two serving entries with one remote.
var fixtures atomic.Uint32

// link builds an entry fixture with link addresses no other fixture holds.
func link(ia addr.IA, state links.State) *links.Link {
	port := uint16(40000 + 2*fixtures.Add(1))
	return &links.Link{
		NeighborIA: ia,
		Local:      netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port),
		Remote:     netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port+1),
		State:      state,
	}
}

func testInsertRead(t *testing.T, db TestableDB) {
	ctx := context.Background()
	l := link(iaA, links.StateEstablished)
	if err := db.Insert(ctx, l); err != nil {
		t.Fatal(err)
	}
	if l.IfID == 0 {
		t.Fatal("Insert did not allocate an interface ID")
	}
	entries, err := db.All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("All = %d entries, want 1", len(entries))
	}
	if !entries[0].NeighborIA.Equal(iaA) || entries[0].State != links.StateEstablished {
		t.Errorf("entry = %+v, want the established %s one", entries[0], iaA)
	}
	if entries[0].IfID != l.IfID {
		t.Errorf("stored IfID = %d, want the allocated %d", entries[0].IfID, l.IfID)
	}
}

func testUpdate(t *testing.T, db TestableDB) {
	ctx := context.Background()
	l := link(iaA, links.StateCandidate)
	if err := db.Insert(ctx, l); err != nil {
		t.Fatal(err)
	}
	l.State = links.StateEstablished
	l.RemoteIfID = 7
	if err := db.Update(ctx, l); err != nil {
		t.Fatal(err)
	}
	entries, err := db.All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("All = %d entries, want 1", len(entries))
	}
	if entries[0].State != links.StateEstablished || entries[0].RemoteIfID != 7 {
		t.Errorf("updated entry = %+v, want the established one with the remote ID",
			entries[0])
	}
	// An update of an unstored interface ID is an error.
	stranger := link(iaB, links.StateEstablished)
	stranger.IfID = 999
	if err := db.Update(ctx, stranger); err == nil {
		t.Error("updating an unstored interface ID succeeded, want error")
	}
}

func testLookups(t *testing.T, db TestableDB) {
	ctx := context.Background()
	a := link(iaA, links.StateEstablished)
	a.Rendezvous = netip.MustParseAddrPort("127.0.0.1:30043")
	if err := db.Insert(ctx, a); err != nil {
		t.Fatal(err)
	}
	b := link(iaB, links.StateCandidate)
	if err := db.Insert(ctx, b); err != nil {
		t.Fatal(err)
	}

	got, err := db.ByNeighbor(ctx, iaA)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.IfID != a.IfID {
		t.Fatalf("ByNeighbor = %+v, want the %s entry", got, iaA)
	}
	// By remote link address and by rendezvous address — the joiner's seeded
	// entry is found by either until the reply retargets it.
	for _, remote := range []netip.AddrPort{a.Remote, a.Rendezvous} {
		got, err = db.ByRemote(ctx, remote)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || got.IfID != a.IfID {
			t.Fatalf("ByRemote(%v) = %+v, want the %s entry", remote, got, iaA)
		}
	}
	// Absent neighbors and addresses report nil, not an error.
	for _, lookup := range []func() (*links.Link, error){
		func() (*links.Link, error) { return db.ByNeighbor(ctx, iaC) },
		func() (*links.Link, error) {
			return db.ByRemote(ctx, netip.MustParseAddrPort("127.0.0.1:1"))
		},
	} {
		got, err := lookup()
		if err != nil || got != nil {
			t.Errorf("lookup = (%v, %v), want (nil, nil)", got, err)
		}
	}

	// A retired entry leaves the lookups.
	a.State = links.StateRetired
	a.Retired = time.Now()
	if err := db.Update(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err = db.ByNeighbor(ctx, iaA)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("ByNeighbor of a retired entry = %+v, want nil", got)
	}
}

// testAllocateSkipsLive checks the monotonic counter: entries inserted in
// order draw consecutive interface IDs, and a live ID is never handed out
// again.
func testAllocateSkipsLive(t *testing.T, db TestableDB) {
	ctx := context.Background()
	var ids []uint16
	for _, ia := range []addr.IA{iaA, iaB, iaC} {
		l := link(ia, links.StateEstablished)
		if err := db.Insert(ctx, l); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, l.IfID)
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("interface IDs = %v, want monotonically increasing", ids)
		}
	}
}

// testPresetIfID checks the entry-carried interface ID: an insert carrying
// one takes it, a later insert claiming the same ID is refused, and the one
// a retired entry still holds back is refused too — the file provider's
// vouched entries are the carrier.
func testPresetIfID(t *testing.T, db TestableDB) {
	ctx := context.Background()
	l := link(iaA, links.StateEstablished)
	l.IfID = 42
	if err := db.Insert(ctx, l); err != nil {
		t.Fatal(err)
	}
	if l.IfID != 42 {
		t.Fatalf("interface ID = %d, want the preset 42", l.IfID)
	}
	clash := link(iaB, links.StateEstablished)
	clash.IfID = 42
	if err := db.Insert(ctx, clash); err == nil {
		t.Error("an insert claiming a live interface ID was accepted")
	}
	l.State = links.StateRetired
	l.Retired = time.Now()
	if err := db.Update(ctx, l); err != nil {
		t.Fatal(err)
	}
	held := link(iaC, links.StateEstablished)
	held.IfID = 42
	if err := db.Insert(ctx, held); err == nil {
		t.Error("an insert claiming a held-back interface ID was accepted")
	}
}

// testPersist checks that entries survive closing and reopening the database:
// a restarted node serves from the persisted neighbor table without
// rendezvous.
func testPersist(t *testing.T, db TestableDB) {
	ctx := context.Background()
	l := link(iaA, links.StateEstablished)
	if err := db.Insert(ctx, l); err != nil {
		t.Fatal(err)
	}
	db.Reopen(t, ctx)
	entries, err := db.All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("All after reopen = %d entries, want 1", len(entries))
	}
	if entries[0].IfID != l.IfID || !entries[0].NeighborIA.Equal(iaA) {
		t.Errorf("entry after reopen = %+v, want the persisted one", entries[0])
	}
	// The counter survived too: a new entry draws a fresh ID.
	fresh := link(iaB, links.StateEstablished)
	if err := db.Insert(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.IfID <= l.IfID {
		t.Errorf("interface ID after reopen = %d, want one past %d", fresh.IfID, l.IfID)
	}
}

// testOneLivePerNeighbor checks the table's rule: an insert or an update
// that would leave two live entries naming one neighbor is refused with
// ErrDuplicateNeighbor and changes nothing, while unnamed entries are
// unbound, an entry's own update passes, and a retired entry frees its
// neighbor.
func testOneLivePerNeighbor(t *testing.T, db TestableDB) {
	ctx := context.Background()
	a := link(iaA, links.StateEstablished)
	if err := db.Insert(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := db.Insert(ctx, link(iaA, links.StateCandidate)); !errors.Is(err, links.ErrDuplicateNeighbor) {
		t.Errorf("a second live entry of %s inserted with %v, want ErrDuplicateNeighbor", iaA, err)
	}
	unnamed := link(0, links.StateCandidate)
	if err := db.Insert(ctx, unnamed); err != nil {
		t.Fatal(err)
	}
	if err := db.Insert(ctx, link(0, links.StateCandidate)); err != nil {
		t.Errorf("a second unnamed entry was refused: %v", err)
	}
	named := *unnamed
	named.NeighborIA = iaA
	if err := db.Update(ctx, &named); !errors.Is(err, links.ErrDuplicateNeighbor) {
		t.Errorf("an update naming a second live entry of %s returned %v, want ErrDuplicateNeighbor",
			iaA, err)
	}
	got, err := db.ByNeighbor(ctx, iaA)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.IfID != a.IfID {
		t.Fatalf("ByNeighbor after the refusals = %+v, want the first entry", got)
	}

	a.RemoteIfID = 7
	if err := db.Update(ctx, a); err != nil {
		t.Errorf("updating the neighbor's own entry: %v", err)
	}
	a.State = links.StateRetired
	a.Retired = time.Now()
	if err := db.Update(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := db.Update(ctx, &named); err != nil {
		t.Errorf("naming an entry after a retired neighbor: %v", err)
	}
}

// testOneServingPerRemote checks the table's other rule: an insert or an
// update that would leave two serving entries with one remote address is
// refused with ErrDuplicateRemote and changes nothing, while an entry's own
// update passes and a retired entry frees its address.
func testOneServingPerRemote(t *testing.T, db TestableDB) {
	ctx := context.Background()
	a := link(iaA, links.StateEstablished)
	if err := db.Insert(ctx, a); err != nil {
		t.Fatal(err)
	}
	b := link(iaB, links.StateCandidate)
	b.Remote = a.Remote
	if err := db.Insert(ctx, b); !errors.Is(err, links.ErrDuplicateRemote) {
		t.Errorf("a second serving entry of %v inserted with %v, want ErrDuplicateRemote",
			a.Remote, err)
	}
	c := link(iaC, links.StateCandidate)
	if err := db.Insert(ctx, c); err != nil {
		t.Fatal(err)
	}
	moved := *c
	moved.Remote = a.Remote
	if err := db.Update(ctx, &moved); !errors.Is(err, links.ErrDuplicateRemote) {
		t.Errorf("an update onto %v returned %v, want ErrDuplicateRemote", a.Remote, err)
	}
	if got, err := db.ByNeighbor(ctx, iaB); err != nil || got != nil {
		t.Errorf("the refused insert left %+v (%v), want nothing", got, err)
	}
	got, err := db.ByNeighbor(ctx, iaC)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Remote != c.Remote {
		t.Fatalf("the entry after the refused update = %+v, want its remote %v", got, c.Remote)
	}

	a.RemoteIfID = 7
	if err := db.Update(ctx, a); err != nil {
		t.Errorf("updating the address holder's own entry: %v", err)
	}
	a.State = links.StateRetired
	a.Retired = time.Now()
	if err := db.Update(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := db.Update(ctx, &moved); err != nil {
		t.Errorf("moving onto a retired entry's address: %v", err)
	}
}
