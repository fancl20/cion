package topology

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/links/impl/memory"
)

var (
	fileIA  = addr.MustIAFrom(20, 0xfd0000000061)
	fileIA2 = addr.MustIAFrom(20, 0xfd0000000062)
	fileIA3 = addr.MustIAFrom(20, 0xfd0000000063)
)

// fileFixture is a file provider over a memory store and a link-set file.
type fileFixture struct {
	store  *memory.DB
	notify int
	path   string
	*File
}

// writeLinkSet writes the entries as the link-set file's JSON.
func writeLinkSet(t *testing.T, path string, entries ...Entry) {
	t.Helper()
	raw := "["
	for i, e := range entries {
		if i > 0 {
			raw += ","
		}
		raw += `{"ia":"` + e.IA + `","local":"` + e.Local +
			`","remote":"` + e.Remote + `"`
		if e.Interface != nil {
			raw += `,"interface":` + strconv.FormatUint(uint64(*e.Interface), 10)
		}
		raw += "}"
	}
	raw += "]"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newFileFixture(t *testing.T, entries ...Entry) *fileFixture {
	t.Helper()
	f := &fileFixture{
		store: memory.New(),
		path:  filepath.Join(t.TempDir(), "link-set.json"),
	}
	f.File = NewFile(FileConfig{Path: f.path, Notify: func() { f.notify++ }})
	writeLinkSet(t, f.path, entries...)
	f.Wire(Pieces{Store: f.store})
	return f
}

// entry returns the neighbor's first entry, retired ones included.
func (f *fileFixture) entry(t *testing.T, ia addr.IA) *links.Link {
	t.Helper()
	entries, err := f.store.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range entries {
		if l.NeighborIA.Equal(ia) {
			return l
		}
	}
	return nil
}

// liveEntry returns the neighbor's live entry, the retired holdbacks
// skipped.
func (f *fileFixture) liveEntry(t *testing.T, ia addr.IA) *links.Link {
	t.Helper()
	entries, err := f.store.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range entries {
		if l.NeighborIA.Equal(ia) && l.Live() {
			return l
		}
	}
	return nil
}

// TestFileCompleteIdentity checks the offline completion: the first entry's
// ISD with the drawn AS, the founding core's draw final already, and the
// empty-set refusal on a non-core's first start.
func TestFileCompleteIdentity(t *testing.T) {
	f := newFileFixture(t,
		Entry{IA: fileIA.String(), Local: "192.0.2.7:5001", Remote: "192.0.2.8:5001"})
	drawn := addr.MustIAFrom(20, 0xfd0000000099)
	ia, err := f.CompleteIdentity(context.Background(), drawn)
	if err != nil {
		t.Fatal(err)
	}
	if ia.ISD() != fileIA.ISD() || ia.AS() != drawn.AS() {
		t.Errorf("completed = %v, want the first entry's ISD %d with the drawn AS",
			ia, fileIA.ISD())
	}

	core := NewFile(FileConfig{Core: true, Path: f.path})
	if ia, err := core.CompleteIdentity(context.Background(), drawn); err != nil ||
		ia != drawn {
		t.Errorf("the core's completion = (%v, %v), want the draw unchanged", ia, err)
	}

	empty := newFileFixture(t)
	if _, err := empty.CompleteIdentity(context.Background(), drawn); err == nil {
		t.Error("an empty link-set on a non-core's first start completed")
	}
}

// TestFileLinkSetParsing checks the file's discipline: unknown members and
// malformed fields fail cleanly, an absent file fails its read.
func TestFileLinkSetParsing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "link-set.json")
	if err := os.WriteFile(path, []byte(`[
		{"ia": "20-ff00:0:1", "local": "192.0.2.7:5001", "remote": "192.0.2.8:5001", "stale": true}
	]`), 0o600); err != nil {
		t.Fatal(err)
	}
	f := NewFile(FileConfig{Path: path})
	if _, err := f.CompleteIdentity(context.Background(), fileIA); err == nil {
		t.Error("a link-set naming an unknown member was accepted")
	}

	for _, body := range []string{
		`[{"ia": "nope", "local": "192.0.2.7:5001", "remote": "192.0.2.8:5001"}]`,
		`[{"ia": "20-ff00:0:1", "local": "192.0.2.7", "remote": "192.0.2.8:5001"}]`,
		`[{"ia": "20-ff00:0:1", "local": "192.0.2.7:5001", "remote": "nope"}]`,
		`[{"ia": "20-ff00:0:1", "local": "192.0.2.7:5001", "remote": "192.0.2.8:5001",
		  "interface": 0}]`,
		`[{"ia": "20-ff00:0:1"}]`,
		`not json`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.CompleteIdentity(context.Background(), fileIA); err == nil {
			t.Errorf("the malformed link-set %q was accepted", body)
		}
	}

	absent := NewFile(FileConfig{Path: filepath.Join(dir, "absent.json")})
	if _, err := absent.CompleteIdentity(context.Background(), fileIA); err == nil {
		t.Error("an absent link-set was accepted")
	}
}

// TestFileSeedEstablishes checks the initial reconciliation: a named entry
// is established with its pinned addresses and optional interface ID, the
// operator vouching with no candidate window and no evidence check.
func TestFileSeedEstablishes(t *testing.T) {
	ifID := uint16(7)
	f := newFileFixture(t,
		Entry{IA: fileIA.String(), Local: "192.0.2.7:5001", Remote: "192.0.2.8:5001"},
		Entry{IA: fileIA2.String(), Local: "192.0.2.7:5002",
			Remote: "192.0.2.9:5002", Interface: &ifID})
	if err := f.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.notify != 1 {
		t.Errorf("notifications = %d, want the one for the file's two entries", f.notify)
	}
	e := f.entry(t, fileIA)
	if e == nil || e.State != links.StateEstablished ||
		e.Local != netip.MustParseAddrPort("192.0.2.7:5001") ||
		e.Remote != netip.MustParseAddrPort("192.0.2.8:5001") {
		t.Errorf("the unnamed-ID entry = %+v, want established with the pinned addresses", e)
	}
	if e2 := f.entry(t, fileIA2); e2 == nil || e2.IfID != ifID {
		t.Errorf("the named-ID entry = %+v, want interface %d", e2, ifID)
	}
}

// TestFileReconcileChanges checks the poll's reconciliation: an unchanged
// file writes nothing, an address change is recorded without a new
// interface ID, an entry absent from the file retires with its interface ID
// held back, and a changed file notifies exactly one generation swap.
func TestFileReconcileChanges(t *testing.T) {
	f := newFileFixture(t,
		Entry{IA: fileIA.String(), Local: "192.0.2.7:5001", Remote: "192.0.2.8:5001"},
		Entry{IA: fileIA2.String(), Local: "192.0.2.7:5002", Remote: "192.0.2.9:5002"})
	if err := f.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	updated := f.entry(t, fileIA).Updated

	// An unchanged file writes nothing — the comparison is the entry's own
	// addresses against the file's, never a clock, so an immediate pass
	// decides on equality alone.
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.notify != 1 {
		t.Errorf("an unchanged file notified %d more times", f.notify-1)
	}
	if got := f.entry(t, fileIA); got.Updated != updated {
		t.Error("an unchanged file rewrote the entry")
	}

	// A changed file notifies exactly once and retires the absent entry,
	// the changed one's addresses recorded without a new interface ID.
	id := f.entry(t, fileIA).IfID
	id2 := f.entry(t, fileIA2).IfID
	writeLinkSet(t, f.path,
		Entry{IA: fileIA.String(), Local: "192.0.2.7:6001", Remote: "192.0.2.8:6001"})
	if err := f.load(); err != nil {
		t.Fatal(err)
	}
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.notify != 2 {
		t.Errorf("notifications after the change = %d, want exactly one more", f.notify)
	}
	e := f.entry(t, fileIA)
	if e.State != links.StateEstablished ||
		e.Local != netip.MustParseAddrPort("192.0.2.7:6001") ||
		e.Remote != netip.MustParseAddrPort("192.0.2.8:6001") {
		t.Errorf("the changed entry = %+v, want the file's new addresses", e)
	}
	if e.IfID != id {
		t.Errorf("the changed entry's interface = %d, want the kept %d", e.IfID, id)
	}
	retired := f.entry(t, fileIA2)
	if retired == nil || retired.State != links.StateRetired {
		t.Fatalf("the absent entry = %+v, want retired", retired)
	}
	if retired.IfID != id2 {
		t.Errorf("the retired entry's interface = %d, want the held %d", retired.IfID, id2)
	}
	// The held-back ID refuses a new claimant.
	held := &links.Link{
		NeighborIA: fileIA3,
		Local:      netip.MustParseAddrPort("192.0.2.7:7001"),
		Remote:     netip.MustParseAddrPort("192.0.2.9:7001"),
		State:      links.StateEstablished,
		IfID:       id2,
	}
	if err := f.store.Insert(context.Background(), held); err == nil {
		t.Error("a new entry claimed the held-back interface ID")
	}

	// A reappearing entry reconciles back to established with a fresh
	// interface ID, the old one still held back.
	writeLinkSet(t, f.path,
		Entry{IA: fileIA.String(), Local: "192.0.2.7:6001", Remote: "192.0.2.8:6001"},
		Entry{IA: fileIA2.String(), Local: "192.0.2.7:5002", Remote: "192.0.2.9:5002"})
	if err := f.load(); err != nil {
		t.Fatal(err)
	}
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	e2 := f.liveEntry(t, fileIA2)
	if e2 == nil || e2.State != links.StateEstablished || e2.IfID == id2 {
		t.Errorf("the reappearing entry = %+v, want established with a fresh ID", e2)
	}
	if old := f.entry(t, fileIA2); old == e2 {
		t.Error("the reappearing entry reused the retired holdback")
	}
}

// TestFileSilentPeerKeepsEntry checks the negative the ADR names: a
// link-set naming a silent peer keeps its established entry — the operator
// vouched, and the file provider runs no candidate sweep — while
// discovery's freshness and the beaconer treat the link as timed out on
// their own.
func TestFileSilentPeerKeepsEntry(t *testing.T) {
	f := newFileFixture(t,
		Entry{IA: fileIA.String(), Local: "127.0.0.1:1", Remote: "127.0.0.1:1"})
	if err := f.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	// However long the silence, the vouch stands: the provider keeps no
	// clock of its own, so the pass right after the seed is the same one
	// any later pass would be.
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e := f.entry(t, fileIA); e == nil || e.State != links.StateEstablished {
		t.Errorf("the silent peer's entry = %+v, want the vouch to stand", e)
	}

	// The provider mounts nothing and closes nothing.
	if mounts, err := f.Mounts(); err != nil || mounts != nil {
		t.Errorf("the file provider's mounts = (%v, %v), want none", mounts, err)
	}
	if err := f.Close(); err != nil {
		t.Errorf("the file provider's close = %v, want nil", err)
	}
}
