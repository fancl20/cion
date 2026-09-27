package segment_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"hash"
	"path/filepath"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers/path"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/segment"
	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/trust/impl/bbolt"
)

var (
	iaA = addr.MustIAFrom(20, 0xff0000000001)
	iaB = addr.MustIAFrom(20, 0xff0000000002)
	iaC = addr.MustIAFrom(20, 0xff0000000003)
)

const macKey = "0123456789abcdef"

// macFactory builds forwarding-key MAC hashers, as the data plane and the
// beaconer do.
func macFactory() func() hash.Hash {
	return func() hash.Hash {
		mac, _ := scrypto.InitMac([]byte(macKey))
		return mac
	}
}

// segFixture holds engines for a three-AS line: the core A and the enrolled
// B and C, all anchored in one TRC.
type segFixture struct {
	db      trust.DB
	engines map[addr.IA]*trust.Engine
	keys    map[addr.IA]*ecdsa.PrivateKey
}

func newSegFixture(t *testing.T, ias ...addr.IA) *segFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := bbolt.New(filepath.Join(dir, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	coreKeys, err := trust.LoadOrCreateCoreKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	trc, err := trust.Genesis(context.Background(), db, ias[0], coreKeys)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := trust.NewIssuer(ias[0], coreKeys, trc)
	if err != nil {
		t.Fatal(err)
	}
	f := &segFixture{
		db:      db,
		engines: make(map[addr.IA]*trust.Engine),
		keys:    make(map[addr.IA]*ecdsa.PrivateKey),
	}
	provider := &trust.NetworkProvider{DB: db}
	for _, ia := range ias {
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
		f.keys[ia] = key
		f.engines[ia] = trust.NewEngine(ia, key, provider)
	}
	return f
}

// buildLineBeacon builds the beacon a core A would originate and B would
// propagate: [A, B] with C as B's next AS.
func buildLineBeacon(t *testing.T, f *segFixture, now time.Time) *segment.PCB {
	t.Helper()
	pcb, err := segment.NewPCB(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := pcb.AppendEntry(context.Background(), iaA, segment.EntryOptions{
		Next:       iaB,
		EgressIfID: 1,
	}, macFactory(), f.engines[iaA]); err != nil {
		t.Fatal(err)
	}
	if err := pcb.AppendEntry(context.Background(), iaB, segment.EntryOptions{
		Next:        iaC,
		IngressIfID: 1,
		EgressIfID:  2,
	}, macFactory(), f.engines[iaB]); err != nil {
		t.Fatal(err)
	}
	return pcb
}

// TestAppendEntrySignature verifies the appended entries' signatures with
// the engine's verifier — the same verification reception applies.
func TestAppendEntrySignature(t *testing.T) {
	f := newSegFixture(t, iaA, iaB, iaC)
	pcb := buildLineBeacon(t, f, time.Now())

	reparsed, err := segment.ParsePCB(pcb.PB)
	if err != nil {
		t.Fatal(err)
	}
	verifier := f.engines[iaC]
	for i := range reparsed.Entries {
		if _, err := verifier.Verify(context.Background(),
			reparsed.Entries[i].Signed, reparsed.AssociatedData(i)...); err != nil {
			t.Fatalf("entry %d signature: %v", i, err)
		}
	}
	if !reparsed.FirstIA().Equal(iaA) || !reparsed.LastIA().Equal(iaB) {
		t.Errorf("entries = [%v, %v], want [%v, %v]",
			reparsed.FirstIA(), reparsed.LastIA(), iaA, iaB)
	}
}

// TestHopFieldMACChain checks the MAC chaining: each hop's MAC covers the
// segment ID advanced through the previous hops, which is what the data
// plane's processor verifies hop by hop.
func TestHopFieldMACChain(t *testing.T) {
	f := newSegFixture(t, iaA, iaB, iaC)
	pcb := buildLineBeacon(t, f, time.Now())

	info := path.InfoField{
		SegID:     pcb.ID(),
		Timestamp: util.TimeToSecs(pcb.Timestamp()),
	}
	for i, e := range pcb.Entries {
		want := path.MAC(macFactory()(), info, e.Hop, nil)
		if e.Hop.Mac != want {
			t.Errorf("hop %d MAC = %x, want %x (SegID %x)", i, e.Hop.Mac, want, info.SegID)
		}
		info.UpdateSegID(e.Hop.Mac)
	}
}

// TestTermination checks that terminating a PCB appends a final entry with
// unset next AS and egress interface (Section 3.1.1).
func TestTermination(t *testing.T) {
	f := newSegFixture(t, iaA, iaB, iaC)
	pcb := buildLineBeacon(t, f, time.Now())

	if err := pcb.AppendEntry(context.Background(), iaC, segment.EntryOptions{
		IngressIfID: 2,
	}, macFactory(), f.engines[iaC]); err != nil {
		t.Fatal(err)
	}
	last := pcb.Entries[len(pcb.Entries)-1]
	if !last.IA.Equal(iaC) {
		t.Errorf("terminating entry IA = %v, want %v", last.IA, iaC)
	}
	if !last.Next.IsZero() {
		t.Errorf("terminating entry next = %v, want unset", last.Next)
	}
	if last.Hop.ConsEgress != 0 {
		t.Errorf("terminating entry egress = %d, want 0", last.Hop.ConsEgress)
	}
	if last.Hop.ConsIngress != 2 {
		t.Errorf("terminating entry ingress = %d, want 2", last.Hop.ConsIngress)
	}
}

// terminatedLine builds the line beacon terminated at C: the segment
// [A, B, C] the truncating builders cut mid-way.
func terminatedLine(t *testing.T, f *segFixture, now time.Time) *segment.PCB {
	t.Helper()
	pcb := buildLineBeacon(t, f, now)
	if err := pcb.AppendEntry(context.Background(), iaC, segment.EntryOptions{
		IngressIfID: 2,
	}, macFactory(), f.engines[iaC]); err != nil {
		t.Fatal(err)
	}
	return pcb
}

// TestForwardReversePath checks the data-plane paths built from a segment:
// the forward path in construction direction with the originated segment ID,
// the reverse path against it with the segment ID chained through every hop
// but the terminator's own.
func TestForwardReversePath(t *testing.T) {
	f := newSegFixture(t, iaA, iaB, iaC)
	now := time.Now()
	pcb := terminatedLine(t, f, now)

	fwd := pcb.ForwardPath()
	if !fwd.InfoFields[0].ConsDir {
		t.Error("forward path is not in construction direction")
	}
	if fwd.InfoFields[0].SegID != pcb.ID() {
		t.Errorf("forward SegID = %x, want %x", fwd.InfoFields[0].SegID, pcb.ID())
	}
	if fwd.PathMeta.SegLen != [3]uint8{3, 0, 0} {
		t.Errorf("forward SegLen = %v, want [3 0 0]", fwd.PathMeta.SegLen)
	}
	for i, hop := range fwd.HopFields {
		if hop != pcb.Entries[i].Hop {
			t.Errorf("forward hop %d does not match the entry", i)
		}
	}

	rev := pcb.ReversePath()
	if rev.InfoFields[0].ConsDir {
		t.Error("reverse path is in construction direction")
	}
	wantSegID := pcb.ID()
	for i := 0; i < len(pcb.Entries)-1; i++ {
		wantSegID ^= binarySegID(pcb.Entries[i].Hop.Mac)
	}
	if rev.InfoFields[0].SegID != wantSegID {
		t.Errorf("reverse SegID = %x, want %x", rev.InfoFields[0].SegID, wantSegID)
	}
	for i, hop := range rev.HopFields {
		want := pcb.Entries[len(pcb.Entries)-1-i].Hop
		if hop != want {
			t.Errorf("reverse hop %d does not mirror entry %d", i, len(pcb.Entries)-1-i)
		}
	}
}

// binarySegID applies UpdateSegID's XOR of the MAC's first two bytes.
func binarySegID(mac [path.MacLen]byte) uint16 {
	return uint16(mac[0])<<8 | uint16(mac[1])
}

// consWalkStates returns the SegID state a construction-direction walk holds
// at each hop — the state its router verifies the hop field's MAC against,
// advanced by each hop it passes.
func consWalkStates(p *spath.Decoded) []uint16 {
	info := p.InfoFields[0]
	states := make([]uint16, 0, len(p.HopFields))
	for _, hop := range p.HopFields {
		states = append(states, info.SegID)
		info.UpdateSegID(hop.Mac)
	}
	return states
}

// antiWalkStates returns the SegID state a against-construction-direction
// walk holds at each hop: the ingress router advances the state with the hop
// it enters on, so the state at a hop is the initial one advanced through
// the hops below it.
func antiWalkStates(p *spath.Decoded) []uint16 {
	info := p.InfoFields[0]
	states := make([]uint16, 0, len(p.HopFields))
	for i, hop := range p.HopFields {
		if i > 0 {
			info.UpdateSegID(hop.Mac)
		}
		states = append(states, info.SegID)
	}
	return states
}

// checkMACs verifies every hop field's MAC against the walk states — the
// recomputation the routers perform.
func checkMACs(t *testing.T, p *spath.Decoded, states []uint16) {
	t.Helper()
	for i, hop := range p.HopFields {
		info := p.InfoFields[0]
		info.SegID = states[i]
		if want := path.MAC(macFactory()(), info, hop, nil); hop.Mac != want {
			t.Errorf("hop %d MAC = %x, want %x (SegID %x)", i, hop.Mac, want, states[i])
		}
	}
}

// TestForwardPathFrom checks the mid-segment forward builder: the info field
// chains the seed through the skipped entries, the kept hop fields' MAC
// inputs are identical to the untruncated path's at the same positions, and
// a start at or past the terminator errors rather than emitting the
// singleton the data plane rejects.
func TestForwardPathFrom(t *testing.T) {
	f := newSegFixture(t, iaA, iaB, iaC)
	pcb := terminatedLine(t, f, time.Now())

	from, err := pcb.ForwardPathFrom(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(from.HopFields) != 2 {
		t.Fatalf("path from entry 1 = %d hops, want 2", len(from.HopFields))
	}
	if !from.InfoFields[0].ConsDir {
		t.Error("path from entry 1 is not in construction direction")
	}
	wantSegID := pcb.ID() ^ binarySegID(pcb.Entries[0].Hop.Mac)
	if from.InfoFields[0].SegID != wantSegID {
		t.Errorf("SegID = %x, want the seed chained through the skipped entry %x",
			from.InfoFields[0].SegID, wantSegID)
	}
	for i, hop := range from.HopFields {
		if hop != pcb.Entries[i+1].Hop {
			t.Errorf("hop %d does not match entry %d", i, i+1)
		}
	}
	// The states the routers recompute at the kept positions are the
	// untruncated walk's own: skipping entries only starts the walk further
	// along the same chain.
	fullStates := consWalkStates(pcb.ForwardPath())
	states := consWalkStates(from)
	for i := range states {
		if states[i] != fullStates[i+1] {
			t.Errorf("walk state at hop %d = %x, want the untruncated %x",
				i, states[i], fullStates[i+1])
		}
	}
	checkMACs(t, from, states)

	for _, i := range []int{-1, 2, 3} {
		if _, err := pcb.ForwardPathFrom(i); err == nil {
			t.Errorf("forward path from entry %d succeeded, want the singleton guard", i)
		}
	}
}

// TestReversePathTo checks the truncated reverse builder: the info field is
// the untruncated one's own — reversed travel starts at the terminator
// whatever the ending — the kept hop fields' MAC inputs are identical to the
// untruncated path's at the same positions, and an ending at or past the
// terminator errors rather than emitting the singleton the data plane
// rejects.
func TestReversePathTo(t *testing.T) {
	f := newSegFixture(t, iaA, iaB, iaC)
	pcb := terminatedLine(t, f, time.Now())

	to, err := pcb.ReversePathTo(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(to.HopFields) != 2 {
		t.Fatalf("path to entry 1 = %d hops, want 2", len(to.HopFields))
	}
	if to.InfoFields[0].ConsDir {
		t.Error("path to entry 1 is in construction direction")
	}
	full := pcb.ReversePath()
	if to.InfoFields[0] != full.InfoFields[0] {
		t.Errorf("info field = %+v, want the untruncated %+v",
			to.InfoFields[0], full.InfoFields[0])
	}
	for i, hop := range to.HopFields {
		want := pcb.Entries[len(pcb.Entries)-1-i].Hop
		if hop != want {
			t.Errorf("hop %d does not mirror entry %d", i, len(pcb.Entries)-1-i)
		}
	}
	// The kept hops are a prefix of the untruncated walk in travel order:
	// truncation removes hops the kept routers never read.
	fullStates := antiWalkStates(full)
	states := antiWalkStates(to)
	for i := range states {
		if states[i] != fullStates[i] {
			t.Errorf("walk state at hop %d = %x, want the untruncated %x",
				i, states[i], fullStates[i])
		}
	}
	checkMACs(t, to, states)

	for _, m := range []int{-1, 2, 3} {
		if _, err := pcb.ReversePathTo(m); err == nil {
			t.Errorf("reversed path to entry %d succeeded, want the singleton guard", m)
		}
	}
}

// TestCompose checks that segment paths concatenate into an end-to-end path.
func TestCompose(t *testing.T) {
	f := newSegFixture(t, iaA, iaB, iaC)
	now := time.Now()
	up := buildLineBeacon(t, f, now) // [A, B] towards C
	down := buildLineBeacon(t, f, now)

	composed, err := segment.Compose(up.ReversePath(), down.ForwardPath())
	if err != nil {
		t.Fatal(err)
	}
	if len(composed.InfoFields) != 2 || composed.NumINF != 2 {
		t.Fatalf("info fields = %d (NumINF %d), want 2", len(composed.InfoFields), composed.NumINF)
	}
	if len(composed.HopFields) != 4 || composed.NumHops != 4 {
		t.Fatalf("hops = %d (NumHops %d), want 4", len(composed.HopFields), composed.NumHops)
	}
	if composed.PathMeta.SegLen != [3]uint8{2, 2, 0} {
		t.Errorf("SegLen = %v, want [2 2 0]", composed.PathMeta.SegLen)
	}
	if composed.InfoFields[0].ConsDir == composed.InfoFields[1].ConsDir {
		t.Error("composed directions do not alternate")
	}
	if _, err := segment.Compose(); err == nil {
		t.Error("composing nothing succeeded")
	}
}

// TestExpiration checks the segment's earliest hop expiration.
func TestExpiration(t *testing.T) {
	f := newSegFixture(t, iaA, iaB, iaC)
	now := time.Now().Truncate(time.Second)
	pcb := buildLineBeacon(t, f, now)

	want := now.Add(path.ExpTimeToDuration(segment.HopExpTime))
	if !pcb.Expiration().Equal(want) {
		t.Errorf("expiration = %v, want %v", pcb.Expiration(), want)
	}
	if !pcb.Expiration().After(now) {
		t.Error("fresh segment already expired")
	}
}

// TestContainsIA checks the loop-prevention predicate.
func TestContainsIA(t *testing.T) {
	f := newSegFixture(t, iaA, iaB, iaC)
	pcb := buildLineBeacon(t, f, time.Now())
	if !pcb.ContainsIA(iaA) || !pcb.ContainsIA(iaB) {
		t.Error("segment does not contain its own ASes")
	}
	if pcb.ContainsIA(iaC) {
		t.Error("segment contains an AS not on it")
	}
}

// TestParseRoundTrip checks that the parsed wire form survives
// re-serialization unchanged.
func TestParseRoundTrip(t *testing.T) {
	f := newSegFixture(t, iaA, iaB, iaC)
	pcb := buildLineBeacon(t, f, time.Now())

	clone, err := pcb.Clone()
	if err != nil {
		t.Fatal(err)
	}
	if len(clone.Entries) != len(pcb.Entries) {
		t.Fatalf("clone entries = %d, want %d", len(clone.Entries), len(pcb.Entries))
	}
	for i := range pcb.Entries {
		if string(clone.Entries[i].Signed.Signature) != string(pcb.Entries[i].Signed.Signature) {
			t.Errorf("clone entry %d signature differs", i)
		}
		if clone.Entries[i].Hop != pcb.Entries[i].Hop {
			t.Errorf("clone entry %d hop differs", i)
		}
	}
}
