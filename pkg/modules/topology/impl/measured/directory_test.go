package measured

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	"google.golang.org/protobuf/proto"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/trust/trusttest"
	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/peeria"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
	nodev1connect "github.com/fancl20/cion/proto/node/v1/nodev1connect"
)

var (
	directoryIA = addr.MustIAFrom(20, 0xfd0000000041)
	founderIA   = addr.MustIAFrom(20, 0xfd0000000001)
	// trcPrev and trcN are two successive TRCs of the entries' ISD.
	trcPrev = cppki.TRCID{ISD: 20, Base: 1, Serial: 1}
	trcN    = cppki.TRCID{ISD: 20, Base: 1, Serial: 2}
	// linkHost is the host a link's peer sees the node at where a test
	// attaches a link by hand.
	linkHost = netip.MustParseAddr("192.0.2.200")
)

// openTrustDB opens a trust database in a fresh directory, closed when the
// test ends.
func openTrustDB(t *testing.T) trustdb.DB {
	t.Helper()
	db, err := bbolt.New(filepath.Join(t.TempDir(), "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// bodyAt returns the entry of the ISD-AS naming the hosts, in order; one
// naming none is a withdrawal.
func bodyAt(ia addr.IA, hosts ...string) *nodev1.Entry {
	body := &nodev1.Entry{IsdAs: uint64(ia)}
	for _, host := range hosts {
		h := netip.MustParseAddr(host)
		body.Addresses = append(body.Addresses, &nodev1.Address{
			ControlAddr:    netip.AddrPortFrom(h, scionrpc.EndpointPort).String(),
			RendezvousAddr: netip.AddrPortFrom(h, RendezvousPort).String(),
		})
	}
	return body
}

// hostsOf returns the hosts an entry's addresses name, in order.
func hostsOf(e bus.DirectoryEntry) []netip.Addr {
	var out []netip.Addr
	for _, a := range e.Addresses {
		out = append(out, a.RendezvousAddr.Addr())
	}
	return out
}

// signEntry signs the body with the engine, as a node signs its entry.
func signEntry(t *testing.T, engine *trust.Engine, body *nodev1.Entry) *cryptopb.SignedMessage {
	t.Helper()
	raw, err := proto.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := engine.Sign(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// uncertifiedKey signs the fake entries: no chain certifies it.
var uncertifiedKey = sync.OnceValue(func() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
})

// fakeEntry returns an entry of the signer naming the TRC and the signing
// time, signed by a key no chain certifies.
func fakeEntry(
	t *testing.T, signer addr.IA, trc cppki.TRCID, at time.Time, body *nodev1.Entry,
) *cryptopb.SignedMessage {

	t.Helper()
	keyID, err := proto.Marshal(&cppb.VerificationKeyID{
		IsdAs:        uint64(signer),
		TrcBase:      uint64(trc.Base),
		TrcSerial:    uint64(trc.Serial),
		SubjectKeyId: []byte{1},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := proto.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := signed.Sign(signed.Header{
		SignatureAlgorithm: signed.ECDSAWithSHA256,
		VerificationKeyID:  keyID,
		Timestamp:          at,
	}, raw, uncertifiedKey())
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// fakeTrust verifies every entry, counting the verifications.
type fakeTrust struct {
	mtx      sync.Mutex
	verified int
}

func (f *fakeTrust) Signer(context.Context) (trust.Signer, error) {
	return trust.Signer{}, errors.New("the fake trust signs nothing")
}

func (f *fakeTrust) VerifyBoundAt(
	_ context.Context, _ addr.IA, _ net.Addr, msg *cryptopb.SignedMessage, _ time.Time,
	_ ...[]byte,
) (*signed.Message, error) {

	f.mtx.Lock()
	f.verified++
	f.mtx.Unlock()
	hdr, err := signed.ExtractUnverifiedHeader(msg)
	if err != nil {
		return nil, err
	}
	body, err := signed.ExtractUnverifiedBody(msg)
	if err != nil {
		return nil, err
	}
	return &signed.Message{Header: signed.Header(*hdr), Body: []byte(body)}, nil
}

func (f *fakeTrust) verifications() int {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	return f.verified
}

// asNeighbor returns the context of a request the neighbor sent over the
// interface it arrived on.
func asNeighbor(ctx context.Context, neighbor addr.IA, ifID uint16) context.Context {
	ctx = context.WithValue(ctx, peeria.AuthenticatedIAContextKey(), neighbor)
	return context.WithValue(ctx, http3.RemoteAddrContextKey,
		&scion.Addr{IA: neighbor, Service: addr.SvcCS, IfID: ifID})
}

// attachLink attaches the link on the interface at linkHost, and returns
// the directory it joins.
func attachLink(d *NodeDirectory, ifID uint16) bus.DirectoryID {
	return d.attach(ifID, linkHost)
}

// plainAddresses returns the node's addresses at the hosts with nothing to
// report of its reach: the endpoint and rendezvous ports on each, no NAT,
// and no echo unanswered.
func plainAddresses(hosts []netip.Addr) ([]*nodev1.Address, error) {
	out := make([]*nodev1.Address, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, &nodev1.Address{
			ControlAddr:    netip.AddrPortFrom(h, scionrpc.EndpointPort).String(),
			RendezvousAddr: netip.AddrPortFrom(h, RendezvousPort).String(),
		})
	}
	return out, nil
}

// heldTimes returns the signing times of the entries the node's
// directories hold, by signer: each signer's latest across them.
func heldTimes(d *NodeDirectory) map[addr.IA]time.Time {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	out := make(map[addr.IA]time.Time)
	for _, s := range d.scopes {
		for signer, e := range s.entries {
			if at, ok := out[signer]; !ok || e.key.signedAt.After(at) {
				out[signer] = e.key.signedAt
			}
		}
	}
	return out
}

// heldIn returns the entries the directory the ID names holds, by signer;
// nil when the node holds no such directory.
func heldIn(d *NodeDirectory, id bus.DirectoryID) map[addr.IA]*signedEntry {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	s, ok := d.scopes[id]
	if !ok {
		return nil
	}
	return maps.Clone(s.entries)
}

// counterIDs returns a mint of ascending IDs whose first byte is first:
// above every ID a test names with a smaller first byte.
func counterIDs(first byte) func() bus.DirectoryID {
	var n uint32
	return func() bus.DirectoryID {
		n++
		id := bus.DirectoryID{first}
		binary.BigEndian.PutUint32(id[12:], n)
		return id
	}
}

// TestEntryOrder checks the order of a signer's entries: the TRC named,
// base then serial, then the signing time, then the signed bytes; and the
// summary's comparison, which agrees with it but for the bytes.
func TestEntryOrder(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	key := func(base, serial uint64, at time.Time, signed string) entryKey {
		return entryKey{
			trc:      cppki.TRCID{ISD: 20, Base: scrypto.Version(base), Serial: scrypto.Version(serial)},
			signedAt: at,
			signed:   []byte(signed),
		}
	}
	for _, tc := range []struct {
		name          string
		lesser, great entryKey
	}{
		{"a later base outranks", key(1, 9, at.Add(time.Hour), "z"), key(2, 1, at, "a")},
		{"a later serial outranks", key(1, 1, at.Add(time.Hour), "z"), key(1, 2, at, "a")},
		{"a later signing outranks", key(1, 1, at, "z"), key(1, 1, at.Add(time.Nanosecond), "a")},
		{"greater bytes outrank", key(1, 1, at, "a"), key(1, 1, at, "b")},
	} {
		if c := tc.lesser.compare(tc.great); c >= 0 {
			t.Errorf("%s: compare = %d, want below 0", tc.name, c)
		}
		if c := tc.great.compare(tc.lesser); c <= 0 {
			t.Errorf("%s: the reverse compare = %d, want above 0", tc.name, c)
		}
		if c := tc.great.compare(tc.great); c != 0 {
			t.Errorf("%s: compare with itself = %d, want 0", tc.name, c)
		}
		s := (&signedEntry{signer: directoryIA, key: tc.lesser}).summary()
		want := 1
		if tc.name == "greater bytes outrank" {
			want = 0
		}
		if c := tc.great.compareSummary(s); c != want {
			t.Errorf("%s: compareSummary = %d, want %d", tc.name, c, want)
		}
	}
}

// generatedEntries returns n entries of random signers, TRCs, signing
// times, and signed bytes.
func generatedEntries(rng *mrand.Rand, n int) []*signedEntry {
	signers := []addr.IA{directoryIA, founderIA, addr.MustIAFrom(20, 0xfd0000000042)}
	base := time.Unix(1_700_000_000, 0)
	out := make([]*signedEntry, 0, n)
	for range n {
		out = append(out, &signedEntry{
			signer: signers[rng.IntN(len(signers))],
			key: entryKey{
				trc:      cppki.TRCID{ISD: 20, Base: 1, Serial: scrypto.Version(1 + rng.IntN(2))},
				signedAt: base.Add(time.Duration(rng.IntN(4)) * time.Second),
				signed:   []byte{byte(rng.IntN(3))},
			},
		})
	}
	return out
}

// keysEqual compares entry keys by the order.
var keysEqual = cmp.Comparer(func(a, b entryKey) bool { return a.compare(b) == 0 })

// TestDirectoryJoinIsASemilattice checks the join over generated entry
// sets: merging them in any order, grouping, and repetition leaves every
// directory holding the same entries — each signer's greatest.
func TestDirectoryJoinIsASemilattice(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(1, 2))
	join := func(sets ...[]*signedEntry) map[addr.IA]entryKey {
		s := newScope()
		for _, set := range sets {
			for _, e := range set {
				s.merge(e)
			}
		}
		out := make(map[addr.IA]entryKey, len(s.entries))
		for signer, e := range s.entries {
			out[signer] = e.key
		}
		return out
	}
	for i := range 200 {
		a, b, c := generatedEntries(rng, rng.IntN(6)), generatedEntries(rng, rng.IntN(6)),
			generatedEntries(rng, rng.IntN(6))
		ab := join(a, b)
		if diff := cmp.Diff(ab, join(b, a), keysEqual); diff != "" {
			t.Fatalf("round %d: the join is not commutative (-a,b +b,a):\n%s", i, diff)
		}
		shuffled := slices.Concat(a, b, c)
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		abc := join(a, b, c)
		if diff := cmp.Diff(abc, join(shuffled), keysEqual); diff != "" {
			t.Fatalf("round %d: the join is not associative (-in order +shuffled):\n%s", i, diff)
		}
		if diff := cmp.Diff(abc, join(a, b, c, c, a, b), keysEqual); diff != "" {
			t.Fatalf("round %d: the join is not idempotent (-once +repeated):\n%s", i, diff)
		}
		for signer, k := range abc {
			for _, e := range slices.Concat(a, b, c) {
				if e.signer == signer && e.key.compare(k) > 0 {
					t.Fatalf("round %d: %v holds an entry below a merged one", i, signer)
				}
			}
		}
	}
}

// TestDirectoryMergesInAnyOrder checks the IDs and the directories together
// over generated networks: whatever the order of the links' reports, the
// syncs, and the entries' arrival, once every link is reported and synced
// the attachments fall into the same scopes, and each scope's directory
// holds the same entries.
func TestDirectoryMergesInAnyOrder(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(3, 4))
	hosts := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}
	signers := []addr.IA{directoryIA, founderIA, addr.MustIAFrom(20, 0xfd0000000042)}
	base := time.Unix(1_700_000_000, 0)
	// spec is one link: b sees a at aSeen, a sees b at bSeen.
	type spec struct {
		a, b         int
		aSeen, bSeen string
	}
	// op is one step: the report of the host the neighbor sees the node at,
	// a sync, or an entry's arrival, at the node's end of its link to the
	// neighbor.
	type op struct {
		kind           int
		node, neighbor int
		msg            *cryptopb.SignedMessage
	}
	const reportOp, syncOp, deliverOp = 0, 1, 2
	type outcome struct {
		Scopes  [][]string
		Entries map[string]map[addr.IA]entryKey
	}
	run := func(specs []spec, ops []op) outcome {
		f := newFabric()
		nodes := make([]*fabricNode, len(hosts))
		for i, h := range hosts {
			nodes[i] = f.addTrusting(addr.MustIAFrom(20, addr.AS(0xfd0000000700+uint64(i))), &fakeTrust{}, h)
		}
		for _, sp := range specs {
			f.connect(nodes[sp.a], nodes[sp.b], netip.MustParseAddr(sp.aSeen), netip.MustParseAddr(sp.bSeen))
		}
		do := func(o op) {
			n, other := nodes[o.node], nodes[o.neighbor]
			ifID := n.ifIDs[other.ia]
			switch o.kind {
			case reportOp:
				f.report(n, other.ia)
			case syncOp:
				_ = n.dir.syncWith(t.Context(), ifID, other.ia)
			case deliverOp:
				n.dir.accept(t.Context(), []*cryptopb.SignedMessage{o.msg}, other.ia, ifID)
			}
		}
		for _, o := range ops {
			do(o)
		}
		// Settle: every link is reported and synced at both ends, and every
		// entry arrives again, until each change has crossed the network.
		for range 2 * len(hosts) {
			for _, kind := range []int{reportOp, syncOp} {
				for _, sp := range specs {
					do(op{kind: kind, node: sp.a, neighbor: sp.b})
					do(op{kind: kind, node: sp.b, neighbor: sp.a})
				}
			}
			for _, o := range ops {
				if o.kind == deliverOp {
					do(o)
				}
			}
		}
		groups := make(map[bus.DirectoryID][]string)
		for i, n := range nodes {
			for host, a := range n.dir.attachments {
				groups[a.id] = append(groups[a.id], fmt.Sprintf("%d@%v", i, host))
			}
		}
		out := outcome{Entries: make(map[string]map[addr.IA]entryKey)}
		for id, members := range groups {
			slices.Sort(members)
			out.Scopes = append(out.Scopes, members)
			keys := make(map[addr.IA]entryKey)
			for _, n := range nodes {
				for signer, e := range heldIn(n.dir, id) {
					if held, ok := keys[signer]; !ok || e.key.compare(held) > 0 {
						keys[signer] = e.key
					}
				}
			}
			out.Entries[strings.Join(members, ",")] = keys
		}
		slices.SortFunc(out.Scopes, func(a, b []string) int { return strings.Compare(a[0], b[0]) })
		return out
	}
	for i := range 30 {
		var specs []spec
		for a := range hosts {
			for b := a + 1; b < len(hosts); b++ {
				if rng.IntN(2) == 0 {
					continue
				}
				sp := spec{a: a, b: b, aSeen: hosts[a], bSeen: hosts[b]}
				if rng.IntN(3) == 0 {
					sp.aSeen = "203.0.113.1"
				}
				specs = append(specs, sp)
			}
		}
		if len(specs) == 0 {
			continue
		}
		var ops []op
		for range rng.IntN(16) {
			sp := specs[rng.IntN(len(specs))]
			o := op{kind: rng.IntN(3), node: sp.a, neighbor: sp.b}
			if rng.IntN(2) == 0 {
				o.node, o.neighbor = sp.b, sp.a
			}
			if o.kind == deliverOp {
				signer := signers[rng.IntN(len(signers))]
				trc := cppki.TRCID{ISD: 20, Base: 1, Serial: scrypto.Version(1 + rng.IntN(2))}
				o.msg = fakeEntry(t, signer, trc, base.Add(time.Duration(rng.IntN(4))*time.Second),
					bodyAt(signer, fmt.Sprintf("198.51.100.%d", 1+rng.IntN(3))))
			}
			ops = append(ops, o)
		}
		want := run(specs, ops)
		shuffled := slices.Clone(ops)
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		if diff := cmp.Diff(want, run(specs, shuffled), keysEqual); diff != "" {
			t.Fatalf("round %d: the order changed the outcome (-in order +shuffled):\n%s", i, diff)
		}
		if diff := cmp.Diff(want, run(specs, slices.Concat(ops, ops)), keysEqual); diff != "" {
			t.Fatalf("round %d: repetition changed the outcome (-once +twice):\n%s", i, diff)
		}
	}
}

// TestDirectoryNeverVerifiesALoser checks acceptance's order: an entry
// greater than the one held is verified and merged, while one equal to it
// or lesser is passed over before any verification, and an entry over a
// link that joins no directory is never verified.
func TestDirectoryNeverVerifiesALoser(t *testing.T) {
	signer := founderIA
	now := time.Now()
	ft := &fakeTrust{}
	d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Trust: ft})
	attachLink(d, 1)
	greater := fakeEntry(t, signer, trcN, now, bodyAt(signer, "192.0.2.1"))
	lesser := fakeEntry(t, signer, trcN, now.Add(-time.Minute), bodyAt(signer, "192.0.2.2"))
	ctx := t.Context()
	if n := d.accept(ctx, []*cryptopb.SignedMessage{greater}, directoryIA, 1); n != 1 {
		t.Fatalf("the greater entry merged %d, want 1", n)
	}
	if n := d.accept(ctx, []*cryptopb.SignedMessage{greater, lesser}, directoryIA, 1); n != 0 {
		t.Errorf("the held and the lesser entries merged %d, want none", n)
	}
	unattached := fakeEntry(t, addr.MustIAFrom(20, 0xfd0000000042), trcN, now,
		bodyAt(addr.MustIAFrom(20, 0xfd0000000042), "192.0.2.3"))
	if n := d.accept(ctx, []*cryptopb.SignedMessage{unattached}, directoryIA, 9); n != 0 {
		t.Errorf("an entry over a link that joins no directory merged %d, want none", n)
	}
	if got := ft.verifications(); got != 1 {
		t.Errorf("verifications = %d, want the greater entry's alone", got)
	}
}

// TestDirectoryView checks the view: it shows an entry whatever TRC it
// names, and leaves out one signed a lifetime before the node's clock or
// after the future bound past it, and a withdrawal, changing nothing in the
// directory. It names when the clock next changes it.
func TestDirectoryView(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	signer := func(n uint64) addr.IA { return addr.MustIAFrom(20, addr.AS(0xfd0000000100+n)) }
	pbs := []*cryptopb.SignedMessage{
		fakeEntry(t, signer(1), trcN, now.Add(-time.Minute), bodyAt(signer(1), "192.0.2.1")),
		fakeEntry(t, signer(2), trcPrev, now.Add(-time.Minute), bodyAt(signer(2), "192.0.2.2")),
		fakeEntry(t, signer(3), trcN, now.Add(-EntryLifetime), bodyAt(signer(3), "192.0.2.3")),
		fakeEntry(t, signer(4), trcN, now.Add(entryFutureBound+time.Second),
			bodyAt(signer(4), "192.0.2.4")),
		fakeEntry(t, signer(5), trcN, now.Add(-time.Minute), bodyAt(signer(5))),
	}
	d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Trust: &fakeTrust{}})
	id := attachLink(d, 1)
	for _, pb := range pbs {
		e, err := parseEntry(pb)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.verify(t.Context(), e, nil); err != nil {
			t.Fatal(err)
		}
		d.mergeOver(1, e)
	}
	held := heldTimes(d)

	d.mtx.Lock()
	v, next := d.viewLocked(now)
	d.mtx.Unlock()
	got := slices.Sorted(maps.Keys(v.scopes[id]))
	if want := []addr.IA{signer(1), signer(2)}; !slices.Equal(got, want) {
		t.Errorf("the view = %v, want %v", got, want)
	}
	if want := now.Add(time.Second); !next.Equal(want) {
		t.Errorf("the view changes next at %v, want the future entry's entering at %v", next, want)
	}
	if v.links[1] != id {
		t.Errorf("the view attaches the link to %v, want %v", v.links[1], id)
	}
	if diff := cmp.Diff(held, heldTimes(d)); diff != "" {
		t.Errorf("the view changed the directory (-before +after):\n%s", diff)
	}
}

// TestDirectoryViewFollowsTheClock checks the views' publication with no
// entry arriving: an entry signed past the future bound is published once
// the clock reaches the bound, and an entry leaves the published view once
// it leaves the window.
func TestDirectoryViewFollowsTheClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		signer := func(n uint64) addr.IA { return addr.MustIAFrom(20, addr.AS(0xfd0000000500+n)) }
		topic := new(bus.Topic[bus.Directory])
		d := NewNodeDirectory(NodeDirectoryConfig{
			IA: directoryIA, Trust: &fakeTrust{}, Directory: topic,
		})
		id := attachLink(d, 1)
		now := time.Now()
		msgs := []*cryptopb.SignedMessage{
			fakeEntry(t, signer(1), trcN, now, bodyAt(signer(1), "192.0.2.1")),
			fakeEntry(t, signer(2), trcN, now.Add(entryFutureBound+time.Minute),
				bodyAt(signer(2), "192.0.2.2")),
		}
		if n := d.accept(t.Context(), msgs, founderIA, 1); n != len(msgs) {
			t.Fatalf("merged %d, want all %d", n, len(msgs))
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go d.runView(ctx)
		published := func() []addr.IA {
			s, _ := topic.Latest().Scope(id)
			var out []addr.IA
			for _, e := range s.Entries() {
				out = append(out, e.IA)
			}
			return out
		}
		synctest.Wait()
		if got, want := published(), []addr.IA{signer(1)}; !slices.Equal(got, want) {
			t.Errorf("published at the start = %v, want %v", got, want)
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if got, want := published(), []addr.IA{signer(1), signer(2)}; !slices.Equal(got, want) {
			t.Errorf("published once the future bound reached the entry = %v, want %v", got, want)
		}
		time.Sleep(EntryLifetime - time.Minute)
		synctest.Wait()
		if got, want := published(), []addr.IA{signer(2)}; !slices.Equal(got, want) {
			t.Errorf("published a lifetime past the first entry = %v, want %v", got, want)
		}
	})
}

// TestDirectoryDiscards checks the discard: a pass drops the entries the
// view never shows again, signed two lifetimes back, and keeps the ones left
// out for less, whatever TRC they name, the future one, and the withdrawal.
// An entry signed before that horizon is discarded on arrival, unverified.
func TestDirectoryDiscards(t *testing.T) {
	now := time.Now()
	signer := func(n uint64) addr.IA { return addr.MustIAFrom(20, addr.AS(0xfd0000000200+n)) }
	ft := &fakeTrust{}
	d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Trust: ft})
	attachLink(d, 1)
	pbs := []*cryptopb.SignedMessage{
		fakeEntry(t, signer(1), trcN, now.Add(-EntryLifetime-time.Minute),
			bodyAt(signer(1), "192.0.2.1")),
		fakeEntry(t, signer(2), trcPrev, now.Add(-time.Minute), bodyAt(signer(2), "192.0.2.2")),
		fakeEntry(t, signer(3), trcN, now.Add(time.Hour), bodyAt(signer(3), "192.0.2.3")),
		fakeEntry(t, signer(4), trcN, now.Add(-time.Minute), bodyAt(signer(4))),
	}
	if n := d.accept(t.Context(), pbs, founderIA, 1); n != len(pbs) {
		t.Fatalf("merged %d, want all %d", n, len(pbs))
	}
	d.pass(now.Add(EntryLifetime))
	got := slices.Sorted(maps.Keys(heldTimes(d)))
	if want := []addr.IA{signer(2), signer(3), signer(4)}; !slices.Equal(got, want) {
		t.Errorf("held after the pass = %v, want %v", got, want)
	}

	verified := ft.verifications()
	ancient := fakeEntry(t, signer(5), trcN, now.Add(-2*EntryLifetime),
		bodyAt(signer(5), "192.0.2.5"))
	if n := d.accept(t.Context(), []*cryptopb.SignedMessage{ancient}, founderIA, 1); n != 0 {
		t.Errorf("merged %d of the ancient entry, want none", n)
	}
	if ft.verifications() != verified {
		t.Errorf("the ancient entry was verified")
	}
}

// TestDirectoryEntryAddresses checks what an entry names: one naming no
// address is a withdrawal, which the view leaves out; one naming two hosts
// carries both, in order; and one naming an address without its rendezvous
// address, or a malformed one, is refused.
func TestDirectoryEntryAddresses(t *testing.T) {
	now := time.Now()
	signer := func(n uint64) addr.IA { return addr.MustIAFrom(20, addr.AS(0xfd0000000400+n)) }
	half := bodyAt(signer(2), "192.0.2.2")
	half.Addresses[0].RendezvousAddr = ""
	malformed := bodyAt(signer(3), "192.0.2.3")
	malformed.Addresses[0].ControlAddr = "nope"
	msgs := []*cryptopb.SignedMessage{
		fakeEntry(t, signer(1), trcN, now, bodyAt(signer(1))),
		fakeEntry(t, signer(2), trcN, now, half),
		fakeEntry(t, signer(3), trcN, now, malformed),
		fakeEntry(t, signer(4), trcN, now, bodyAt(signer(4), "192.0.2.41", "192.0.2.42")),
	}
	d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Trust: &fakeTrust{}})
	id := attachLink(d, 1)
	if n := d.accept(t.Context(), msgs, founderIA, 1); n != 2 {
		t.Fatalf("merged %d, want the withdrawal and the two-host entry", n)
	}
	held := heldIn(d, id)
	if e := held[signer(1)]; e == nil || !e.withdrawn {
		t.Errorf("the entry naming no address is no withdrawal: %+v", e)
	}
	want := []netip.Addr{netip.MustParseAddr("192.0.2.41"), netip.MustParseAddr("192.0.2.42")}
	if e := held[signer(4)]; e == nil || !slices.Equal(hostsOf(e.entry), want) {
		t.Errorf("the two-host entry names %v, want %v", held[signer(4)], want)
	}
	v, _ := d.pass(now)
	if got := slices.Sorted(maps.Keys(v.scopes[id])); !slices.Equal(got, []addr.IA{signer(4)}) {
		t.Errorf("the view shows %v, want the two-host entry alone", got)
	}
}

// TestDirectoryEntryPeers checks the entry's peer reports and its cluster:
// they read back as signed, and an entry naming an interface no hop field
// could carry — its link's or one a retirement relies on — is refused.
func TestDirectoryEntryPeers(t *testing.T) {
	now := time.Now()
	signer := func(n uint64) addr.IA { return addr.MustIAFrom(20, addr.AS(0xfd0000000500+n)) }
	good := bodyAt(signer(1), "192.0.2.1")
	good.Cluster = uint64(signer(2))
	good.Peers = []*nodev1.Peer{
		{IsdAs: uint64(signer(2)), RttUs: 1500, RttLowUs: 1200, RttHighUs: 1900, IfId: 3, Promoting: true},
		{IsdAs: uint64(signer(3)), RttUs: 20000, Retiring: true,
			Relies: []*nodev1.LinkRef{{IsdAs: uint64(signer(2)), IfId: 7}}},
	}
	wideLink := bodyAt(signer(4), "192.0.2.4")
	wideLink.Peers = []*nodev1.Peer{{IsdAs: uint64(signer(1)), RttUs: 1, IfId: 1 << 16}}
	wideReliance := bodyAt(signer(5), "192.0.2.5")
	wideReliance.Peers = []*nodev1.Peer{{IsdAs: uint64(signer(1)), RttUs: 1, Retiring: true,
		Relies: []*nodev1.LinkRef{{IsdAs: uint64(signer(2)), IfId: 1 << 16}}}}
	msgs := []*cryptopb.SignedMessage{
		fakeEntry(t, signer(1), trcN, now, good),
		fakeEntry(t, signer(4), trcN, now, wideLink),
		fakeEntry(t, signer(5), trcN, now, wideReliance),
	}
	d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Trust: &fakeTrust{}})
	id := attachLink(d, 1)
	if n := d.accept(t.Context(), msgs, founderIA, 1); n != 1 {
		t.Fatalf("merged %d, want the well-formed entry alone", n)
	}
	want := []bus.PeerReport{
		{IA: signer(2), RTT: 1500 * time.Microsecond, Low: 1200 * time.Microsecond, High: 1900 * time.Microsecond,
			IfID: 3, Promoting: true},
		{IA: signer(3), RTT: 20 * time.Millisecond, Retiring: true,
			Relies: []segment.LinkID{{IA: signer(2), IfID: 7}}},
	}
	e := heldIn(d, id)[signer(1)]
	if e == nil {
		t.Fatal("the well-formed entry is not held")
	}
	if diff := cmp.Diff(want, e.entry.Peers); diff != "" {
		t.Errorf("peers (-want +got):\n%s", diff)
	}
	if e.entry.Cluster != signer(2) {
		t.Errorf("cluster %v, want %v", e.entry.Cluster, signer(2))
	}
}

// TestSameChanges checks what signs a node's entry again at once: a peer's
// link or announcements, a peer one report omits naming none; round trips
// and their bounds, and peers that name neither, wait for the refresh.
func TestSameChanges(t *testing.T) {
	a, b := addr.MustIAFrom(20, 0xfd0000000601), addr.MustIAFrom(20, 0xfd0000000602)
	held := []bus.PeerReport{
		{IA: a, RTT: 5 * time.Millisecond, IfID: 2},
		{IA: b, RTT: 30 * time.Millisecond},
	}
	relies := []segment.LinkID{{IA: b, IfID: 4}}
	for _, tc := range []struct {
		name string
		want []bus.PeerReport
		same bool
	}{
		{"round trips moved", []bus.PeerReport{
			{IA: a, RTT: 7 * time.Millisecond, IfID: 2}, {IA: b, RTT: 40 * time.Millisecond},
		}, true},
		{"bounds moved", []bus.PeerReport{
			{IA: a, RTT: 5 * time.Millisecond, Low: 4 * time.Millisecond, High: 6 * time.Millisecond, IfID: 2},
			{IA: b, RTT: 30 * time.Millisecond, Low: 28 * time.Millisecond},
		}, true},
		{"an unlinked peer left", []bus.PeerReport{{IA: a, RTT: 5 * time.Millisecond, IfID: 2}}, true},
		{"an unlinked peer joined", append(slices.Clone(held),
			bus.PeerReport{IA: addr.MustIAFrom(20, 0xfd0000000603), RTT: time.Millisecond}), true},
		{"a link left", []bus.PeerReport{
			{IA: a, RTT: 5 * time.Millisecond}, {IA: b, RTT: 30 * time.Millisecond},
		}, false},
		{"a linked peer left", []bus.PeerReport{{IA: b, RTT: 30 * time.Millisecond}}, false},
		{"a link joined", []bus.PeerReport{
			{IA: a, RTT: 5 * time.Millisecond, IfID: 2}, {IA: b, RTT: 30 * time.Millisecond, IfID: 3},
		}, false},
		{"a promotion announced", []bus.PeerReport{
			{IA: a, RTT: 5 * time.Millisecond, IfID: 2},
			{IA: b, RTT: 30 * time.Millisecond, Promoting: true},
		}, false},
		{"a retirement announced", []bus.PeerReport{
			{IA: a, RTT: 5 * time.Millisecond, IfID: 2, Retiring: true, Relies: relies},
			{IA: b, RTT: 30 * time.Millisecond},
		}, false},
	} {
		if got := sameChanges(held, tc.want); got != tc.same {
			t.Errorf("%s: sameChanges = %v, want %v", tc.name, got, tc.same)
		}
	}
	retiring := []bus.PeerReport{{IA: a, RTT: 5 * time.Millisecond, IfID: 2, Retiring: true, Relies: relies}}
	other := []bus.PeerReport{{IA: a, RTT: 5 * time.Millisecond, IfID: 2, Retiring: true,
		Relies: []segment.LinkID{{IA: b, IfID: 5}}}}
	if sameChanges(retiring, other) {
		t.Error("a retirement's changed reliance signs nothing")
	}
	// A retirement stays announced through a window its link's verdict is
	// down, the link named nowhere: its withdrawal signs too.
	down := []bus.PeerReport{{IA: a, RTT: 5 * time.Millisecond, Retiring: true, Relies: relies}}
	if sameChanges(down, []bus.PeerReport{{IA: a, RTT: 5 * time.Millisecond}}) {
		t.Error("a retirement withdrawn while its link is down signs nothing")
	}
}

// TestDirectoryOutranking checks two outrankings: a withdrawal outranks
// its signer's earlier entries, and an entry under a newer TRC outranks a
// runaway one signed far ahead of the clock.
func TestDirectoryOutranking(t *testing.T) {
	now := time.Now()
	d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Trust: &fakeTrust{}})
	id := attachLink(d, 1)
	ctx := t.Context()
	signer := founderIA
	entry := fakeEntry(t, signer, trcN, now.Add(-time.Minute), bodyAt(signer, "192.0.2.1"))
	withdrawal := fakeEntry(t, signer, trcN, now, bodyAt(signer))
	if n := d.accept(ctx, []*cryptopb.SignedMessage{entry, withdrawal}, directoryIA, 1); n != 2 {
		t.Fatalf("merged %d, want the entry and the withdrawal", n)
	}
	if n := d.accept(ctx, []*cryptopb.SignedMessage{entry}, directoryIA, 1); n != 0 {
		t.Errorf("an earlier entry outranked the withdrawal")
	}
	if v, _ := d.pass(now); len(v.scopes[id]) != 0 {
		t.Errorf("the view shows %d entries past the withdrawal, want none", len(v.scopes[id]))
	}

	runaway := addr.MustIAFrom(20, 0xfd0000000042)
	ahead := fakeEntry(t, runaway, trcPrev, now.Add(24*time.Hour), bodyAt(runaway, "192.0.2.2"))
	current := fakeEntry(t, runaway, trcPrev, now, bodyAt(runaway, "192.0.2.3"))
	renewed := fakeEntry(t, runaway, trcN, now, bodyAt(runaway, "192.0.2.4"))
	if n := d.accept(ctx, []*cryptopb.SignedMessage{ahead, current}, directoryIA, 1); n != 1 {
		t.Fatalf("merged %d, want the runaway entry alone", n)
	}
	if n := d.accept(ctx, []*cryptopb.SignedMessage{renewed}, directoryIA, 1); n != 1 {
		t.Fatalf("the entry under the newer TRC did not outrank the runaway one")
	}
	v, _ := d.pass(now)
	if e, ok := v.scopes[id][runaway]; !ok ||
		!slices.Equal(hostsOf(e.entry), []netip.Addr{netip.MustParseAddr("192.0.2.4")}) {
		t.Errorf("the view holds %v for the runaway signer, want the renewed entry", v.scopes[id][runaway])
	}
}

// recordingFetcher serves the founder database's chains, recording the
// server each fetch asked.
type recordingFetcher struct {
	db     trustdb.DB
	mtx    sync.Mutex
	asked  []*scion.Addr
	server net.Addr
}

func (f *recordingFetcher) TRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	return f.db.SignedTRC(ctx, id)
}

func (f *recordingFetcher) Chains(
	ctx context.Context, q trustdb.ChainQuery,
) ([][]*x509.Certificate, error) {

	f.mtx.Lock()
	server, _ := f.server.(*scion.Addr)
	f.asked = append(f.asked, server)
	f.mtx.Unlock()
	return f.db.Chains(ctx, q)
}

// TestDirectoryAcceptance checks acceptance against real chains: an entry
// verifies against the chain valid at its signing time, the chain fetched
// from the neighbor that sent it over the link it arrived on, while an
// altered entry, one whose body names another ISD-AS, and one no chain of
// its signer verifies are refused.
func TestDirectoryAcceptance(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := trusttest.NewFounder(t, openTrustDB(t), founderIA)
		signer := addr.MustIAFrom(20, 0xfd0000000042)
		signerKey, chain := founder.Enroll(t, signer)
		signerEngine := trust.NewEngine(signer, signerKey, &trust.NetworkProvider{DB: founder.DB},
			trusttest.Unchecked{})

		db := openTrustDB(t)
		if _, err := db.InsertTRC(t.Context(), founder.TRC); err != nil {
			t.Fatal(err)
		}
		fetcher := &recordingFetcher{db: founder.DB}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		engine := trust.NewEngine(directoryIA, key, &trust.NetworkProvider{
			DB: db,
			Peer: func(server net.Addr) trust.Fetcher {
				fetcher.mtx.Lock()
				fetcher.server = server
				fetcher.mtx.Unlock()
				return fetcher
			},
		}, trusttest.Unchecked{})
		d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Trust: engine})
		const arrival = 7
		id := attachLink(d, arrival)
		ctx := asNeighbor(t.Context(), signer, arrival)

		// Signed a minute before the chain expires, pushed a minute after.
		time.Sleep(time.Until(chain[0].NotAfter) - time.Minute)
		entry := signEntry(t, signerEngine, bodyAt(signer, "192.0.2.1"))
		altered := proto.Clone(entry).(*cryptopb.SignedMessage)
		altered.HeaderAndBody[len(altered.HeaderAndBody)-1] ^= 1
		impostor := signEntry(t, signerEngine, bodyAt(founderIA, "192.0.2.2"))
		time.Sleep(2 * time.Minute)

		for _, refused := range []*cryptopb.SignedMessage{altered, impostor} {
			if _, err := d.Push(ctx, &nodev1.PushRequest{
				Entries: []*cryptopb.SignedMessage{refused},
			}); err != nil {
				t.Fatal(err)
			}
		}
		if held := heldIn(d, id); len(held) != 0 {
			t.Fatalf("held %d entries after the altered and the impostor, want none", len(held))
		}
		if _, err := d.Push(ctx, &nodev1.PushRequest{
			Entries: []*cryptopb.SignedMessage{entry},
		}); err != nil {
			t.Fatal(err)
		}
		v, _ := d.pass(time.Now())
		if e, ok := v.scopes[id][signer]; !ok ||
			!slices.Equal(hostsOf(e.entry), []netip.Addr{netip.MustParseAddr("192.0.2.1")}) {
			t.Fatalf("the view holds %v for the signer, want the entry", v.scopes[id][signer])
		}
		if len(fetcher.asked) == 0 {
			t.Fatal("no chain was asked of the sender")
		}
		for _, server := range fetcher.asked {
			if server == nil || server.IA != signer || server.IfID != arrival {
				t.Errorf("chains asked of %v, want the sender %v over interface %d",
					server, signer, arrival)
			}
		}

		// A key no chain certifies.
		stranger := addr.MustIAFrom(20, 0xfd0000000043)
		forged := fakeEntry(t, stranger, founder.TRC.TRC.ID, time.Now(),
			bodyAt(stranger, "192.0.2.3"))
		if _, err := d.Push(ctx, &nodev1.PushRequest{
			Entries: []*cryptopb.SignedMessage{forged},
		}); err != nil {
			t.Fatal(err)
		}
		if _, ok := heldIn(d, id)[stranger]; ok {
			t.Error("an entry no chain verifies was held")
		}
	})
}

// TestDirectoryHandlersRefuse checks the service's gates: a request with no
// authenticated ISD-AS, or that arrived over no link, is refused; so is a
// call past the per-call bound, a sync naming no directory or a malformed
// one, and a sync over a link that joins no directory yet.
func TestDirectoryHandlersRefuse(t *testing.T) {
	d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Trust: &fakeTrust{}})
	if _, err := d.Push(t.Context(), &nodev1.PushRequest{}); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("an unauthenticated push = %v, want permission denied", err)
	}
	if _, err := d.Sync(t.Context(), &nodev1.SyncRequest{}); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("an unauthenticated sync = %v, want permission denied", err)
	}
	linkless := context.WithValue(t.Context(), peeria.AuthenticatedIAContextKey(), founderIA)
	if _, err := d.Push(linkless, &nodev1.PushRequest{}); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a push over no link = %v, want permission denied", err)
	}
	ctx := asNeighbor(t.Context(), founderIA, 1)
	if _, err := d.Push(ctx, &nodev1.PushRequest{
		Entries: make([]*cryptopb.SignedMessage, maxEntriesPerCall+1),
	}); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("an oversized push = %v, want resource exhaustion", err)
	}
	if _, err := d.Sync(ctx, &nodev1.SyncRequest{
		Summaries: make([]*nodev1.Summary, maxEntriesPerCall+1),
	}); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("an oversized sync = %v, want resource exhaustion", err)
	}
	if _, err := d.Sync(ctx, &nodev1.SyncRequest{}); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a sync naming no directory = %v, want an invalid argument", err)
	}
	if _, err := d.Sync(ctx, &nodev1.SyncRequest{Directory: []byte{1, 2, 3}}); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a sync naming a 3-byte directory = %v, want an invalid argument", err)
	}
	named := bus.DirectoryID{1}
	if _, err := d.Sync(ctx, &nodev1.SyncRequest{Directory: named[:]}); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a sync over an unattached link = %v, want a failed precondition", err)
	}
}

// TestDirectorySyncKeepsTheLesserID checks the sync's handler: the link's
// attachment takes the request's directory ID when it is the lesser and
// keeps its own otherwise, and the reply names the ID it keeps.
func TestDirectorySyncKeepsTheLesserID(t *testing.T) {
	d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Trust: &fakeTrust{}})
	d.mint = counterIDs(0xf0)
	d.attach(3, netip.MustParseAddr("203.0.113.9"))
	ctx := asNeighbor(t.Context(), founderIA, 3)
	lesser := bus.DirectoryID{1}
	resp, err := d.Sync(ctx, &nodev1.SyncRequest{Directory: lesser[:]})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := parseDirectoryID(resp.Directory); got != lesser {
		t.Errorf("the reply names directory %v, want the request's lesser %v", got, lesser)
	}
	if id, ok := d.linkID(3); !ok || id != lesser {
		t.Errorf("the link joins %v (%t), want %v", id, ok, lesser)
	}

	greater := bus.DirectoryID{0xfe}
	resp, err = d.Sync(ctx, &nodev1.SyncRequest{Directory: greater[:]})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := parseDirectoryID(resp.Directory); got != lesser {
		t.Errorf("after a greater ID the reply names %v, want %v kept", got, lesser)
	}
}

// TestDirectorySyncWithKeepsTheLesserID checks the sync's caller: its
// request names its end's directory ID, which the callee takes when it is
// the lesser, and it takes the ID the reply names when that one is.
func TestDirectorySyncWithKeepsTheLesserID(t *testing.T) {
	f := newFabric()
	a := f.addTrusting(addr.MustIAFrom(20, 0xfd0000000071), &fakeTrust{}, "192.0.2.71")
	b := f.addTrusting(addr.MustIAFrom(20, 0xfd0000000072), &fakeTrust{}, "192.0.2.72")
	c := f.addTrusting(addr.MustIAFrom(20, 0xfd0000000073), &fakeTrust{}, "192.0.2.73")
	a.dir.mint, b.dir.mint, c.dir.mint = counterIDs(0x10), counterIDs(0x20), counterIDs(0x30)
	f.link(a, b)
	f.link(b, c)
	attached := func(n *fabricNode, neighbor addr.IA) bus.DirectoryID {
		t.Helper()
		id, ok := n.dir.linkID(n.ifIDs[neighbor])
		if !ok {
			t.Fatalf("%v's link to %v joins no directory", n.ia, neighbor)
		}
		return id
	}

	if err := b.dir.syncWith(t.Context(), b.ifIDs[a.ia], a.ia); err != nil {
		t.Fatal(err)
	}
	lesser := attached(a, b.ia)
	if got := attached(b, a.ia); got != lesser {
		t.Errorf("the caller's link joins %v, want the callee's lesser %v", got, lesser)
	}
	if err := b.dir.syncWith(t.Context(), b.ifIDs[c.ia], c.ia); err != nil {
		t.Fatal(err)
	}
	if got := attached(c, b.ia); got != lesser {
		t.Errorf("the callee's link joins %v, want the caller's lesser %v", got, lesser)
	}
}

// TestDirectoryAttachments checks the attachments' lifetime: links group by
// the host their peers report, each host's attachment naming a directory of
// its own; an attachment whose links have all gone stays while its
// directory holds an entry, named in no entry of the node's own, and goes,
// with the directory, once that entry does.
func TestDirectoryAttachments(t *testing.T) {
	now := time.Now()
	state := new(bus.Topic[bus.LinkState])
	live := func(ifIDs ...uint16) {
		var ls []bus.Link
		for _, ifID := range ifIDs {
			ls = append(ls, bus.Link{Entry: links.Link{
				IfID: ifID, NeighborIA: addr.MustIAFrom(20, addr.AS(0xfd0000000600+uint64(ifID))),
				State: links.StateEstablished,
			}})
		}
		state.Publish(bus.NewLinkState(ls...))
	}
	live(1, 2, 3)
	d := NewNodeDirectory(NodeDirectoryConfig{
		IA: directoryIA, Trust: &fakeTrust{}, Links: state, Addresses: plainAddresses,
	})
	d.mint = counterIDs(0xf0)
	hostA, hostB := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")
	idA := d.attach(1, hostA)
	if got := d.attach(2, hostA); got != idA {
		t.Errorf("a second link at the host joins %v, want the host's %v", got, idA)
	}
	idB := d.attach(3, hostB)
	if idB == idA {
		t.Fatalf("two hosts' attachments name one directory, %v", idA)
	}
	if got := d.attach(2, hostB); got != idB {
		t.Errorf("the moved link joins %v, want the new host's %v", got, idB)
	}

	signer := addr.MustIAFrom(20, 0xfd0000000042)
	if n := d.accept(t.Context(), []*cryptopb.SignedMessage{
		fakeEntry(t, signer, trcN, now, bodyAt(signer, "192.0.2.9")),
	}, signer, 1); n != 1 {
		t.Fatalf("merged %d, want 1", n)
	}
	live(2, 3)
	d.pass(now)
	if _, ok := d.attachments[hostA]; !ok || heldIn(d, idA) == nil {
		t.Fatal("the attachment whose links went is gone while its directory holds an entry")
	}
	if _, ok := d.linkID(1); ok {
		t.Error("the gone link still joins a directory")
	}
	bodies, err := d.ownBodies()
	if err != nil {
		t.Fatal(err)
	}
	if body, ok := bodies[idB]; len(bodies) != 1 || !ok || len(body.Addresses) != 1 ||
		body.Addresses[0].RendezvousAddr != netip.AddrPortFrom(hostB, RendezvousPort).String() {
		t.Errorf("the node's entries = %v, want one in %v naming its linked host alone", bodies, idB)
	}
	d.pass(now.Add(2 * EntryLifetime))
	if _, ok := d.attachments[hostA]; ok || heldIn(d, idA) != nil {
		t.Error("the attachment with no link and no entry stays")
	}
	if _, ok := d.attachments[hostB]; !ok {
		t.Error("the attachment holding links went")
	}
}

// TestDirectoryMergeJoinsDirectories checks a merge at one node: when one
// attachment's directory ID gives way to another attachment's lesser one,
// the greater ID's directory joins the lesser's signer by signer, the merge
// wakes the catch-up of every link, and the node signs one entry there
// naming both hosts, ordered.
func TestDirectoryMergeJoinsDirectories(t *testing.T) {
	founder := newFounded(t)
	d := NewNodeDirectory(NodeDirectoryConfig{
		IA: directoryIA, Trust: founder.Engine(t, directoryIA), Addresses: plainAddresses,
	})
	d.mint = counterIDs(0xf0)
	hostA, hostB := netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("198.51.100.1")
	idA := d.attach(1, hostA)
	idB := d.attach(2, hostB)
	s, u := addr.MustIAFrom(20, 0xfd0000000042), addr.MustIAFrom(20, 0xfd0000000043)
	at := time.Now()
	entry := func(signer addr.IA, at time.Time) *signedEntry {
		return &signedEntry{signer: signer, key: entryKey{trc: trcN, signedAt: at, signed: []byte{1}}}
	}
	older, newer, only := entry(s, at), entry(s, at.Add(time.Second)), entry(u, at)
	d.mergeOver(1, older)
	d.mergeOver(1, only)
	d.mergeOver(2, newer)
	select {
	case <-d.catchUp:
	default:
	}

	if got, _ := d.adopt(2, idA); got != idA {
		t.Fatalf("the link whose peer names %v joins %v", idA, got)
	}
	held := heldIn(d, idA)
	if held[s] != newer || held[u] != only {
		t.Errorf("the joined directory holds %v and %v, want each signer's greatest", held[s], held[u])
	}
	if heldIn(d, idB) != nil {
		t.Error("the greater ID still names a directory")
	}
	select {
	case <-d.catchUp:
	default:
		t.Error("the merge woke no catch-up")
	}
	if _, err := d.signScopes(t.Context()); err != nil {
		t.Fatal(err)
	}
	own := heldIn(d, idA)[directoryIA]
	if own == nil || !slices.Equal(hostsOf(own.entry), []netip.Addr{hostB, hostA}) {
		t.Errorf("the node's entry = %v, want both hosts in order", own)
	}
}

// fabric is an in-process one-hop channel between directories: a node's
// client reaches the neighbor its link names, each request carrying the
// caller as its authenticated ISD-AS and the link's far interface as its
// arrival, and each node's link state observes each neighbor at the host
// the node sees it at.
type fabric struct {
	mtx   sync.Mutex
	nodes map[addr.IA]*fabricNode
	calls []call
	// cut holds the pairs whose calls fail.
	cut map[[2]addr.IA]bool
	// seen holds the host each node sees each neighbor at, by observer and
	// observed.
	seen map[[2]addr.IA]netip.Addr
}

// call is one request the fabric carried.
type call struct {
	from, to addr.IA
	method   string
}

// fabricNode is one node of the fabric.
type fabricNode struct {
	ia      addr.IA
	host    netip.Addr
	engine  *trust.Engine
	dir     *NodeDirectory
	links   *bus.Topic[bus.LinkState]
	view    *bus.Topic[bus.Directory]
	handler http.Handler
	// ifIDs holds the interface of the link reaching each neighbor, and
	// lastIfID the interface the node allocated last.
	ifIDs    map[addr.IA]uint16
	lastIfID uint16
}

func newFabric() *fabric {
	return &fabric{
		nodes: make(map[addr.IA]*fabricNode),
		cut:   make(map[[2]addr.IA]bool),
		seen:  make(map[[2]addr.IA]netip.Addr),
	}
}

// add builds a node signing with the engine, at the host.
func (f *fabric) add(ia addr.IA, engine *trust.Engine, host string) *fabricNode {
	n := f.addTrusting(ia, engine, host)
	n.engine = engine
	return n
}

// addTrusting builds a node of the trust given, at the host.
func (f *fabric) addTrusting(ia addr.IA, trust DirectoryTrust, host string) *fabricNode {
	n := &fabricNode{
		ia:    ia,
		host:  netip.MustParseAddr(host),
		links: new(bus.Topic[bus.LinkState]),
		view:  new(bus.Topic[bus.Directory]),
		ifIDs: make(map[addr.IA]uint16),
	}
	n.links.Publish(bus.NewLinkState())
	n.dir = NewNodeDirectory(NodeDirectoryConfig{
		IA:        ia,
		Addresses: plainAddresses,
		Trust:     trust,
		Links:     n.links,
		Peer:      fabricPeer{f: f, from: ia},
		Directory: n.view,
	})
	server := connect.NewServer()
	nodev1connect.RegisterDirectoryServiceHandler(server, n.dir)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	n.handler = mux
	f.mtx.Lock()
	f.nodes[ia] = n
	f.mtx.Unlock()
	return n
}

// addEnrolled builds a node of the ISD-AS whose AS number ends in n,
// enrolled under the founder, at the host 192.0.2.n.
func (f *fabric) addEnrolled(t *testing.T, founder *trusttest.Founder, n byte) *fabricNode {
	t.Helper()
	ia := addr.MustIAFrom(20, addr.AS(0xfd0000000000+uint64(n)))
	return f.add(ia, founder.Engine(t, ia), netip.AddrFrom4([4]byte{192, 0, 2, n}).String())
}

// link links the two nodes, each seeing the other at its own host.
func (f *fabric) link(a, b *fabricNode) {
	f.linkVia(a, b, a.host, b.host)
}

// linkVia links the two nodes, b seeing a at aSeen and a seeing b at bSeen,
// and reports each end the host the other sees it at, as the link's
// exchange does.
func (f *fabric) linkVia(a, b *fabricNode, aSeen, bSeen netip.Addr) {
	f.connect(a, b, aSeen, bSeen)
	f.report(a, b.ia)
	f.report(b, a.ia)
}

// report tells the node the host the neighbor sees it at on their link, as
// the link's exchange does.
func (f *fabric) report(n *fabricNode, neighbor addr.IA) {
	f.mtx.Lock()
	ifID, seen := n.ifIDs[neighbor], f.seen[[2]addr.IA{neighbor, n.ia}]
	f.mtx.Unlock()
	n.dir.attach(ifID, seen)
}

// connect links the two nodes, b seeing a at aSeen and a seeing b at
// bSeen, and publishes both ends' link state; neither end hears what the
// other sees.
func (f *fabric) connect(a, b *fabricNode, aSeen, bSeen netip.Addr) {
	f.mtx.Lock()
	a.lastIfID++
	b.lastIfID++
	a.ifIDs[b.ia] = a.lastIfID
	b.ifIDs[a.ia] = b.lastIfID
	f.seen[[2]addr.IA{b.ia, a.ia}] = aSeen
	f.seen[[2]addr.IA{a.ia, b.ia}] = bSeen
	f.mtx.Unlock()
	f.publishLinks(a)
	f.publishLinks(b)
}

// unlink takes the link between the two nodes away at both ends.
func (f *fabric) unlink(a, b *fabricNode) {
	f.mtx.Lock()
	delete(a.ifIDs, b.ia)
	delete(b.ifIDs, a.ia)
	f.mtx.Unlock()
	f.publishLinks(a)
	f.publishLinks(b)
}

// move moves the node to the host: each neighbor that saw it at its old
// host sees it at the new one, and reports it.
func (f *fabric) move(n *fabricNode, host string) {
	f.mtx.Lock()
	old := n.host
	n.host = netip.MustParseAddr(host)
	var neighbors []*fabricNode
	for neighbor := range n.ifIDs {
		if key := [2]addr.IA{neighbor, n.ia}; f.seen[key] == old {
			f.seen[key] = n.host
		}
		neighbors = append(neighbors, f.nodes[neighbor])
	}
	f.mtx.Unlock()
	for _, neighbor := range neighbors {
		f.publishLinks(neighbor)
		f.report(n, neighbor.ia)
	}
}

func (f *fabric) publishLinks(n *fabricNode) {
	f.mtx.Lock()
	var ls []bus.Link
	for neighbor, ifID := range n.ifIDs {
		ls = append(ls, bus.Link{
			Entry: links.Link{IfID: ifID, NeighborIA: neighbor, State: links.StateEstablished},
			// The port is the far end's link socket; the attachments read the
			// host alone.
			Observed: netip.AddrPortFrom(f.seen[[2]addr.IA{n.ia, neighbor}], 40000+ifID),
		})
	}
	f.mtx.Unlock()
	n.links.Publish(bus.NewLinkState(ls...))
}

// settleIDs has each end of every link keep the lesser of the two ends'
// directory IDs, as their syncs do, until no ID changes.
func (f *fabric) settleIDs(t *testing.T) {
	t.Helper()
	type end struct {
		n, neighbor *fabricNode
	}
	f.mtx.Lock()
	var ends []end
	for _, ia := range slices.Sorted(maps.Keys(f.nodes)) {
		n := f.nodes[ia]
		for _, neighbor := range slices.Sorted(maps.Keys(n.ifIDs)) {
			ends = append(ends, end{n: n, neighbor: f.nodes[neighbor]})
		}
	}
	f.mtx.Unlock()
	for changed := true; changed; {
		changed = false
		for _, e := range ends {
			theirs, ok := e.neighbor.dir.linkID(e.neighbor.ifIDs[e.n.ia])
			if !ok {
				t.Fatalf("%v's link to %v joins no directory", e.neighbor.ia, e.n.ia)
			}
			before, _ := e.n.dir.linkID(e.n.ifIDs[e.neighbor.ia])
			if after, _ := e.n.dir.adopt(e.n.ifIDs[e.neighbor.ia], theirs); after != before {
				changed = true
			}
		}
	}
}

// pushes returns the pushes the fabric carried from one node to another.
func (f *fabric) pushes(from, to addr.IA) int {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.from == from && c.to == to && c.method == "Push" {
			n++
		}
	}
	return n
}

// roundTrip carries the caller's request to the neighbor its authority
// names.
func (f *fabric) roundTrip(from addr.IA, r *http.Request) (*http.Response, error) {
	f.mtx.Lock()
	caller := f.nodes[from]
	var target *fabricNode
	for neighbor, ifID := range caller.ifIDs {
		authority := scionrpc.PeerAuthority(&scion.Addr{IA: neighbor, Service: addr.SvcCS, IfID: ifID})
		if authority == r.URL.Host {
			target = f.nodes[neighbor]
		}
	}
	if target == nil || f.cut[[2]addr.IA{from, target.ia}] {
		f.mtx.Unlock()
		return nil, errors.New("no link serves the authority")
	}
	arrival := target.ifIDs[from]
	f.calls = append(f.calls, call{from: from, to: target.ia, method: path.Base(r.URL.Path)})
	f.mtx.Unlock()
	w := httptest.NewRecorder()
	target.handler.ServeHTTP(w, r.WithContext(asNeighbor(r.Context(), from, arrival)))
	return w.Result(), nil
}

// fabricPeer is one node's channel over the fabric.
type fabricPeer struct {
	f    *fabric
	from addr.IA
}

func (p fabricPeer) VerifiedClient() *http.Client { return p.OneHopClient() }

func (p fabricPeer) OneHopClient() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return p.f.roundTrip(p.from, r)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// run runs the node's directory until the test's end.
func (n *fabricNode) run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		n.dir.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// shown returns the host each node's entry names first in the node's views,
// by ISD-AS, the view of the least directory ID that shows one winning.
func (n *fabricNode) shown() map[addr.IA]netip.Addr {
	out := make(map[addr.IA]netip.Addr)
	for _, s := range n.view.Latest().Scopes() {
		for _, e := range s.Entries() {
			if _, ok := out[e.IA]; !ok && len(e.Addresses) != 0 {
				out[e.IA] = e.Addresses[0].RendezvousAddr.Addr()
			}
		}
	}
	return out
}

// shownIn returns the hosts each node's entry names in the node's view of
// the directory, by ISD-AS.
func (n *fabricNode) shownIn(id bus.DirectoryID) map[addr.IA][]netip.Addr {
	out := make(map[addr.IA][]netip.Addr)
	s, _ := n.view.Latest().Scope(id)
	for _, e := range s.Entries() {
		out[e.IA] = hostsOf(e)
	}
	return out
}

// scopeOf returns the directory the node's link to the neighbor joins.
func (n *fabricNode) scopeOf(neighbor addr.IA) bus.DirectoryID {
	id, _ := n.view.Latest().LinkScope(n.ifIDs[neighbor])
	return id
}

// newFounded founds an ISD over a fresh trust database.
func newFounded(t *testing.T) *trusttest.Founder {
	t.Helper()
	return trusttest.NewFounder(t, openTrustDB(t), founderIA)
}

// TestDirectoryFloods checks the flooding: an accepted greater entry is
// pushed to every neighbor of its directory but its sender, and a lesser
// one to none.
func TestDirectoryFloods(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := newFounded(t)
		f := newFabric()
		a, b, c, d := f.addEnrolled(t, founder, 0xa1), f.addEnrolled(t, founder, 0xb1),
			f.addEnrolled(t, founder, 0xc1), f.addEnrolled(t, founder, 0xd1)
		f.link(a, b)
		f.link(b, c)
		f.link(b, d)
		f.settleIDs(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go b.dir.runForward(ctx)

		older := signEntry(t, a.engine, bodyAt(a.ia, "192.0.2.91"))
		time.Sleep(time.Second)
		newer := signEntry(t, a.engine, bodyAt(a.ia, "192.0.2.92"))
		push := func(e *cryptopb.SignedMessage) {
			t.Helper()
			if _, err := b.dir.Push(asNeighbor(ctx, a.ia, b.ifIDs[a.ia]), &nodev1.PushRequest{
				Entries: []*cryptopb.SignedMessage{e},
			}); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
		}
		push(newer)
		for _, n := range []*fabricNode{c, d} {
			if got := heldTimes(n.dir)[a.ia]; got.IsZero() {
				t.Errorf("%v holds no entry of the signer after the flood", n.ia)
			}
			if got := f.pushes(b.ia, n.ia); got != 1 {
				t.Errorf("pushes from %v to %v = %d, want 1", b.ia, n.ia, got)
			}
		}
		if got := f.pushes(b.ia, a.ia); got != 0 {
			t.Errorf("pushes back to the sender = %d, want none", got)
		}

		time.Sleep(EntryForwardBound)
		push(older)
		for n, want := range map[*fabricNode]int{a: 0, c: 1, d: 1} {
			if got := f.pushes(b.ia, n.ia); got != want {
				t.Errorf("pushes from %v to %v after a lesser entry = %d, want %d",
					b.ia, n.ia, got, want)
			}
		}
	})
}

// TestDirectoryForwardingBound checks the forwarding bound: a signer
// signing in a loop costs each link one entry per bound, and its latest
// entry travels at the bound's end.
func TestDirectoryForwardingBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := newFounded(t)
		f := newFabric()
		a, b, c := f.addEnrolled(t, founder, 0xa1), f.addEnrolled(t, founder, 0xb1),
			f.addEnrolled(t, founder, 0xc1)
		f.link(a, b)
		f.link(b, c)
		f.settleIDs(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go b.dir.runForward(ctx)

		var last time.Time
		for i := range 10 {
			host := netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}).String()
			e := signEntry(t, a.engine, bodyAt(a.ia, host))
			if _, err := b.dir.Push(asNeighbor(ctx, a.ia, b.ifIDs[a.ia]), &nodev1.PushRequest{
				Entries: []*cryptopb.SignedMessage{e},
			}); err != nil {
				t.Fatal(err)
			}
			last = time.Now()
			time.Sleep(100 * time.Millisecond)
		}
		synctest.Wait()
		if got := f.pushes(b.ia, c.ia); got != 1 {
			t.Errorf("pushes within the bound = %d, want 1", got)
		}
		time.Sleep(EntryForwardBound)
		synctest.Wait()
		if got := f.pushes(b.ia, c.ia); got != 2 {
			t.Errorf("pushes once the bound ended = %d, want 2", got)
		}
		if got := heldTimes(c.dir)[a.ia]; !got.Equal(last) {
			t.Errorf("the neighbor holds the entry signed at %v, want the latest at %v", got, last)
		}
	})
}

// TestDirectorySync checks the sync: each side ends holding what the other
// held greater, a tie of TRC and signing time resolved by the signed bytes.
func TestDirectorySync(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := newFounded(t)
		f := newFabric()
		x, y := f.addEnrolled(t, founder, 0xa1), f.addEnrolled(t, founder, 0xb1)
		f.link(x, y)
		f.settleIDs(t)
		s1, s2, s3, s4 := addr.MustIAFrom(20, 0xfd0000000301), addr.MustIAFrom(20, 0xfd0000000302),
			addr.MustIAFrom(20, 0xfd0000000303), addr.MustIAFrom(20, 0xfd0000000304)
		engines := map[addr.IA]*trust.Engine{}
		for _, s := range []addr.IA{s1, s2, s3, s4} {
			engines[s] = founder.Engine(t, s)
		}
		older1 := signEntry(t, engines[s1], bodyAt(s1, "192.0.2.11"))
		// The fake clock stands still between these two: a tie of TRC and
		// signing time.
		tieA := signEntry(t, engines[s4], bodyAt(s4, "192.0.2.41"))
		tieB := signEntry(t, engines[s4], bodyAt(s4, "192.0.2.42"))
		time.Sleep(time.Second)
		newer1 := signEntry(t, engines[s1], bodyAt(s1, "192.0.2.12"))
		e2 := signEntry(t, engines[s2], bodyAt(s2, "192.0.2.21"))
		e3 := signEntry(t, engines[s3], bodyAt(s3, "192.0.2.31"))
		merge := func(n *fabricNode, neighbor addr.IA, entries ...*cryptopb.SignedMessage) {
			t.Helper()
			if n.dir.accept(t.Context(), entries, neighbor, n.ifIDs[neighbor]) != len(entries) {
				t.Fatalf("%v did not merge every entry", n.ia)
			}
		}
		merge(x, y.ia, newer1, e2, tieA)
		merge(y, x.ia, older1, e3, tieB)

		if err := x.dir.syncWith(t.Context(), x.ifIDs[y.ia], y.ia); err != nil {
			t.Fatal(err)
		}
		want := heldTimes(x.dir)
		if diff := cmp.Diff(want, heldTimes(y.dir)); diff != "" {
			t.Errorf("the two sides differ after the sync (-x +y):\n%s", diff)
		}
		if len(want) != 4 {
			t.Errorf("the sides hold %d signers, want 4", len(want))
		}
		for _, ends := range [][2]*fabricNode{{x, y}, {y, x}} {
			n, other := ends[0], ends[1]
			id, _ := n.dir.linkID(n.ifIDs[other.ia])
			held := heldIn(n.dir, id)
			if got := hostsOf(held[s1].entry); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.12")}) {
				t.Errorf("%v holds %v of the first signer, want the newer entry", n.ia, got)
			}
			greater := tieA.HeaderAndBody
			if string(tieB.HeaderAndBody) > string(greater) {
				greater = tieB.HeaderAndBody
			}
			if string(held[s4].key.signed) != string(greater) {
				t.Errorf("%v holds the lesser of the tied entries", n.ia)
			}
		}
	})
}

// addrs compares addresses.
var addrs = cmpopts.EquateComparable(netip.Addr{})

// TestDirectoryReplicatesAlongLinks checks the directory over running
// nodes in a line: every node's view holds every node's entry; a node whose
// neighbor sees it at another host names that host at the far end; a node
// that comes back with an empty directory, holding no entry before its
// link, holds every entry once its link is up; and a node that stops on
// purpose leaves every view.
func TestDirectoryReplicatesAlongLinks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := newFounded(t)
		f := newFabric()
		a, b, c := f.addEnrolled(t, founder, 0xa1), f.addEnrolled(t, founder, 0xb1),
			f.addEnrolled(t, founder, 0xc1)
		nodes := []*fabricNode{a, b, c}
		for _, n := range nodes {
			n.run(t)
		}
		f.link(a, b)
		f.link(b, c)
		synctest.Wait()
		want := map[addr.IA]netip.Addr{
			a.ia: netip.MustParseAddr("192.0.2.161"),
			b.ia: netip.MustParseAddr("192.0.2.177"),
			c.ia: netip.MustParseAddr("192.0.2.193"),
		}
		for _, n := range nodes {
			if diff := cmp.Diff(want, n.shown(), addrs); diff != "" {
				t.Errorf("%v's view (-want +got):\n%s", n.ia, diff)
			}
		}

		// Past the forwarding bound of the entries the links' first sync
		// delivered.
		time.Sleep(EntryForwardBound)
		f.move(c, "203.0.113.3")
		synctest.Wait()
		if got := a.shown()[c.ia]; got != netip.MustParseAddr("203.0.113.3") {
			t.Errorf("the far end shows %v for the moved node, want its new host", got)
		}

		// The far end comes back empty: its first link fills it.
		f.unlink(b, c)
		fresh := f.add(c.ia, c.engine, "203.0.113.3")
		fresh.run(t)
		synctest.Wait()
		if got := len(fresh.shown()); got != 0 {
			t.Errorf("the returning node shows %d entries before its link, want none", got)
		}
		f.link(b, fresh)
		synctest.Wait()
		want[c.ia] = netip.MustParseAddr("203.0.113.3")
		if diff := cmp.Diff(want, fresh.shown(), addrs); diff != "" {
			t.Errorf("the returning node's view (-want +got):\n%s", diff)
		}

		// A change just before the withdrawal holds the node's forwards for
		// a bound; the withdrawal reaches its neighbor past it, at once.
		time.Sleep(EntryForwardBound)
		f.move(a, "203.0.113.1")
		synctest.Wait()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		a.dir.Withdraw(ctx)
		synctest.Wait()
		if _, ok := b.shown()[a.ia]; ok {
			t.Error("the neighbor shows the withdrawn node within the forwarding bound")
		}
		time.Sleep(EntryForwardBound)
		synctest.Wait()
		delete(want, a.ia)
		for _, n := range []*fabricNode{b, fresh} {
			if diff := cmp.Diff(want, n.shown(), addrs); diff != "" {
				t.Errorf("%v's view after the withdrawal (-want +got):\n%s", n.ia, diff)
			}
		}
		time.Sleep(EntryRefreshInterval)
		synctest.Wait()
		if _, ok := b.shown()[a.ia]; ok {
			t.Error("the withdrawn node signed an entry after its withdrawal")
		}
	})
}

// TestDirectoryScopes checks scopes over running nodes: two nodes behind
// one translator, linked to each other and to a node outside that sees both
// at the translator's address. Each of the two holds an outside directory,
// whose ID it shares with the outside node, and a site directory, shared
// between them alone; the site directory names their inside addresses, and
// no directory the outside node holds ever names one. A withdrawal reaches
// every directory of its signer.
func TestDirectoryScopes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := newFounded(t)
		f := newFabric()
		gateway := netip.MustParseAddr("203.0.113.1")
		insideA, insideB := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
		o := f.addEnrolled(t, founder, 0x10)
		aIA, bIA := addr.MustIAFrom(20, 0xfd00000000a1), addr.MustIAFrom(20, 0xfd00000000b1)
		a := f.add(aIA, founder.Engine(t, aIA), insideA.String())
		b := f.add(bIA, founder.Engine(t, bIA), insideB.String())
		for _, n := range []*fabricNode{o, a, b} {
			n.run(t)
		}
		f.linkVia(o, a, o.host, gateway)
		f.linkVia(o, b, o.host, gateway)
		f.link(a, b)
		synctest.Wait()

		outside := o.scopeOf(a.ia)
		if got := o.view.Latest().Scopes(); len(got) != 1 {
			t.Errorf("the outside node holds %d directories, want 1", len(got))
		}
		want := map[addr.IA][]netip.Addr{o.ia: {o.host}, a.ia: {gateway}, b.ia: {gateway}}
		if diff := cmp.Diff(want, o.shownIn(outside), addrs); diff != "" {
			t.Errorf("the outside view (-want +got):\n%s", diff)
		}
		site := a.scopeOf(b.ia)
		if site == outside {
			t.Fatalf("the site's directory is the outside one, %v", site)
		}
		for _, n := range []*fabricNode{a, b} {
			if got := n.scopeOf(o.ia); got != outside {
				t.Errorf("%v's outside link joins %v, want %v", n.ia, got, outside)
			}
			if diff := cmp.Diff(want, n.shownIn(outside), addrs); diff != "" {
				t.Errorf("%v's outside view (-want +got):\n%s", n.ia, diff)
			}
		}
		if got := b.scopeOf(a.ia); got != site {
			t.Errorf("the two inside ends join %v and %v", site, got)
		}
		wantSite := map[addr.IA][]netip.Addr{a.ia: {insideA}, b.ia: {insideB}}
		for _, n := range []*fabricNode{a, b} {
			if diff := cmp.Diff(wantSite, n.shownIn(site), addrs); diff != "" {
				t.Errorf("%v's site view (-want +got):\n%s", n.ia, diff)
			}
		}
		o.dir.mtx.Lock()
		for id, s := range o.dir.scopes {
			for _, e := range s.entries {
				for _, host := range hostsOf(e.entry) {
					if host == insideA || host == insideB {
						t.Errorf("the outside node holds %v's inside address in %v", e.signer, id)
					}
				}
			}
		}
		o.dir.mtx.Unlock()

		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		a.dir.Withdraw(ctx)
		synctest.Wait()
		if _, ok := o.shownIn(outside)[a.ia]; ok {
			t.Error("the outside node shows the withdrawn node")
		}
		// The outside node forwards the withdrawal past the bound its
		// forward of the node's entry started.
		time.Sleep(EntryForwardBound)
		synctest.Wait()
		for _, id := range []bus.DirectoryID{outside, site} {
			if _, ok := b.shownIn(id)[a.ia]; ok {
				t.Errorf("the inside neighbor shows the withdrawn node in %v", id)
			}
		}
	})
}

// TestDirectorySyncsALinkOnceAttached checks the catch-up's wake on an
// attachment: a link whose syncs failed while its ends knew no host syncs
// as soon as its ends attach, rather than at the retry, and its two ends
// keep one ID.
func TestDirectorySyncsALinkOnceAttached(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFabric()
		a := f.addTrusting(addr.MustIAFrom(20, 0xfd0000000081), &fakeTrust{}, "192.0.2.81")
		b := f.addTrusting(addr.MustIAFrom(20, 0xfd0000000082), &fakeTrust{}, "192.0.2.82")
		a.run(t)
		b.run(t)
		f.connect(a, b, a.host, b.host)
		synctest.Wait()
		f.report(a, b.ia)
		f.report(b, a.ia)
		synctest.Wait()
		ida, _ := a.dir.linkID(a.ifIDs[b.ia])
		idb, _ := b.dir.linkID(b.ifIDs[a.ia])
		if ida != idb {
			t.Errorf("the link's ends name %v and %v, want one ID before any retry", ida, idb)
		}
	})
}

// TestDirectoryNamesEveryHostOfAScope checks a node one network sees at two
// hosts: its two attachments' IDs merge through that network, and its one
// entry there names both hosts.
func TestDirectoryNamesEveryHostOfAScope(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := newFounded(t)
		f := newFabric()
		first, second := netip.MustParseAddr("203.0.113.11"), netip.MustParseAddr("203.0.113.12")
		q1, q2 := f.addEnrolled(t, founder, 0x21), f.addEnrolled(t, founder, 0x22)
		pIA := addr.MustIAFrom(20, 0xfd00000000a5)
		p := f.add(pIA, founder.Engine(t, pIA), "10.0.0.5")
		for _, n := range []*fabricNode{q1, q2, p} {
			n.run(t)
		}
		f.link(q1, q2)
		f.linkVia(q1, p, q1.host, first)
		f.linkVia(q2, p, q2.host, second)
		// The node signs anew once its clock passes its entry's signing, and
		// its forward waits out the bound its first entry's forward started.
		time.Sleep(EntryForwardBound)
		synctest.Wait()

		if got := p.view.Latest().Scopes(); len(got) != 1 {
			t.Errorf("the node seen at two hosts holds %d directories, want 1", len(got))
		}
		if got := q1.shownIn(q1.scopeOf(p.ia))[p.ia]; !slices.Equal(got, []netip.Addr{first, second}) {
			t.Errorf("the network's view names %v for the node, want both hosts", got)
		}
	})
}

// TestDirectoryIDsConverge checks the IDs along a line of links: the syncs,
// run in any order, leave every attachment naming the least ID minted; and
// a node that comes back with a fresh directory adopts that ID, which
// stays.
func TestDirectoryIDsConverge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := newFounded(t)
		f := newFabric()
		nodes := []*fabricNode{f.addEnrolled(t, founder, 0xa1), f.addEnrolled(t, founder, 0xb1),
			f.addEnrolled(t, founder, 0xc1), f.addEnrolled(t, founder, 0xd1)}
		for i := 1; i < len(nodes); i++ {
			f.link(nodes[i-1], nodes[i])
		}
		rng := mrand.New(mrand.NewPCG(5, 6))
		syncRandomly := func(nodes []*fabricNode) {
			t.Helper()
			for range 60 {
				i := rng.IntN(len(nodes) - 1)
				from, to := nodes[i], nodes[i+1]
				if rng.IntN(2) == 0 {
					from, to = to, from
				}
				if err := from.dir.syncWith(t.Context(), from.ifIDs[to.ia], to.ia); err != nil {
					t.Fatal(err)
				}
			}
		}
		ids := func(nodes []*fabricNode) map[addr.IA]bus.DirectoryID {
			out := make(map[addr.IA]bus.DirectoryID)
			for _, n := range nodes {
				n.dir.mtx.Lock()
				for _, a := range n.dir.attachments {
					out[n.ia] = a.id
				}
				n.dir.mtx.Unlock()
			}
			return out
		}
		syncRandomly(nodes)
		got := ids(nodes)
		least := slices.MinFunc(slices.Collect(maps.Values(got)), bus.DirectoryID.Compare)
		for ia, id := range got {
			if id != least {
				t.Errorf("%v's attachment names %v, want the least %v", ia, id, least)
			}
		}

		f.unlink(nodes[1], nodes[2])
		f.unlink(nodes[2], nodes[3])
		fresh := f.add(nodes[2].ia, nodes[2].engine, nodes[2].host.String())
		f.link(nodes[1], fresh)
		f.link(fresh, nodes[3])
		line := []*fabricNode{nodes[0], nodes[1], fresh, nodes[3]}
		syncRandomly(line)
		for ia, id := range ids(line) {
			if id != least {
				t.Errorf("after the return %v's attachment names %v, want %v", ia, id, least)
			}
		}
	})
}

// TestDirectorySignsItsOwnEntry checks the node's own signing: it signs in
// the directory its link attaches to once it holds a chain, naming the host
// the link's peer reports; again when that host changes — at the instant of
// the last signing, once its clock passed it — when its addresses' report
// changes, and when its cluster changes; one entry naming both hosts once a
// second link attaches at another host of the directory; again every
// refresh interval with no change; and, holding an entry of its own signed
// ahead of its clock, once the clock passes it.
func TestDirectorySignsItsOwnEntry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := newFounded(t)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		engine := trust.NewEngine(directoryIA, key, &trust.NetworkProvider{DB: founder.DB},
			trusttest.Unchecked{})
		// silent is the host whose echo went unanswered, if any, and peers
		// the node's peer reports.
		var silent atomic.Pointer[netip.Addr]
		var peers atomic.Pointer[[]*nodev1.Peer]
		var cluster atomic.Uint64
		verdicts := new(bus.Topic[bus.LinkState])
		d := NewNodeDirectory(NodeDirectoryConfig{
			IA: directoryIA, Trust: engine,
			Addresses: func(hosts []netip.Addr) ([]*nodev1.Address, error) {
				out, err := plainAddresses(hosts)
				for i, h := range hosts {
					if s := silent.Load(); s != nil && *s == h {
						out[i].RendezvousUnanswered = true
					}
				}
				return out, err
			},
			Peers: func(bus.DirectoryID) []*nodev1.Peer {
				if p := peers.Load(); p != nil {
					return *p
				}
				return nil
			},
			Cluster: func() addr.IA { return addr.IA(cluster.Load()) },
			Links:   verdicts,
		})
		d.mint = counterIDs(0xf0)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go d.runSign(ctx)
		// The link's peer names a directory older than any the node mints.
		id := bus.DirectoryID{1}
		own := func() (time.Time, bus.DirectoryEntry) {
			e, ok := heldIn(d, id)[directoryIA]
			if !ok {
				return time.Time{}, bus.DirectoryEntry{}
			}
			return e.key.signedAt, e.entry
		}
		hostOne, hostTwo := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")

		synctest.Wait()
		d.attach(1, hostOne)
		d.adopt(1, id)
		synctest.Wait()
		if at, _ := own(); !at.IsZero() {
			t.Fatal("the node signed with no chain")
		}
		csr, err := trust.CreateCSR(directoryIA, key)
		if err != nil {
			t.Fatal(err)
		}
		chain, err := founder.Issuer.IssueChain(csr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := founder.DB.InsertChain(t.Context(), chain); err != nil {
			t.Fatal(err)
		}
		time.Sleep(EntryRetry)
		synctest.Wait()
		first, e := own()
		if first.IsZero() || !slices.Equal(hostsOf(e), []netip.Addr{hostOne}) {
			t.Fatalf("the enrolled node's entry = %v at %v, want its host", hostsOf(e), first)
		}

		// A change at the instant of the last signing waits the clock past
		// it, and its entry outranks the last.
		d.attach(1, hostTwo)
		d.adopt(1, id)
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		moved, e := own()
		if !moved.After(first) || !slices.Equal(hostsOf(e), []netip.Addr{hostTwo}) {
			t.Errorf("after the host changed: %v at %v, want the new host after %v",
				hostsOf(e), moved, first)
		}

		silent.Store(&hostTwo)
		d.resign()
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if _, e := own(); len(e.Addresses) != 1 || !e.Addresses[0].Reach.RendezvousUnanswered {
			t.Errorf("after the echo went unanswered the entry = %+v, want its report", e)
		}

		reported, _ := own()
		cluster.Store(uint64(founderIA))
		d.resign()
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if at, e := own(); !at.After(reported) || e.Cluster != founderIA {
			t.Errorf("after the cluster changed the entry names %v at %v, want %v after %v",
				e.Cluster, at, founderIA, reported)
		}

		// A peer report the link state changes signs again at the link
		// state's publication, with no other wake.
		peers.Store(&[]*nodev1.Peer{{IsdAs: uint64(founderIA), RttUs: 5000, IfId: 1}})
		verdicts.Publish(bus.NewLinkState())
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		want := []bus.PeerReport{{IA: founderIA, RTT: 5 * time.Millisecond, IfID: 1}}
		if _, e := own(); !slices.EqualFunc(e.Peers, want, bus.PeerReport.Equal) {
			t.Errorf("after the link state changed the entry reports %+v, want %+v", e.Peers, want)
		}

		d.attach(2, hostOne)
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if _, e := own(); !slices.Equal(hostsOf(e), []netip.Addr{hostOne, hostTwo}) {
			t.Errorf("with a second host the entry names %v, want both in order", hostsOf(e))
		}

		// A changed round trip, and a peer that names no link, sign nothing
		// at the link state's publication: the refresh carries them.
		last, _ := own()
		other := addr.MustIAFrom(20, 0xfd0000000099)
		peers.Store(&[]*nodev1.Peer{
			{IsdAs: uint64(founderIA), RttUs: 7000, IfId: 1},
			{IsdAs: uint64(other), RttUs: 9000},
		})
		verdicts.Publish(bus.NewLinkState())
		time.Sleep(time.Second)
		synctest.Wait()
		if at, _ := own(); !at.Equal(last) {
			t.Errorf("a changed round trip signed again %v after the last signing", at.Sub(last))
		}

		time.Sleep(EntryRefreshInterval - time.Second)
		synctest.Wait()
		refreshed, e := own()
		if !refreshed.Equal(time.Now()) {
			t.Errorf("the refresh signed at %v, want %v", refreshed, time.Now())
		}
		want = []bus.PeerReport{
			{IA: founderIA, RTT: 7 * time.Millisecond, IfID: 1},
			{IA: other, RTT: 9 * time.Millisecond},
		}
		if !slices.EqualFunc(e.Peers, want, bus.PeerReport.Equal) {
			t.Errorf("the refresh reports %+v, want %+v", e.Peers, want)
		}

		// An entry of the node's own signed an hour ahead — its clock
		// stepped back — outranks the next change's signing, which retries
		// once the clock passes it.
		ahead := time.Now().Add(time.Hour)
		body := bodyAt(directoryIA, "192.0.2.9")
		stepped, err := parseEntry(fakeEntry(t, directoryIA, heldIn(d, id)[directoryIA].key.trc, ahead, body))
		if err != nil {
			t.Fatal(err)
		}
		if err := stepped.read(body); err != nil {
			t.Fatal(err)
		}
		d.mergeOver(1, stepped)
		hostThree := netip.MustParseAddr("192.0.2.3")
		d.attach(3, hostThree)
		d.adopt(3, id)
		synctest.Wait()
		if at, _ := own(); !at.Equal(ahead) {
			t.Fatalf("the entry signed ahead lost to one at %v", at)
		}
		time.Sleep(time.Hour + time.Nanosecond)
		synctest.Wait()
		if at, e := own(); !at.After(ahead) ||
			!slices.Equal(hostsOf(e), []netip.Addr{hostOne, hostTwo, hostThree}) {
			t.Errorf("once the clock passed the entry signed ahead: %v at %v, want the three hosts after %v",
				hostsOf(e), at, ahead)
		}
	})
}

// TestDirectoryCatchesUpAtTheFirstChain checks the catch-up once the node
// first holds its chain: a node whose link came up before its chain, its
// catch-ups failing meanwhile, syncs at the signing that finds the chain,
// rather than at its catch-ups' next retry.
func TestDirectoryCatchesUpAtTheFirstChain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := newFounded(t)
		f := newFabric()
		b := f.addEnrolled(t, founder, 0xb1)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		xIA := addr.MustIAFrom(20, 0xfd00000000a1)
		x := f.add(xIA, trust.NewEngine(xIA, key, &trust.NetworkProvider{DB: founder.DB},
			trusttest.Unchecked{}),
			"192.0.2.161")
		b.run(t)
		x.run(t)
		// The channel admits no node without a chain: the fabric refuses the
		// link's calls until the node enrolls.
		f.mtx.Lock()
		f.cut[[2]addr.IA{x.ia, b.ia}] = true
		f.cut[[2]addr.IA{b.ia, x.ia}] = true
		f.mtx.Unlock()
		f.link(x, b)
		// Long enough for the failed catch-ups' retries to back off to the
		// summary period.
		time.Sleep(10 * time.Minute)
		synctest.Wait()

		csr, err := trust.CreateCSR(xIA, key)
		if err != nil {
			t.Fatal(err)
		}
		chain, err := founder.Issuer.IssueChain(csr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := founder.DB.InsertChain(t.Context(), chain); err != nil {
			t.Fatal(err)
		}
		f.mtx.Lock()
		clear(f.cut)
		f.mtx.Unlock()
		// The signing retries within the retry interval and finds the chain.
		time.Sleep(EntryRetry)
		synctest.Wait()
		if _, ok := x.shown()[b.ia]; !ok {
			t.Error("the node holds no entry of its neighbor at the signing that found its chain")
		}
	})
}
