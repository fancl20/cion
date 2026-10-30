package measured

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"maps"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path"
	"path/filepath"
	"slices"
	"sync"
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

// bodyAt returns the entry of the ISD-AS naming the host.
func bodyAt(ia addr.IA, host string) *nodev1.Entry {
	h := netip.MustParseAddr(host)
	return &nodev1.Entry{
		IsdAs:          uint64(ia),
		ControlAddr:    netip.AddrPortFrom(h, scionrpc.EndpointPort).String(),
		RendezvousAddr: netip.AddrPortFrom(h, RendezvousPort).String(),
	}
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

// heldTimes returns the signing times of the entries the directory holds,
// by signer.
func heldTimes(d *NodeDirectory) map[addr.IA]time.Time {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	out := make(map[addr.IA]time.Time, len(d.entries))
	for signer, e := range d.entries {
		out[signer] = e.key.signedAt
	}
	return out
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

// TestDirectoryJoinIsASemilattice checks the join over generated entry
// sets: merging them in any order, grouping, and repetition leaves every
// directory holding the same entries — each signer's greatest.
func TestDirectoryJoinIsASemilattice(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(1, 2))
	signers := []addr.IA{directoryIA, founderIA, addr.MustIAFrom(20, 0xfd0000000042)}
	base := time.Unix(1_700_000_000, 0)
	generate := func(n int) []*signedEntry {
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
	join := func(sets ...[]*signedEntry) map[addr.IA]entryKey {
		d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA})
		for _, set := range sets {
			for _, e := range set {
				d.merge(e)
			}
		}
		out := make(map[addr.IA]entryKey, len(d.entries))
		for signer, e := range d.entries {
			out[signer] = e.key
		}
		return out
	}
	opts := cmp.Comparer(func(a, b entryKey) bool { return a.compare(b) == 0 })
	for i := range 200 {
		a, b, c := generate(rng.IntN(6)), generate(rng.IntN(6)), generate(rng.IntN(6))
		ab := join(a, b)
		if diff := cmp.Diff(ab, join(b, a), opts); diff != "" {
			t.Fatalf("round %d: the join is not commutative (-a,b +b,a):\n%s", i, diff)
		}
		shuffled := slices.Concat(a, b, c)
		rng.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		abc := join(a, b, c)
		if diff := cmp.Diff(abc, join(shuffled), opts); diff != "" {
			t.Fatalf("round %d: the join is not associative (-in order +shuffled):\n%s", i, diff)
		}
		if diff := cmp.Diff(abc, join(a, b, c, c, a, b), opts); diff != "" {
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

// TestDirectoryNeverVerifiesALoser checks acceptance's order: an entry
// greater than the one held is verified and merged, while one equal to it
// or lesser is passed over before any verification.
func TestDirectoryNeverVerifiesALoser(t *testing.T) {
	signer := founderIA
	now := time.Now()
	ft := &fakeTrust{}
	d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Trust: ft})
	greater := fakeEntry(t, signer, trcN, now, bodyAt(signer, "192.0.2.1"))
	lesser := fakeEntry(t, signer, trcN, now.Add(-time.Minute), bodyAt(signer, "192.0.2.2"))
	ctx := t.Context()
	if n := d.accept(ctx, []*cryptopb.SignedMessage{greater}, directoryIA, nil); n != 1 {
		t.Fatalf("the greater entry merged %d, want 1", n)
	}
	if n := d.accept(ctx, []*cryptopb.SignedMessage{greater, lesser}, directoryIA, nil); n != 0 {
		t.Errorf("the held and the lesser entries merged %d, want none", n)
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
	withdrawal := &nodev1.Entry{IsdAs: uint64(signer(5))}
	pbs := []*cryptopb.SignedMessage{
		fakeEntry(t, signer(1), trcN, now.Add(-time.Minute), bodyAt(signer(1), "192.0.2.1")),
		fakeEntry(t, signer(2), trcPrev, now.Add(-time.Minute), bodyAt(signer(2), "192.0.2.2")),
		fakeEntry(t, signer(3), trcN, now.Add(-EntryLifetime), bodyAt(signer(3), "192.0.2.3")),
		fakeEntry(t, signer(4), trcN, now.Add(entryFutureBound+time.Second),
			bodyAt(signer(4), "192.0.2.4")),
		fakeEntry(t, signer(5), trcN, now.Add(-time.Minute), withdrawal),
	}
	d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Trust: &fakeTrust{}})
	for _, pb := range pbs {
		e, err := parseEntry(pb)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.verify(t.Context(), e, nil); err != nil {
			t.Fatal(err)
		}
		d.merge(e)
	}
	held := heldTimes(d)

	d.mtx.Lock()
	view, next := d.viewLocked(now)
	d.mtx.Unlock()
	got := slices.Sorted(maps.Keys(view))
	if want := []addr.IA{signer(1), signer(2)}; !slices.Equal(got, want) {
		t.Errorf("the view = %v, want %v", got, want)
	}
	if want := now.Add(time.Second); !next.Equal(want) {
		t.Errorf("the view changes next at %v, want the future entry's entering at %v", next, want)
	}
	if diff := cmp.Diff(held, heldTimes(d)); diff != "" {
		t.Errorf("the view changed the directory (-before +after):\n%s", diff)
	}
}

// TestDirectoryViewFollowsTheClock checks the view's publication with no
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
		now := time.Now()
		msgs := []*cryptopb.SignedMessage{
			fakeEntry(t, signer(1), trcN, now, bodyAt(signer(1), "192.0.2.1")),
			fakeEntry(t, signer(2), trcN, now.Add(entryFutureBound+time.Minute),
				bodyAt(signer(2), "192.0.2.2")),
		}
		if n := d.accept(t.Context(), msgs, founderIA, nil); n != len(msgs) {
			t.Fatalf("merged %d, want all %d", n, len(msgs))
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go d.runView(ctx)
		published := func() []addr.IA {
			var out []addr.IA
			for _, e := range topic.Latest().Entries() {
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
	withdrawal := &nodev1.Entry{IsdAs: uint64(signer(4))}
	pbs := []*cryptopb.SignedMessage{
		fakeEntry(t, signer(1), trcN, now.Add(-EntryLifetime-time.Minute),
			bodyAt(signer(1), "192.0.2.1")),
		fakeEntry(t, signer(2), trcPrev, now.Add(-time.Minute), bodyAt(signer(2), "192.0.2.2")),
		fakeEntry(t, signer(3), trcN, now.Add(time.Hour), bodyAt(signer(3), "192.0.2.3")),
		fakeEntry(t, signer(4), trcN, now.Add(-time.Minute), withdrawal),
	}
	if n := d.accept(t.Context(), pbs, founderIA, nil); n != len(pbs) {
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
	if n := d.accept(t.Context(), []*cryptopb.SignedMessage{ancient}, founderIA, nil); n != 0 {
		t.Errorf("merged %d of the ancient entry, want none", n)
	}
	if ft.verifications() != verified {
		t.Errorf("the ancient entry was verified")
	}
}

// TestDirectoryEntryAddresses checks what an entry names: one naming no
// address is a withdrawal, which the view leaves out, while one naming a
// single address, or a malformed one, is refused.
func TestDirectoryEntryAddresses(t *testing.T) {
	now := time.Now()
	signer := func(n uint64) addr.IA { return addr.MustIAFrom(20, addr.AS(0xfd0000000400+n)) }
	half := bodyAt(signer(2), "192.0.2.2")
	half.RendezvousAddr = ""
	malformed := bodyAt(signer(3), "192.0.2.3")
	malformed.ControlAddr = "nope"
	msgs := []*cryptopb.SignedMessage{
		fakeEntry(t, signer(1), trcN, now, &nodev1.Entry{IsdAs: uint64(signer(1))}),
		fakeEntry(t, signer(2), trcN, now, half),
		fakeEntry(t, signer(3), trcN, now, malformed),
	}
	d := NewNodeDirectory(NodeDirectoryConfig{
		IA: directoryIA, Trust: &fakeTrust{},
	})
	if n := d.accept(t.Context(), msgs, founderIA, nil); n != 1 {
		t.Fatalf("merged %d, want the entry naming no address alone", n)
	}
	d.mtx.Lock()
	e := d.entries[signer(1)]
	d.mtx.Unlock()
	if e == nil || !e.withdrawn {
		t.Errorf("the entry naming no address is no withdrawal: %+v", e)
	}
	if view, _ := d.pass(now); len(view) != 0 {
		t.Errorf("the view shows %d entries, want none", len(view))
	}
}

// TestDirectoryOutranking checks two outrankings: a withdrawal outranks
// its signer's earlier entries, and an entry under a newer TRC outranks a
// runaway one signed far ahead of the clock.
func TestDirectoryOutranking(t *testing.T) {
	now := time.Now()
	ft := &fakeTrust{}
	d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Trust: ft})
	ctx := t.Context()
	signer := founderIA
	entry := fakeEntry(t, signer, trcN, now.Add(-time.Minute), bodyAt(signer, "192.0.2.1"))
	withdrawal := fakeEntry(t, signer, trcN, now,
		&nodev1.Entry{IsdAs: uint64(signer)})
	if n := d.accept(ctx, []*cryptopb.SignedMessage{entry, withdrawal}, directoryIA, nil); n != 2 {
		t.Fatalf("merged %d, want the entry and the withdrawal", n)
	}
	if n := d.accept(ctx, []*cryptopb.SignedMessage{entry}, directoryIA, nil); n != 0 {
		t.Errorf("an earlier entry outranked the withdrawal")
	}
	if view, _ := d.pass(now); len(view) != 0 {
		t.Errorf("the view shows %d entries past the withdrawal, want none", len(view))
	}

	runaway := addr.MustIAFrom(20, 0xfd0000000042)
	ahead := fakeEntry(t, runaway, trcPrev, now.Add(24*time.Hour), bodyAt(runaway, "192.0.2.2"))
	current := fakeEntry(t, runaway, trcPrev, now, bodyAt(runaway, "192.0.2.3"))
	renewed := fakeEntry(t, runaway, trcN, now, bodyAt(runaway, "192.0.2.4"))
	if n := d.accept(ctx, []*cryptopb.SignedMessage{ahead, current}, directoryIA, nil); n != 1 {
		t.Fatalf("merged %d, want the runaway entry alone", n)
	}
	if n := d.accept(ctx, []*cryptopb.SignedMessage{renewed}, directoryIA, nil); n != 1 {
		t.Fatalf("the entry under the newer TRC did not outrank the runaway one")
	}
	view, _ := d.pass(now)
	if e, ok := view[runaway]; !ok || e.entry.RendezvousAddr.Addr() != netip.MustParseAddr("192.0.2.4") {
		t.Errorf("the view holds %v for the runaway signer, want the renewed entry", view[runaway])
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
// from the neighbor that sent it, while an altered entry, one whose body
// names another ISD-AS, and one no chain of its signer verifies are
// refused.
func TestDirectoryAcceptance(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := trusttest.NewFounder(t, openTrustDB(t), founderIA)
		signer := addr.MustIAFrom(20, 0xfd0000000042)
		signerKey, chain := founder.Enroll(t, signer)
		signerEngine := trust.NewEngine(signer, signerKey, &trust.NetworkProvider{DB: founder.DB})

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
		})
		d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Trust: engine})
		const arrival = 7
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
		if len(d.entries) != 0 {
			t.Fatalf("held %d entries after the altered and the impostor, want none",
				len(d.entries))
		}
		if _, err := d.Push(ctx, &nodev1.PushRequest{
			Entries: []*cryptopb.SignedMessage{entry},
		}); err != nil {
			t.Fatal(err)
		}
		view, _ := d.pass(time.Now())
		if e, ok := view[signer]; !ok || e.entry.RendezvousAddr.Addr() != netip.MustParseAddr("192.0.2.1") {
			t.Fatalf("the view holds %v for the signer, want the entry", view[signer])
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
		if _, ok := d.entries[stranger]; ok {
			t.Error("an entry no chain verifies was held")
		}
	})
}

// TestDirectoryHandlersRefuse checks the service's gates: a request with no
// authenticated ISD-AS is refused, and so is a call past the per-call
// bound.
func TestDirectoryHandlersRefuse(t *testing.T) {
	d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Trust: &fakeTrust{}})
	if _, err := d.Push(t.Context(), &nodev1.PushRequest{}); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("an unauthenticated push = %v, want permission denied", err)
	}
	if _, err := d.Sync(t.Context(), &nodev1.SyncRequest{}); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("an unauthenticated sync = %v, want permission denied", err)
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
}

// fabric is an in-process one-hop channel between directories: a node's
// client reaches the neighbor its link names, each request carrying the
// caller as its authenticated ISD-AS and the link's far interface as its
// arrival.
type fabric struct {
	mtx   sync.Mutex
	nodes map[addr.IA]*fabricNode
	calls []call
	// cut holds the pairs whose calls fail.
	cut map[[2]addr.IA]bool
}

// call is one request the fabric carried.
type call struct {
	from, to addr.IA
	method   string
}

// fabricNode is one node of the fabric.
type fabricNode struct {
	ia      addr.IA
	engine  *trust.Engine
	dir     *NodeDirectory
	self    *bus.Topic[bus.SelfState]
	links   *bus.Topic[bus.LinkState]
	view    *bus.Topic[bus.Directory]
	handler http.Handler
	// ifIDs holds the interface of the link reaching each neighbor.
	ifIDs map[addr.IA]uint16
}

func newFabric() *fabric {
	return &fabric{nodes: make(map[addr.IA]*fabricNode), cut: make(map[[2]addr.IA]bool)}
}

// add builds a node signing with the engine, at the host.
func (f *fabric) add(ia addr.IA, engine *trust.Engine, host string) *fabricNode {
	n := &fabricNode{
		ia:    ia,
		self:  new(bus.Topic[bus.SelfState]),
		links: new(bus.Topic[bus.LinkState]),
		view:  new(bus.Topic[bus.Directory]),
		ifIDs: make(map[addr.IA]uint16),
	}
	n.self.Publish(bus.SelfState{Host: netip.MustParseAddr(host)})
	n.links.Publish(bus.NewLinkState())
	n.dir = NewNodeDirectory(NodeDirectoryConfig{
		IA:        ia,
		Self:      n.self,
		Trust:     engine,
		Links:     n.links,
		Peer:      fabricPeer{f: f, from: ia},
		Directory: n.view,
	})
	n.engine = engine
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

// link links the two nodes and publishes both ends' link state.
func (f *fabric) link(a, b *fabricNode) {
	f.mtx.Lock()
	a.ifIDs[b.ia] = uint16(len(a.ifIDs) + 1)
	b.ifIDs[a.ia] = uint16(len(b.ifIDs) + 1)
	f.mtx.Unlock()
	f.publishLinks(a)
	f.publishLinks(b)
}

// unlink takes the link between the two nodes down at both ends.
func (f *fabric) unlink(a, b *fabricNode) {
	f.mtx.Lock()
	delete(a.ifIDs, b.ia)
	delete(b.ifIDs, a.ia)
	f.mtx.Unlock()
	f.publishLinks(a)
	f.publishLinks(b)
}

func (f *fabric) publishLinks(n *fabricNode) {
	f.mtx.Lock()
	var ls []bus.Link
	for neighbor, ifID := range n.ifIDs {
		ls = append(ls, bus.Link{Entry: links.Link{
			IfID: ifID, NeighborIA: neighbor, State: links.StateEstablished,
		}})
	}
	f.mtx.Unlock()
	n.links.Publish(bus.NewLinkState(ls...))
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

// shown returns the hosts the node's view names, by ISD-AS.
func (n *fabricNode) shown() map[addr.IA]netip.Addr {
	out := make(map[addr.IA]netip.Addr)
	for _, e := range n.view.Latest().Entries() {
		out[e.IA] = e.RendezvousAddr.Addr()
	}
	return out
}

// newFounded founds an ISD over a fresh trust database.
func newFounded(t *testing.T) *trusttest.Founder {
	t.Helper()
	return trusttest.NewFounder(t, openTrustDB(t), founderIA)
}

// TestDirectoryFloods checks the flooding: an accepted greater entry is
// pushed to every neighbor but its sender, and a lesser one to none.
func TestDirectoryFloods(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := newFounded(t)
		f := newFabric()
		a, b, c, d := f.addEnrolled(t, founder, 0xa1), f.addEnrolled(t, founder, 0xb1),
			f.addEnrolled(t, founder, 0xc1), f.addEnrolled(t, founder, 0xd1)
		f.link(a, b)
		f.link(b, c)
		f.link(b, d)
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

// TestDirectorySync checks the sync: each side ends holding what
// the other held greater, a tie of TRC and signing time resolved by the
// signed bytes.
func TestDirectorySync(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := newFounded(t)
		f := newFabric()
		x, y := f.addEnrolled(t, founder, 0xa1), f.addEnrolled(t, founder, 0xb1)
		f.link(x, y)
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
		merge := func(n *fabricNode, entries ...*cryptopb.SignedMessage) {
			t.Helper()
			if n.dir.accept(t.Context(), entries, founderIA, nil) != len(entries) {
				t.Fatalf("%v did not merge every entry", n.ia)
			}
		}
		merge(x, newer1, e2, tieA)
		merge(y, older1, e3, tieB)

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
		for _, n := range []*fabricNode{x, y} {
			n.dir.mtx.Lock()
			got1 := n.dir.entries[s1].entry.RendezvousAddr.Addr()
			got4 := n.dir.entries[s4].key.signed
			n.dir.mtx.Unlock()
			if got1 != netip.MustParseAddr("192.0.2.12") {
				t.Errorf("%v holds %v of the first signer, want the newer entry", n.ia, got1)
			}
			greater := tieA.HeaderAndBody
			if string(tieB.HeaderAndBody) > string(greater) {
				greater = tieB.HeaderAndBody
			}
			if string(got4) != string(greater) {
				t.Errorf("%v holds the lesser of the tied entries", n.ia)
			}
		}
	})
}

// addrs compares addresses.
var addrs = cmpopts.EquateComparable(netip.Addr{})

// TestDirectoryReplicatesAlongLinks checks the directory over running
// nodes in a line: every node's view holds every node's entry; a node's
// changed host reaches the far end; a node that comes back with an empty
// directory holds every entry once its link is up; and a node that stops on
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
		c.self.Publish(bus.SelfState{Host: netip.MustParseAddr("203.0.113.3")})
		synctest.Wait()
		if got := a.shown()[c.ia]; got != netip.MustParseAddr("203.0.113.3") {
			t.Errorf("the far end shows %v for the moved node, want its new host", got)
		}

		// The far end comes back empty: its first link fills it.
		f.unlink(b, c)
		fresh := f.add(c.ia, c.engine, "203.0.113.3")
		fresh.run(t)
		synctest.Wait()
		if got := len(fresh.shown()); got != 1 {
			t.Errorf("the returning node shows %d entries before its link, want its own", got)
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
		a.self.Publish(bus.SelfState{Host: netip.MustParseAddr("203.0.113.1")})
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

// TestDirectorySignsItsOwnEntry checks the node's own signing: it signs once
// its state and its chain are ready, again when its state changes — at the
// instant of the last signing, once its clock passed it — and again every
// refresh interval with no change.
func TestDirectorySignsItsOwnEntry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := newFounded(t)
		self := new(bus.Topic[bus.SelfState])
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		engine := trust.NewEngine(directoryIA, key, &trust.NetworkProvider{DB: founder.DB})
		d := NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA, Self: self, Trust: engine})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go d.runSign(ctx)
		own := func() (time.Time, netip.Addr) {
			d.mtx.Lock()
			defer d.mtx.Unlock()
			e, ok := d.entries[directoryIA]
			if !ok {
				return time.Time{}, netip.Addr{}
			}
			return e.key.signedAt, e.entry.RendezvousAddr.Addr()
		}

		synctest.Wait()
		if at, _ := own(); !at.IsZero() {
			t.Fatal("the node signed with no host")
		}
		self.Publish(bus.SelfState{Host: netip.MustParseAddr("192.0.2.1")})
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
		first, host := own()
		if first.IsZero() || host != netip.MustParseAddr("192.0.2.1") {
			t.Fatalf("the enrolled node's entry = %v at %v, want its host", host, first)
		}

		// A change at the instant of the last signing waits the clock past
		// it, and its entry outranks the last.
		self.Publish(bus.SelfState{Host: netip.MustParseAddr("192.0.2.2")})
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		moved, host := own()
		if !moved.After(first) || host != netip.MustParseAddr("192.0.2.2") {
			t.Errorf("after the state changed: %v at %v, want the new host after %v",
				host, moved, first)
		}

		time.Sleep(EntryRefreshInterval)
		synctest.Wait()
		if refreshed, _ := own(); !refreshed.Equal(time.Now()) {
			t.Errorf("the refresh signed at %v, want %v", refreshed, time.Now())
		}
	})
}

// TestDirectoryCatchesUpAtTheFirstSigning checks the catch-up at the
// node's first signing: a node whose link came up before its chain, its
// syncs failing meanwhile, syncs at the instant it signs, rather than at its
// syncs' next retry.
func TestDirectoryCatchesUpAtTheFirstSigning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := newFounded(t)
		f := newFabric()
		b := f.addEnrolled(t, founder, 0xb1)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		xIA := addr.MustIAFrom(20, 0xfd00000000a1)
		x := f.add(xIA, trust.NewEngine(xIA, key, &trust.NetworkProvider{DB: founder.DB}),
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
		// Long enough for the failed syncs' retries to back off to the
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
		// An event of the node's own state wakes its first signing at once,
		// so the check reads what that signing brought, at its instant.
		x.self.Publish(bus.SelfState{Host: netip.MustParseAddr("192.0.2.161")})
		synctest.Wait()
		if _, ok := x.shown()[b.ia]; !ok {
			t.Error("the node holds no entry of its neighbor at its first signing")
		}
	})
}
