package wireguard

import (
	"bytes"
	"context"
	"hash"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"

	"github.com/fancl20/cion/pkg/pathdb"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
)

// testMACKey mirrors the forwarding key the data plane verifies.
var testMACKey = []byte("0123456789abcdef")

// countingDB counts the queries a provider makes, beside what it serves.
type countingDB struct {
	inner      pathdb.DB
	queries    int
	lastAccess time.Time
}

func (d *countingDB) Insert(ctx context.Context, s *pathdb.Segment) (bool, error) {
	return d.inner.Insert(ctx, s)
}

func (d *countingDB) Get(ctx context.Context, q pathdb.Query) ([]*pathdb.Segment, error) {
	d.queries++
	return d.inner.Get(ctx, q)
}

func (d *countingDB) DeleteExpired(ctx context.Context, t time.Time) (int, error) {
	return d.inner.DeleteExpired(ctx, t)
}

func (d *countingDB) Close() error { return nil }

// memDB serves the segments it was handed.
type memDB struct {
	segs []*pathdb.Segment
}

func (d *memDB) Insert(context.Context, *pathdb.Segment) (bool, error) { return false, nil }
func (d *memDB) Get(_ context.Context, q pathdb.Query) ([]*pathdb.Segment, error) {
	var segs []*pathdb.Segment
	for _, seg := range d.segs {
		if q.Type != pathdb.SegmentTypeUnspecified && q.Type != seg.Type {
			continue
		}
		if !q.SrcIA.IsZero() && !q.SrcIA.Equal(seg.FirstIA()) {
			continue
		}
		segs = append(segs, seg)
	}
	return segs, nil
}
func (d *memDB) DeleteExpired(context.Context, time.Time) (int, error) { return 0, nil }
func (d *memDB) Close() error                                          { return nil }

// upSegmentAt builds a two-AS up segment beaconed at the given time, MACed
// with the forwarding key.
func upSegmentAt(t *testing.T, now time.Time, core, leaf addr.IA) *pathdb.Segment {
	t.Helper()
	pcb, err := segment.PCBWithID(now, 0x333)
	if err != nil {
		t.Fatal(err)
	}
	macFactory := func() hash.Hash {
		mac, _ := scrypto.InitMac(testMACKey)
		return mac
	}
	if _, err := pcb.AppendRouteHop(core, segment.EntryOptions{EgressIfID: 1},
		macFactory); err != nil {
		t.Fatal(err)
	}
	if _, err := pcb.AppendRouteHop(leaf, segment.EntryOptions{IngressIfID: 1},
		macFactory); err != nil {
		t.Fatal(err)
	}
	return &pathdb.Segment{Type: pathdb.SegmentTypeUp, PCB: pcb}
}

// testMeshSocket builds a mesh socket whose conn submits to a throwaway
// internal link, the path library's socket without the router behind it.
func testMeshSocket(t *testing.T, db pathdb.DB) (*meshSocket, *countingDB) {
	t.Helper()
	internal, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { internal.Close() }) //nolint:errcheck
	counting := &countingDB{inner: db}
	provider := &scion.PathProvider{IA: addr.MustIAFrom(20, 1), DB: counting}
	conn, err := scion.NewConn(scion.ConnConfig{
		IA:           addr.MustIAFrom(20, 1),
		Bind:         "127.0.0.1:0",
		InternalAddr: internal.LocalAddr().String(),
		MACKey:       testMACKey,
		Links:        map[uint16]addr.IA{1: addr.MustIAFrom(20, 2)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck
	cnt := &counters{}
	return newMeshSocket(conn, provider, cnt), counting
}

// TestMeshSocketCachesPath checks the send path's resolution discipline: the
// freshest path is resolved once per peer and cached, not per datagram.
func TestMeshSocketCachesPath(t *testing.T) {
	core, leaf := addr.MustIAFrom(20, 0xff0000000021), addr.MustIAFrom(20, 0xff0000000022)
	db := &memDB{segs: []*pathdb.Segment{upSegmentAt(t, time.Now(), core, leaf)}}
	socket, counting := testMeshSocket(t, db)

	peer := &meshEndpoint{addr: scion.Addr{
		IA:   core,
		Addr: netip.MustParseAddrPort("127.0.0.1:30045"),
	}}
	for i := 0; i < 5; i++ {
		if err := socket.send(peer, [][]byte{[]byte("datagram")}); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if counting.queries != 1 {
		t.Errorf("%d path queries for 5 sends, want 1 (the cache)", counting.queries)
	}
	if got := socket.cnt.sentDatagrams.Load(); got != 5 {
		t.Errorf("%d datagrams counted, want 5", got)
	}
}

// TestMeshSocketRefreshesExpiredPath checks the cache's expiry: a path whose
// hops have lapsed — or lapse inside the refresh margin — is re-resolved
// before it fails, not after.
func TestMeshSocketRefreshesExpiredPath(t *testing.T) {
	core, leaf := addr.MustIAFrom(20, 0xff0000000031), addr.MustIAFrom(20, 0xff0000000032)
	stale := upSegmentAt(t, time.Now().Add(-25*time.Hour), core, leaf)
	db := &memDB{segs: []*pathdb.Segment{stale}}
	socket, _ := testMeshSocket(t, db)

	peer := &meshEndpoint{addr: scion.Addr{
		IA:   core,
		Addr: netip.MustParseAddrPort("127.0.0.1:30045"),
	}}
	if err := socket.send(peer, [][]byte{[]byte("datagram")}); err != nil {
		t.Fatalf("send over a stale path: %v", err)
	}
	socket.mtx.Lock()
	path := socket.paths[core]
	socket.mtx.Unlock()
	if path == nil {
		t.Fatal("the stale path was not cached at all")
	}
	// The cached path is the stale one — its expiry sits inside the refresh
	// margin, so the next send refreshes it.
	if scion.PathExpiry(path).After(time.Now().Add(pathRefreshMargin)) {
		t.Fatalf("stale path expiry %v is outside the refresh margin",
			scion.PathExpiry(path))
	}
	socket.mtx.Lock()
	socket.expiry[core] = time.Now().Add(-time.Hour) // age it past the margin
	socket.mtx.Unlock()
	if socket.cachedPath(core) != nil {
		t.Error("an expired cached path was served")
	}
}

// TestMeshSocketRefreshesFailedSend checks the error path: a send that fails
// invalidates the cached path and retries once on a fresh one.
func TestMeshSocketRefreshesFailedSend(t *testing.T) {
	core, leaf := addr.MustIAFrom(20, 0xff0000000041), addr.MustIAFrom(20, 0xff0000000042)
	db := &memDB{segs: []*pathdb.Segment{upSegmentAt(t, time.Now(), core, leaf)}}
	socket, counting := testMeshSocket(t, db)

	peer := &meshEndpoint{addr: scion.Addr{
		IA:   core,
		Addr: netip.MustParseAddrPort("127.0.0.1:30045"),
	}}
	if err := socket.send(peer, [][]byte{[]byte("datagram")}); err != nil {
		t.Fatalf("first send: %v", err)
	}
	// A closed socket fails every send; the failure refreshes the path once
	// and reports.
	socket.conn.Close() //nolint:errcheck
	if err := socket.send(peer, [][]byte{[]byte("datagram")}); err == nil {
		t.Fatal("sending over a closed socket succeeded")
	}
	if got := socket.cnt.pathRefreshes.Load(); got != 1 {
		t.Errorf("%d path refreshes after a failed send, want 1", got)
	}
	if got := socket.cnt.sendFailures.Load(); got == 0 {
		t.Error("the failed send was not counted")
	}
	if counting.queries < 2 {
		t.Errorf("%d path queries; the failed send did not re-resolve", counting.queries)
	}
}

// TestMeshBindEndpointRoundTrip checks the IPC string form flows through
// ParseEndpoint: the peer named by ISD-AS and the gateway service, the
// malformed forms refused.
func TestMeshBindEndpointRoundTrip(t *testing.T) {
	socket, _ := testMeshSocket(t, &memDB{})
	bind := newMeshBind(socket)
	ia := addr.MustIAFrom(20, 0xff0000000051)
	ep, err := bind.ParseEndpoint(endpointString(ia))
	if err != nil {
		t.Fatal(err)
	}
	peer, ok := ep.(*meshEndpoint)
	if !ok {
		t.Fatalf("endpoint of type %T", ep)
	}
	if !peer.addr.IA.Equal(ia) || peer.addr.Service != SvcGateway {
		t.Errorf("endpoint = %v, want %s,%s", peer.addr, ia, SvcGateway)
	}
	for _, bad := range []string{
		"no-comma",
		"nope,gateway",           // malformed ISD-AS
		ia.String(),              // no service
		ia.String() + ",bogus",   // unknown service
		ia.String() + ",1.2.3.4", // an underlay form names no service
	} {
		if _, err := bind.ParseEndpoint(bad); err == nil {
			t.Errorf("parsing endpoint %q succeeded", bad)
		}
	}
	// The cookie MAC's endpoint digest carries the service value in place of
	// the address, distinguishing peers the way the underlay form did.
	digest := peer.DstToBytes()
	svc := uint16(SvcGateway)
	if len(digest) != 10 || digest[8] != byte(svc>>8) || digest[9] != byte(svc) {
		t.Errorf("digest = %x, want the ISD-AS and the service value %04x", digest, SvcGateway)
	}
	other, err := bind.ParseEndpoint(endpointString(addr.MustIAFrom(20, 0xff0000000052)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(peer.DstToBytes(), other.DstToBytes()) {
		t.Error("two peers share an endpoint digest")
	}
}
