package wireguard

import (
	"bytes"
	"context"
	"hash"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers/path"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"
	"golang.zx2c4.com/wireguard/device"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// testMACKey mirrors the forwarding key the data plane verifies.
var testMACKey = []byte("0123456789abcdef")

// countingDB counts the queries a provider makes, beside what it serves.
type countingDB struct {
	inner   pathdb.DB
	queries int
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

// testMeshSocket builds a mesh socket over a provider of the database's
// segments, returning the path requests the provider publishes. Its conn
// submits to a throwaway internal link: the path library's socket without
// the router behind it.
func testMeshSocket(t *testing.T, db pathdb.DB) (*meshSocket, *bus.Topic[bus.PathRequests]) {
	t.Helper()
	internal, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = internal.Close() })
	requests := new(bus.Topic[bus.PathRequests])
	provider := &scion.PathProvider{IA: addr.MustIAFrom(20, 1), DB: db, Requests: requests}
	linkState := new(bus.Topic[bus.LinkState])
	linkState.Publish(bus.NewLinkState(bus.Link{
		Entry: links.Link{IfID: 1, NeighborIA: addr.MustIAFrom(20, 2)},
	}))
	conn, err := scion.NewConn(scion.ConnConfig{
		IA:           addr.MustIAFrom(20, 1),
		Bind:         "127.0.0.1:0",
		InternalAddr: internal.LocalAddr().String(),
		MACKey:       testMACKey,
		Links:        linkState,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return newMeshSocket(conn, provider, &counters{}), requests
}

// message returns a WireGuard message of the type and size, its body zero.
func message(typ byte, size int) []byte {
	pkt := make([]byte, size)
	pkt[0] = typ
	return pkt
}

// dataPacket returns a transport message carrying a data packet.
func dataPacket() []byte {
	return message(device.MessageTransportType, device.MessageTransportSize+64)
}

// TestMeshSocketRidesTheLease checks the sends' reads of the peer's lease:
// the sends within LeaseEvaluation share one evaluation, and every datagram
// counts.
func TestMeshSocketRidesTheLease(t *testing.T) {
	core, leaf := addr.MustIAFrom(20, 0xff0000000021), addr.MustIAFrom(20, 0xff0000000022)
	counting := &countingDB{inner: &memDB{segs: []*pathdb.Segment{upSegmentAt(t, time.Now(), core, leaf)}}}
	socket, _ := testMeshSocket(t, counting)

	peer := &meshEndpoint{addr: scion.Addr{
		IA:   core,
		Addr: netip.MustParseAddrPort("127.0.0.1:40001"),
	}}
	for i := range 5 {
		if err := socket.send(peer, [][]byte{dataPacket()}); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if counting.queries != 1 {
		t.Errorf("%d path queries for 5 sends, want 1 (the lease's one evaluation)", counting.queries)
	}
	if got := socket.cnt.sentDatagrams.Load(); got != 5 {
		t.Errorf("%d datagrams counted, want 5", got)
	}
}

// TestMeshSocketUsesTheLeaseForData checks which sends count as their
// peer's use: a data packet's, whose lease then requests its path measured,
// while a keepalive's read requests nothing.
func TestMeshSocketUsesTheLeaseForData(t *testing.T) {
	data, idle := addr.MustIAFrom(20, 0xff0000000031), addr.MustIAFrom(20, 0xff0000000033)
	leaf := addr.MustIAFrom(20, 0xff0000000032)
	socket, requests := testMeshSocket(t, &memDB{segs: []*pathdb.Segment{
		upSegmentAt(t, time.Now(), data, leaf),
		upSegmentAt(t, time.Now(), idle, leaf),
	}})
	for _, send := range []struct {
		ia  addr.IA
		pkt []byte
	}{
		{idle, message(device.MessageTransportType, device.MessageTransportSize)},
		{data, dataPacket()},
	} {
		peer := &meshEndpoint{addr: scion.Addr{IA: send.ia, Service: SvcWireguard}}
		if err := socket.send(peer, [][]byte{send.pkt}); err != nil {
			t.Fatalf("send to %s: %v", send.ia, err)
		}
	}
	var inUse []addr.IA
	for r := range requests.Latest().All() {
		if r.Role == bus.PathInUse {
			inUse = append(inUse, r.Dst)
		}
	}
	if !slices.Equal(inUse, []addr.IA{data}) {
		t.Errorf("paths in use requested to %v, want the data packet's peer %s alone", inUse, data)
	}
}

// TestCarriesData checks which datagrams count as data: transport messages
// longer than a keepalive, never a keepalive, a handshake message, or a
// cookie reply.
func TestCarriesData(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"data", dataPacket(), true},
		{"keepalive", message(device.MessageTransportType, device.MessageTransportSize), false},
		{"initiation", message(device.MessageInitiationType, device.MessageInitiationSize), false},
		{"response", message(device.MessageResponseType, device.MessageResponseSize), false},
		{"cookie reply", message(device.MessageCookieReplyType, device.MessageCookieReplySize), false},
	} {
		if got := carriesData(tc.pkt); got != tc.want {
			t.Errorf("carriesData(%s) = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// TestMeshSocketFallsBackOnArrival checks a send while the peer's lease
// holds no path: it rides the peer's arrival path while that path lapses
// beyond LeaseExpiryMargin, and fails, every datagram counted, without one.
func TestMeshSocketFallsBackOnArrival(t *testing.T) {
	core, leaf := addr.MustIAFrom(20, 0xff0000000041), addr.MustIAFrom(20, 0xff0000000042)
	arrival := func(origin time.Time) *spath.Decoded {
		p, err := upSegmentAt(t, origin, core, leaf).PCB.ReversePathTo(0)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	lifetime := path.ExpTimeToDuration(segment.HopExpTime)
	for _, tc := range []struct {
		name         string
		path         *spath.Decoded
		sent, failed int64
	}{
		{"fresh arrival", arrival(time.Now()), 2, 0},
		{"expiring arrival", arrival(time.Now().Add(scion.LeaseExpiryMargin - lifetime)), 0, 2},
		{"no arrival", nil, 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket, _ := testMeshSocket(t, &memDB{})
			peer := &meshEndpoint{addr: scion.Addr{
				IA:   core,
				Addr: netip.MustParseAddrPort("127.0.0.1:40001"),
				Path: tc.path,
			}}
			err := socket.send(peer, [][]byte{dataPacket(), dataPacket()})
			if (err == nil) != (tc.failed == 0) {
				t.Errorf("send = %v, want failure %t", err, tc.failed != 0)
			}
			if got := socket.cnt.sentDatagrams.Load(); got != tc.sent {
				t.Errorf("%d datagrams sent, want %d", got, tc.sent)
			}
			if got := socket.cnt.sendFailures.Load(); got != tc.failed {
				t.Errorf("%d datagrams failed, want %d", got, tc.failed)
			}
		})
	}
}

// TestMeshSocketCountsRouteSwitches checks the route switches: a send riding
// another path than its peer's last send counts one, never the same path or
// a peer's first send.
func TestMeshSocketCountsRouteSwitches(t *testing.T) {
	socket := newMeshSocket(nil, nil, &counters{})
	near, far := addr.MustIAFrom(20, 0xff0000000071), addr.MustIAFrom(20, 0xff0000000072)
	for _, ride := range []struct {
		ia addr.IA
		id bus.PathID
	}{
		{near, "a"}, {near, "a"}, {far, "b"}, {near, "b"}, {far, "b"}, {near, "a"},
	} {
		socket.rode(ride.ia, ride.id)
	}
	if got := socket.cnt.routeSwitches.Load(); got != 2 {
		t.Errorf("%d route switches, want 2", got)
	}
}

// TestMeshBindEndpointRoundTrip checks the IPC string form flows through
// ParseEndpoint: the peer named by ISD-AS and the wireguard service, the
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
	if !peer.addr.IA.Equal(ia) || peer.addr.Service != SvcWireguard {
		t.Errorf("endpoint = %v, want %s,%s", peer.addr, ia, SvcWireguard)
	}
	for _, bad := range []string{
		"no-comma",
		"nope,wireguard",         // malformed ISD-AS
		ia.String(),              // no service
		ia.String() + ",gateway", // a service name nothing serves
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
	svc := uint16(SvcWireguard)
	if len(digest) != 10 || digest[8] != byte(svc>>8) || digest[9] != byte(svc) {
		t.Errorf("digest = %x, want the ISD-AS and the service value %04x", digest, SvcWireguard)
	}
	other, err := bind.ParseEndpoint(endpointString(addr.MustIAFrom(20, 0xff0000000052)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(peer.DstToBytes(), other.DstToBytes()) {
		t.Error("two peers share an endpoint digest")
	}
}
