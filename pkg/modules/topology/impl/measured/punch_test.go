package measured

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/peeria"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/links/impl/memory"
	"github.com/fancl20/cion/pkg/modules/pathdb"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
)

// TestPunchPacketParse checks the punch datagram: its form round-trips,
// and a truncated, padded, or other-version datagram — the empty datagram
// a rendezvous establishment sends among them — parses as none.
func TestPunchPacketParse(t *testing.T) {
	want := punchPacket{nonce: [16]byte{1, 2, 3}, kind: punchEcho}
	raw := want.marshal()
	if got, ok := parsePunchPacket(raw); !ok || got != want {
		t.Errorf("round trip = %+v, %t; want %+v", got, ok, want)
	}
	for name, b := range map[string][]byte{
		"a truncated datagram": raw[:len(raw)-1],
		"a padded datagram":    append(slices.Clone(raw), 0),
		"another version's":    append([]byte{0, 9}, raw[2:]...),
		"the empty datagram":   nil,
		"a binding request":    marshaled(t, RendezvousRequest{Binding: true}),
	} {
		if _, ok := parsePunchPacket(b); ok {
			t.Errorf("%s parsed as a punch", name)
		}
	}
}

// udpSocket binds a kernel socket on a loopback ephemeral port.
func udpSocket(t *testing.T) underlay.UDPConn {
	t.Helper()
	conn, err := underlay.Kernel.NewUDP(
		net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")), netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// boundAddr returns the socket's bound address as the reflector reports it.
func boundAddr(conn underlay.UDPConn) netip.AddrPort {
	ap := conn.LocalAddr().AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// punchService builds a link service that punches, its reflector a
// rendezvous acceptor on loopback — where every reflexive address is the
// socket's own.
func punchService(t *testing.T, mutate func(*LinkService)) *LinkService {
	t.Helper()
	reflector := newRendezvousFixture(t, nil)
	return newLinkService(t, func(s *LinkService) {
		s.Reflector = func(context.Context) (netip.AddrPort, error) { return reflector.addr, nil }
		if mutate != nil {
			mutate(s)
		}
	})
}

// authenticated returns a context carrying the peer the middleware
// authenticated.
func authenticated(peer addr.IA) context.Context {
	return context.WithValue(context.Background(), peeria.AuthenticatedIAContextKey(), peer)
}

// linkPunch calls the link's punch as the authenticated peer.
func linkPunch(
	svc *LinkService, peer addr.IA, reflexive netip.AddrPort, nonce [16]byte, ifID uint32,
) (*nodev1.PunchReply, error) {

	return svc.Punch(authenticated(peer), &nodev1.PunchRequest{
		ReflexiveAddr: reflexive.String(),
		Nonce:         nonce[:],
		IfId:          ifID,
	})
}

// probeStream is one probe's punch held open: the reply the handler sent,
// or the error it returned before sending one.
type probeStream struct {
	reply  *nodev1.PunchProbeReply
	err    error
	cancel context.CancelFunc
	done   chan error
}

// close ends the probe's request and returns what the handler returned.
func (p *probeStream) close() error {
	p.cancel()
	return <-p.done
}

// openProbe calls a probe's punch as the authenticated peer and holds its
// request open until close, the way a prober's stream stays open while it
// probes.
func openProbe(svc *LinkService, peer addr.IA, reflexive netip.AddrPort, nonce [16]byte) *probeStream {
	ctx, cancel := context.WithCancel(authenticated(peer))
	sent := make(chan *nodev1.PunchProbeReply, 1)
	p := &probeStream{cancel: cancel, done: make(chan error, 1)}
	go func() {
		p.done <- svc.punchProbe(ctx, &nodev1.PunchProbeRequest{
			ReflexiveAddr: reflexive.String(),
			Nonce:         nonce[:],
		}, func(r *nodev1.PunchProbeReply) error {
			sent <- r
			return nil
		})
	}()
	select {
	case p.reply = <-sent:
	case p.err = <-p.done:
		p.done <- p.err
	}
	return p
}

// TestPunchProbeAnswers checks a probe's punch: the handler sends the
// reflexive address of an ephemeral socket that echoes the caller's
// packets while the request stays open, returns once the request ends, and
// records nothing.
func TestPunchProbeAnswers(t *testing.T) {
	svc := punchService(t, nil)
	prober := udpSocket(t)
	nonce := [16]byte{7}
	p := openProbe(svc, linkIA, boundAddr(prober), nonce)
	if p.err != nil {
		t.Fatal(p.err)
	}
	theirs, err := netip.ParseAddrPort(p.reply.ReflexiveAddr)
	if err != nil {
		t.Fatal(err)
	}
	if rtt, err := probeRTT(context.Background(), prober, theirs, nonce); err != nil || rtt <= 0 {
		t.Errorf("the punched probe measured %v (%v), want a round trip", rtt, err)
	}
	if err := p.close(); err != nil {
		t.Errorf("the probe's handler returned %v once its request ended, want nil", err)
	}
	if entries, err := svc.Store.All(context.Background()); err != nil || len(entries) != 0 {
		t.Errorf("the probe recorded %v (%v), want nothing", entries, err)
	}
}

// TestPunchLinkRecordsTheCallersReflexiveAddress checks a link's punch: the
// caller's entry is a candidate on a fresh link address aimed at the
// caller's reflexive address, the reply names the entry's reflexive address
// and interface, and the caller's socket has the opens from the entry's
// link address, sent before the reply.
func TestPunchLinkRecordsTheCallersReflexiveAddress(t *testing.T) {
	svc := punchService(t, nil)
	caller := udpSocket(t)
	nonce := [16]byte{9}
	reply, err := linkPunch(svc, linkIA, boundAddr(caller), nonce, 7)
	if err != nil {
		t.Fatal(err)
	}
	entry := linkEntry(t, svc, linkIA)
	if entry.State != links.StateCandidate || entry.Remote != boundAddr(caller) ||
		entry.RemoteIfID != 7 {
		t.Errorf("the caller's entry = %+v, want a candidate aimed at %v, interface 7",
			entry, boundAddr(caller))
	}
	if reply.ReflexiveAddr != entry.Local.String() || reply.IfId != uint32(entry.IfID) {
		t.Errorf("the reply = %s/%d, want the entry's %v/%d",
			reply.ReflexiveAddr, reply.IfId, entry.Local, entry.IfID)
	}
	awaitOpen(t, caller, nonce, entry.Local)
}

// awaitOpen fails the test unless the socket holds the nonce's open from the
// given address. The opens left before the punch's reply: the deadline only
// bounds a read the queue answers at once.
func awaitOpen(t *testing.T, conn underlay.UDPConn, nonce [16]byte, from netip.AddrPort) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, src, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the socket has no open: %v", err)
	}
	p, ok := parsePunchPacket(buf[:n])
	if got := netip.AddrPortFrom(src.AddrPort().Addr().Unmap(), src.AddrPort().Port()); !ok ||
		p != (punchPacket{nonce: nonce, kind: punchOpen}) || got != from {
		t.Errorf("the socket has %+v from %v, want the nonce's open from %v", p, got, from)
	}
}

// TestPunchLinkMovesADownEntry checks a link's punch toward a caller whose
// standing entry is down — a NAT on the way remapped — naming the interface
// the entry pairs with: the entry moves to a fresh link address with its
// interface ID kept, aimed at the caller's reflexive address, and the
// caller's socket has the opens from the fresh address.
func TestPunchLinkMovesADownEntry(t *testing.T) {
	standing := liveLink(linkIA, 40001)
	standing.RemoteIfID = 6
	svc := punchService(t, func(s *LinkService) {
		if err := s.Store.Insert(context.Background(), standing); err != nil {
			t.Fatal(err)
		}
		s.Verdicts = func() map[uint16]bool { return map[uint16]bool{standing.IfID: false} }
	})
	caller := udpSocket(t)
	nonce := [16]byte{4}
	if _, err := linkPunch(svc, linkIA, boundAddr(caller), nonce, 6); err != nil {
		t.Fatal(err)
	}
	entry := linkEntry(t, svc, linkIA)
	if entry.IfID != standing.IfID || entry.Local == standing.Local ||
		entry.Remote != boundAddr(caller) || entry.RemoteIfID != 6 ||
		entry.State != links.StateEstablished {
		t.Errorf("the moved entry = %+v, want interface %d established on a fresh address "+
			"aimed at %v, interface 6", entry, standing.IfID, boundAddr(caller))
	}
	awaitOpen(t, caller, nonce, entry.Local)
}

// TestPunchLinkAdoptsTheUnfinishedEntry checks a link's punch toward a
// caller whose entry names no locator — the one an unfinished punch or
// promotion left: the punch adopts it, no second entry recorded.
func TestPunchLinkAdoptsTheUnfinishedEntry(t *testing.T) {
	svc := punchService(t, nil)
	left := &links.Link{
		NeighborIA: linkIA,
		Local:      linkAddr(t),
		State:      links.StateCandidate,
	}
	if err := svc.Store.Insert(context.Background(), left); err != nil {
		t.Fatal(err)
	}
	caller := udpSocket(t)
	if _, err := linkPunch(svc, linkIA, boundAddr(caller), [16]byte{1}, 3); err != nil {
		t.Fatal(err)
	}
	entries, err := svc.Store.All(context.Background())
	if err != nil || len(entries) != 1 {
		t.Fatalf("the table holds %v (%v), want the adopted entry alone", entries, err)
	}
	if e := entries[0]; e.IfID != left.IfID || e.Local != left.Local ||
		e.Remote != boundAddr(caller) || e.RemoteIfID != 3 {
		t.Errorf("the adopted entry = %+v, want the left one aimed at %v, interface 3",
			e, boundAddr(caller))
	}
}

// TestPunchRefusals checks what a link's punch refuses, each with its code.
func TestPunchRefusals(t *testing.T) {
	reflexive := netip.MustParseAddrPort("127.0.0.1:4242").String()
	valid := func() *nodev1.PunchRequest {
		return &nodev1.PunchRequest{ReflexiveAddr: reflexive, Nonce: make([]byte, 16), IfId: 3}
	}
	tests := []struct {
		name   string
		mutate func(*LinkService)
		peer   addr.IA
		req    func() *nodev1.PunchRequest
		want   connect.Code
	}{{
		name: "an unauthenticated caller",
		req:  valid,
		want: connect.CodePermissionDenied,
	}, {
		name: "a malformed reflexive address",
		peer: linkIA,
		req: func() *nodev1.PunchRequest {
			r := valid()
			r.ReflexiveAddr = "nowhere"
			return r
		},
		want: connect.CodeInvalidArgument,
	}, {
		name: "a short nonce",
		peer: linkIA,
		req: func() *nodev1.PunchRequest {
			r := valid()
			r.Nonce = make([]byte, 8)
			return r
		},
		want: connect.CodeInvalidArgument,
	}, {
		name: "no interface",
		peer: linkIA,
		req: func() *nodev1.PunchRequest {
			r := valid()
			r.IfId = 0
			return r
		},
		want: connect.CodeInvalidArgument,
	}, {
		name: "an interface out of range",
		peer: linkIA,
		req: func() *nodev1.PunchRequest {
			r := valid()
			r.IfId = 1 << 16
			return r
		},
		want: connect.CodeInvalidArgument,
	}, {
		name:   "a node that punches nothing",
		mutate: func(s *LinkService) { s.Reflector = nil },
		peer:   linkIA,
		req:    valid,
		want:   connect.CodeUnimplemented,
	}, {
		name: "no reflector answering",
		mutate: func(s *LinkService) {
			s.Reflector = func(context.Context) (netip.AddrPort, error) {
				return netip.AddrPort{}, errNoReflector
			}
		},
		peer: linkIA,
		req:  valid,
		want: connect.CodeUnavailable,
	}, {
		name: "a standing link that is up",
		mutate: func(s *LinkService) {
			if err := s.Store.Insert(context.Background(), liveLink(linkIA, 40001)); err != nil {
				t.Fatal(err)
			}
		},
		peer: linkIA,
		req:  valid,
		want: connect.CodeAlreadyExists,
	}, {
		name: "a down standing link paired with another interface",
		mutate: func(s *LinkService) {
			standing := liveLink(linkIA, 40001)
			standing.RemoteIfID = 9
			if err := s.Store.Insert(context.Background(), standing); err != nil {
				t.Fatal(err)
			}
			s.Verdicts = func() map[uint16]bool { return map[uint16]bool{standing.IfID: false} }
		},
		peer: linkIA,
		req:  valid,
		want: connect.CodeAlreadyExists,
	}, {
		name:   "the node's own punch in flight",
		mutate: func(s *LinkService) { s.Punching = func(addr.IA) bool { return true } },
		peer:   linkIA,
		req:    valid,
		want:   connect.CodeAborted,
	}, {
		name: "the link cap",
		mutate: func(s *LinkService) {
			s.MaxLinks = 1
			if err := s.Store.Insert(context.Background(), liveLink(linkIA2, 40002)); err != nil {
				t.Fatal(err)
			}
		},
		peer: linkIA,
		req:  valid,
		want: connect.CodeResourceExhausted,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := punchService(t, tt.mutate)
			ctx := context.Background()
			if !tt.peer.IsZero() {
				ctx = authenticated(tt.peer)
			}
			_, err := svc.Punch(ctx, tt.req())
			if got := connect.CodeOf(err); got != tt.want {
				t.Errorf("Punch = %v, want code %v", err, tt.want)
			}
		})
	}
}

// TestPunchRateCap checks the punch rate cap: a peer's second probe inside
// the interval is refused, while its link's punch beside the probe is not —
// a promotion's punch never waits out the probe that qualified it.
func TestPunchRateCap(t *testing.T) {
	svc := punchService(t, func(s *LinkService) { s.MinInterval = time.Hour })
	prober := udpSocket(t)
	first := openProbe(svc, linkIA, boundAddr(prober), [16]byte{1})
	if first.err != nil {
		t.Fatal(first.err)
	}
	second := openProbe(svc, linkIA, boundAddr(prober), [16]byte{2})
	if got := connect.CodeOf(second.err); got != connect.CodeResourceExhausted {
		t.Errorf("a second probe inside the interval = %v, want code %v",
			second.err, connect.CodeResourceExhausted)
	}
	if err := first.close(); err != nil {
		t.Errorf("the first probe's handler returned %v, want nil", err)
	}
	_ = second.close()
	if _, err := linkPunch(svc, linkIA, boundAddr(prober), [16]byte{3}, 5); err != nil {
		t.Errorf("the link's punch beside the probe = %v, want admitted", err)
	}
}

// stubPuncher answers the selection's punches with fixed results,
// recording the peers asked.
type stubPuncher struct {
	rtt       time.Duration
	reflexive netip.AddrPort
	ifID      uint16

	mtx         sync.Mutex
	probed      []addr.IA
	established []addr.IA
}

func (p *stubPuncher) Probe(_ context.Context, peer addr.IA) (time.Duration, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.probed = append(p.probed, peer)
	return p.rtt, nil
}

func (p *stubPuncher) Establish(
	_ context.Context, peer addr.IA, _ *links.Link,
) (netip.AddrPort, uint16, error) {

	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.established = append(p.established, peer)
	if !p.reflexive.IsValid() {
		return netip.AddrPort{}, 0, errors.New("no reflexive address")
	}
	return p.reflexive, p.ifID, nil
}

// TestProbePunchesUnansweredCandidates checks the probe's carrier for a
// candidate whose own report says its published rendezvous address answers
// nothing: the punch measures it.
func TestProbePunchesUnansweredCandidates(t *testing.T) {
	punch := &stubPuncher{rtt: 7 * time.Millisecond}
	s := &selection{cfg: SelectionConfig{
		Punch: punch,
		Paths: &scion.PathProvider{
			IA:     selIA,
			DB:     emptyPathDB{},
			Lookup: func(context.Context, addr.IA) []*pathdb.Segment { return nil },
		},
	}}
	e := DirectoryEntry{
		IA:             selPeer,
		RendezvousAddr: netip.MustParseAddrPort("192.0.2.9:30043"),
		Reach:          Reach{RendezvousUnanswered: true},
	}
	if sm := s.probe(context.Background(), e, nil); sm.m.direct != punch.rtt {
		t.Errorf("direct sample = %v, want the punch's %v", sm.m.direct, punch.rtt)
	}
	if want := []addr.IA{selPeer}; !slices.Equal(punch.probed, want) {
		t.Errorf("the punch probed %v, want %v", punch.probed, want)
	}
}

// TestEstablishmentPunchesUnansweredCandidates checks a promotion of a
// candidate whose published rendezvous address answers nothing: the punch
// seeds the entry with the peer's reflexive address and interface, and the
// confirm establishes it on the address its link observes — not the link
// address the peer claims behind its NAT.
func TestEstablishmentPunchesUnansweredCandidates(t *testing.T) {
	store := memory.New()
	reflexive := netip.MustParseAddrPort("192.0.2.9:26001")
	punch := &stubPuncher{reflexive: reflexive, ifID: 4}
	var dialedIfID uint16
	s := &selection{
		streaks: make(map[addr.IA]*peerStreak),
		cfg: SelectionConfig{
			IA:       selIA,
			Store:    store,
			LinkHost: netip.MustParseAddr("127.0.0.1"),
			Punch:    punch,
			Observed: func(uint16) netip.AddrPort { return reflexive },
			Link: linkRequester(func(_ context.Context, _ *scion.Addr,
				_ netip.AddrPort, ifID uint16) (*nodev1.LinkReply, error) {
				dialedIfID = ifID
				return &nodev1.LinkReply{LocalAddr: "10.0.0.9:31001", IfId: 4}, nil
			}),
		}}
	e := DirectoryEntry{
		IA:             selB,
		ControlAddr:    netip.MustParseAddrPort("192.0.2.9:30042"),
		RendezvousAddr: netip.MustParseAddrPort("192.0.2.9:30043"),
		Reach:          Reach{BehindNAT: true, RendezvousUnanswered: true},
	}
	if !s.establishLink(context.Background(), e, "the test") {
		t.Fatal("the establishment failed")
	}
	if want := []addr.IA{selB}; !slices.Equal(punch.established, want) {
		t.Errorf("the punch established %v, want %v", punch.established, want)
	}
	entry, err := store.ByNeighbor(context.Background(), selB)
	if err != nil || entry == nil {
		t.Fatalf("no entry recorded (%v)", err)
	}
	if entry.State != links.StateEstablished || entry.Remote != reflexive || entry.RemoteIfID != 4 {
		t.Errorf("the entry = %+v, want established on %v, interface 4", entry, reflexive)
	}
	if dialedIfID != entry.IfID {
		t.Errorf("the confirm offered interface %d, want the entry's %d", dialedIfID, entry.IfID)
	}

	// A punch that fails seeds nothing and confirms nothing.
	punch.reflexive = netip.AddrPort{}
	other := e
	other.IA = selA
	if s.establishLink(context.Background(), other, "the test") {
		t.Error("an establishment whose punch failed landed")
	}
	if l, err := store.ByNeighbor(context.Background(), selA); err != nil || l == nil ||
		l.Remote.IsValid() {
		t.Errorf("the failed punch's entry = %+v (%v), want a candidate naming no locator", l, err)
	}
}
