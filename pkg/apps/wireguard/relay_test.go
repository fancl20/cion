package wireguard

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"tailscale.com/derp"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// initiationTo builds a handshake initiation from the sender index, its mac1
// keyed to the responder's public key the way an initiator keys it and its
// sealed fields filler.
func initiationTo(responder PublicKey, sender uint32) []byte {
	var macs device.CookieGenerator
	macs.Init(device.NoisePublicKey(responder))
	return initiationWith(&macs, sender)
}

// initiationWith builds a handshake initiation from the sender index, its
// sealed fields filler and its macs the initiator's generator adds: mac1
// keyed to the responder's public key, and mac2 once the generator holds a
// cookie.
func initiationWith(macs *device.CookieGenerator, sender uint32) []byte {
	msg := make([]byte, device.MessageInitiationSize)
	msg[0] = device.MessageInitiationType
	binary.LittleEndian.PutUint32(msg[4:], sender)
	for i := 8; i < len(msg); i++ {
		msg[i] = byte(i)
	}
	macs.AddMacs(msg)
	return msg
}

// decodeCookieReply reads a cookie reply in WireGuard's wire layout: the
// type and the receiver index, little-endian, the nonce, and the sealed
// cookie.
func decodeCookieReply(t *testing.T, b []byte) *device.MessageCookieReply {
	t.Helper()
	if len(b) != device.MessageCookieReplySize {
		t.Fatalf("the cookie reply is %d bytes, want %d", len(b), device.MessageCookieReplySize)
	}
	reply := &device.MessageCookieReply{
		Type:     binary.LittleEndian.Uint32(b),
		Receiver: binary.LittleEndian.Uint32(b[4:]),
	}
	copy(reply.Nonce[:], b[8:])
	copy(reply.Cookie[:], b[8+len(reply.Nonce):])
	return reply
}

// responseTo builds a handshake response from the sender index to the
// receiver index.
func responseTo(sender, receiver uint32) []byte {
	msg := make([]byte, device.MessageResponseSize)
	msg[0] = device.MessageResponseType
	binary.LittleEndian.PutUint32(msg[4:], sender)
	binary.LittleEndian.PutUint32(msg[8:], receiver)
	return msg
}

// cookieReplyTo builds a cookie reply to the receiver index.
func cookieReplyTo(receiver uint32) []byte {
	msg := make([]byte, device.MessageCookieReplySize)
	msg[0] = device.MessageCookieReplyType
	binary.LittleEndian.PutUint32(msg[4:], receiver)
	return msg
}

// transportTo builds a transport message to the receiver index, the payload
// standing in for its ciphertext.
func transportTo(receiver uint32, payload string) []byte {
	msg := make([]byte, device.MessageTransportSize+len(payload))
	msg[0] = device.MessageTransportType
	binary.LittleEndian.PutUint32(msg[4:], receiver)
	copy(msg[device.MessageTransportOffsetContent:], payload)
	return msg
}

// classified is one classification, by fields go-cmp reads: the
// verdict, and where onward leads — the node for a host's datagram, the
// host's endpoint for a node's.
type classified struct {
	Verdict relayVerdict
	Node    addr.IA
	Host    string
}

// classifyHost classifies a host's datagram on the relay.
func classifyHost(r *hostRelay, pkt []byte, from netip.AddrPort) classified {
	node, _, verdict := r.fromHost(pkt, from)
	return classified{Verdict: verdict, Node: node}
}

// classifyNode classifies a node's datagram on the relay.
func classifyNode(r *hostRelay, pkt []byte, node addr.IA) classified {
	host, verdict := r.fromNode(pkt, node)
	got := classified{Verdict: verdict}
	if host.IsValid() {
		got.Host = host.String()
	}
	return got
}

// expectClassified fails the test unless the classification is the one
// wanted.
func expectClassified(t *testing.T, what string, want, got classified) {
	t.Helper()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%s (-want +got):\n%s", what, diff)
	}
}

// TestRelayClassifies checks the relay's verdicts and the table between
// them: an initiation keyed to the node's own key reaches the host device;
// one keyed to another node's goes onward to that node, the node's response
// returns to the host's endpoint, and later datagrams follow the recorded
// indices both ways; an index the relay recorded for one node means nothing
// from another, and an unknown index reaches the host device from either
// side; a node's initiation keyed to the node's own key reaches the host
// device and one keyed to another drops, as does a host's keyed to no node's
// key; a copy of an initiation keeps its session's endpoint, and a host's
// later handshake from a new endpoint records it for the session it begins.
func TestRelayClassifies(t *testing.T) {
	self := addr.MustIAFrom(20, 0xff0000000281)
	exit := addr.MustIAFrom(20, 0xff0000000282)
	other := addr.MustIAFrom(20, 0xff0000000283)
	_, ownPub := newKeyPair(t)
	_, exitPub := newKeyPair(t)
	_, otherPub := newKeyPair(t)
	_, strangerPub := newKeyPair(t)
	r := newHostRelay(self, ownPub, nil, nil, &counters{})
	r.setNodes([]Entry{
		{IA: self, PublicKey: ownPub},
		{IA: exit, PublicKey: exitPub},
		{IA: other, PublicKey: otherPub},
	})
	hostA := netip.MustParseAddrPort("198.51.100.7:41641")
	hostB := netip.MustParseAddrPort("198.51.100.8:41641")
	fromHost := func(pkt []byte, from netip.AddrPort) classified { return classifyHost(r, pkt, from) }
	fromNode := func(pkt []byte, node addr.IA) classified { return classifyNode(r, pkt, node) }
	toDevice := classified{Verdict: relayToDevice}
	toExit := classified{Verdict: relayOnward, Node: exit}

	for _, step := range []struct {
		name string
		got  func() classified
		want classified
	}{
		{"a host's initiation keyed to the node",
			func() classified { return fromHost(initiationTo(ownPub, 0x01), hostA) }, toDevice},
		{"a host's initiation keyed to the exit",
			func() classified { return fromHost(initiationTo(exitPub, 0x11), hostA) }, toExit},
		{"a host's initiation keyed to no node",
			func() classified { return fromHost(initiationTo(strangerPub, 0x02), hostA) },
			classified{Verdict: relayDrop}},
		{"the exit's response",
			func() classified { return fromNode(responseTo(0x22, 0x11), exit) },
			classified{Verdict: relayOnward, Host: hostA.String()}},
		{"the host's transport to the exit's index",
			func() classified { return fromHost(transportTo(0x22, "up"), hostA) }, toExit},
		{"the host's cookie reply to the exit's index",
			func() classified { return fromHost(cookieReplyTo(0x22), hostA) }, toExit},
		{"the exit's transport to the host's index",
			func() classified { return fromNode(transportTo(0x11, "down"), exit) },
			classified{Verdict: relayOnward, Host: hostA.String()}},
		{"the exit's cookie reply to the host's index",
			func() classified { return fromNode(cookieReplyTo(0x11), exit) },
			classified{Verdict: relayOnward, Host: hostA.String()}},
		{"another node's transport to the host's index",
			func() classified { return fromNode(transportTo(0x11, "other"), other) }, toDevice},
		{"a host's transport to an unknown index",
			func() classified { return fromHost(transportTo(0x99, "stray"), hostA) }, toDevice},
		{"a node's transport to an unknown index",
			func() classified { return fromNode(transportTo(0x98, "stray"), exit) }, toDevice},
		{"a node's initiation keyed to the node",
			func() classified { return fromNode(initiationTo(ownPub, 0x33), exit) }, toDevice},
		{"a node's initiation keyed to a host",
			func() classified { return fromNode(initiationTo(strangerPub, 0x34), exit) },
			classified{Verdict: relayDrop}},
		{"a datagram of no message format",
			func() classified { return fromHost([]byte("not wireguard"), hostA) }, toDevice},
		{"a copy of the initiation from elsewhere",
			func() classified { return fromHost(initiationTo(exitPub, 0x11), hostB) }, toExit},
		{"the exit's transport after the copy",
			func() classified { return fromNode(transportTo(0x11, "kept"), exit) },
			classified{Verdict: relayOnward, Host: hostA.String()}},
		{"the host's later handshake from a new endpoint",
			func() classified { return fromHost(initiationTo(exitPub, 0x12), hostB) }, toExit},
		{"the exit's response to it",
			func() classified { return fromNode(responseTo(0x23, 0x12), exit) },
			classified{Verdict: relayOnward, Host: hostB.String()}},
		{"the host's transport on the new session",
			func() classified { return fromHost(transportTo(0x23, "new"), hostB) }, toExit},
	} {
		if diff := cmp.Diff(step.want, step.got()); diff != "" {
			t.Errorf("%s (-want +got):\n%s", step.name, diff)
		}
	}
}

// fakeClock is a clock the test moves by hand.
type fakeClock struct {
	mtx sync.Mutex
	t   time.Time
}

func (c *fakeClock) now() time.Time {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.t = c.t.Add(d)
}

// TestRelayForgetsSilentSessions checks the table's expiry: a session whose
// datagrams keep passing outlives the rejection time many times over, one
// silent past it is forgotten — a datagram of it reaches the host device
// from either side — and the next initiation sweeps the silent sessions no
// datagram looked up.
func TestRelayForgetsSilentSessions(t *testing.T) {
	self := addr.MustIAFrom(20, 0xff0000000284)
	exit := addr.MustIAFrom(20, 0xff0000000285)
	_, ownPub := newKeyPair(t)
	_, exitPub := newKeyPair(t)
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	r := newHostRelay(self, ownPub, nil, nil, &counters{})
	r.now = clock.now
	r.setNodes([]Entry{{IA: exit, PublicKey: exitPub}})
	host := netip.MustParseAddrPort("198.51.100.7:41641")
	verdict := func(_ any, v relayVerdict) relayVerdict { return v }
	hostVerdict := func(_ addr.IA, _ []byte, v relayVerdict) relayVerdict { return v }

	// Two sessions with the exit, both answered.
	for _, s := range []struct{ host, node uint32 }{{0x11, 0x21}, {0x12, 0x22}} {
		r.fromHost(initiationTo(exitPub, s.host), host)
		r.fromNode(responseTo(s.node, s.host), exit)
	}
	// The first carries a datagram every two minutes, past three rejection
	// times; the second falls silent.
	for range 5 {
		clock.advance(2 * time.Minute)
		if v := hostVerdict(r.fromHost(transportTo(0x21, "keepalive"), host)); v != relayOnward {
			t.Fatalf("the busy session's datagram went %v, want onward", v)
		}
	}
	if v := verdict(r.fromNode(transportTo(0x11, "busy"), exit)); v != relayOnward {
		t.Errorf("the busy session's answer went %v, want onward", v)
	}

	// A third session's initiation sweeps the silent second from the table.
	r.fromHost(initiationTo(exitPub, 0x13), host)
	sessions := func() []uint32 {
		var held []uint32
		for key := range r.byHost {
			held = append(held, key.index)
		}
		for index := range r.byNode {
			held = append(held, index)
		}
		slices.Sort(held)
		return held
	}
	if diff := cmp.Diff([]uint32{0x11, 0x13, 0x21}, sessions()); diff != "" {
		t.Errorf("the indices held after the sweep (-want +got):\n%s", diff)
	}
	if v := hostVerdict(r.fromHost(transportTo(0x22, "silent"), host)); v != relayToDevice {
		t.Errorf("the swept session's datagram went %v, want the host device", v)
	}

	// The busy session falls silent past the rejection time: its datagrams
	// reach the host device from either side, and the table forgets it.
	clock.advance(device.RejectAfterTime + time.Second)
	if v := verdict(r.fromNode(transportTo(0x11, "late"), exit)); v != relayToDevice {
		t.Errorf("the silent session's answer went %v, want the host device", v)
	}
	if v := hostVerdict(r.fromHost(transportTo(0x21, "late"), host)); v != relayToDevice {
		t.Errorf("the silent session's datagram went %v, want the host device", v)
	}
	if diff := cmp.Diff([]uint32{0x13}, sessions()); diff != "" {
		t.Errorf("the indices held after the silence (-want +got):\n%s", diff)
	}
}

// newExitRelay builds the relay of a node whose directory holds one other
// node, exit, on the test's clock, and returns it beside the exit's public
// key.
func newExitRelay(t *testing.T, exit addr.IA, clock *fakeClock) (*hostRelay, PublicKey) {
	t.Helper()
	_, ownPub := newKeyPair(t)
	_, exitPub := newKeyPair(t)
	r := newHostRelay(addr.MustIAFrom(20, 0xff0000000280), ownPub, nil, nil, &counters{})
	r.now = clock.now
	r.setNodes([]Entry{{IA: exit, PublicKey: exitPub}})
	return r, exitPub
}

// TestRelayExpiresPendingSessions checks the two lifetimes: a pending
// session lives pendingLifetime from its initiation, which a copy of the
// initiation neither extends nor moves to the copy's endpoint — the node's
// response just before reaches the host's first endpoint, and one at
// pendingLifetime reaches the host device — while an answered session
// outlives pendingLifetime. The pending counts end empty.
func TestRelayExpiresPendingSessions(t *testing.T) {
	exit := addr.MustIAFrom(20, 0xff000000028a)
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	r, exitPub := newExitRelay(t, exit, clock)
	hostA := netip.MustParseAddrPort("198.51.100.7:41641")
	hostB := netip.MustParseAddrPort("198.51.100.8:41641")
	toExit := classified{Verdict: relayOnward, Node: exit}

	expectClassified(t, "the first initiation", toExit, classifyHost(r, initiationTo(exitPub, 0x11), hostA))
	expectClassified(t, "the second initiation", toExit, classifyHost(r, initiationTo(exitPub, 0x12), hostA))
	clock.advance(pendingLifetime - time.Millisecond)
	expectClassified(t, "a copy of the first from elsewhere", toExit,
		classifyHost(r, initiationTo(exitPub, 0x11), hostB))
	expectClassified(t, "a copy of the second", toExit, classifyHost(r, initiationTo(exitPub, 0x12), hostA))
	expectClassified(t, "the exit's response to the first",
		classified{Verdict: relayOnward, Host: hostA.String()}, classifyNode(r, responseTo(0x21, 0x11), exit))
	clock.advance(time.Millisecond)
	expectClassified(t, "the exit's response to the second at pendingLifetime",
		classified{Verdict: relayToDevice}, classifyNode(r, responseTo(0x22, 0x12), exit))
	clock.advance(time.Minute)
	expectClassified(t, "the host's transport on the answered session a minute later", toExit,
		classifyHost(r, transportTo(0x21, "answered"), hostA))
	if r.pending != 0 || len(r.perSource) != 0 {
		t.Errorf("pending sessions at the end = %d, by source %v; want none", r.pending, r.perSource)
	}
}

// TestRelayBoundsPendingSessionsPerSource checks the bound on one source
// address: holding maxPendingPerSource pending sessions, the address gets
// no more from any port while another address still does, and the node's
// response to one of them frees one place for the address.
func TestRelayBoundsPendingSessionsPerSource(t *testing.T) {
	exit := addr.MustIAFrom(20, 0xff000000028b)
	r, exitPub := newExitRelay(t, exit, &fakeClock{t: time.Unix(1_000_000, 0)})
	crowded := netip.MustParseAddr("198.51.100.7")
	from := func(port uint16) netip.AddrPort { return netip.AddrPortFrom(crowded, port) }
	toExit := classified{Verdict: relayOnward, Node: exit}
	drop := classified{Verdict: relayDrop}

	for i := range uint32(maxPendingPerSource) {
		if got := classifyHost(r, initiationTo(exitPub, 0x100+i), from(uint16(40000+i))); got != toExit {
			t.Fatalf("initiation %d from the address = %+v, want onward to the exit", i, got)
		}
	}
	expectClassified(t, "an initiation past the address's bound", drop,
		classifyHost(r, initiationTo(exitPub, 0x200), from(50000)))
	expectClassified(t, "another address's initiation", toExit,
		classifyHost(r, initiationTo(exitPub, 0x201), netip.MustParseAddrPort("198.51.100.8:41641")))
	expectClassified(t, "the exit's response to the address's first",
		classified{Verdict: relayOnward, Host: from(40000).String()},
		classifyNode(r, responseTo(0x300, 0x100), exit))
	expectClassified(t, "the address's initiation after the response", toExit,
		classifyHost(r, initiationTo(exitPub, 0x202), from(50000)))
	expectClassified(t, "the address's next initiation", drop,
		classifyHost(r, initiationTo(exitPub, 0x203), from(50001)))
}

// TestRelayBoundsPendingSessionsPerIPv6Block checks an IPv6 source is its
// /64: maxPendingPerSource pending sessions from as many addresses of one
// /64 hold the block's bound, so another address of the block gets none,
// while an address of the next /64 still does.
func TestRelayBoundsPendingSessionsPerIPv6Block(t *testing.T) {
	exit := addr.MustIAFrom(20, 0xff000000028d)
	r, exitPub := newExitRelay(t, exit, &fakeClock{t: time.Unix(1_000_000, 0)})
	block := netip.MustParsePrefix("2001:db8:0:1::/64")
	from := func(host uint32) netip.AddrPort {
		octets := block.Addr().As16()
		binary.BigEndian.PutUint32(octets[12:], host)
		return netip.AddrPortFrom(netip.AddrFrom16(octets), 41641)
	}
	toExit := classified{Verdict: relayOnward, Node: exit}

	for i := range uint32(maxPendingPerSource) {
		if got := classifyHost(r, initiationTo(exitPub, 0x100+i), from(i+1)); got != toExit {
			t.Fatalf("initiation %d from the block = %+v, want onward to the exit", i, got)
		}
	}
	expectClassified(t, "another address of the block", classified{Verdict: relayDrop},
		classifyHost(r, initiationTo(exitPub, 0x200), from(0xffff)))
	expectClassified(t, "an address of the next block", toExit,
		classifyHost(r, initiationTo(exitPub, 0x201), netip.MustParseAddrPort("[2001:db8:0:2::1]:41641")))
}

// TestRelayBoundsPendingSessionsInTotal checks the total bound, lowered to
// 8, which puts the relay under load from its first pending session: with
// the cookie the host's generator consumed, initiations carrying mac2 fill
// the bound and the one past it drops; the node's response to a pending
// session frees one place, and pendingLifetime frees every place the
// pending sessions held.
func TestRelayBoundsPendingSessionsInTotal(t *testing.T) {
	exit := addr.MustIAFrom(20, 0xff000000028c)
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	r, exitPub := newExitRelay(t, exit, clock)
	r.maxPending = 8
	host := netip.MustParseAddrPort("198.51.100.7:41641")
	toExit := classified{Verdict: relayOnward, Node: exit}
	drop := classified{Verdict: relayDrop}
	var macs device.CookieGenerator
	macs.Init(device.NoisePublicKey(exitPub))
	fill := func(what string, senders ...uint32) {
		t.Helper()
		for _, sender := range senders {
			if got := classifyHost(r, initiationWith(&macs, sender), host); got != toExit {
				t.Fatalf("%s %#x = %+v, want onward to the exit", what, sender, got)
			}
		}
	}

	fill("the first initiation", 0x100)
	_, reply, verdict := r.fromHost(initiationWith(&macs, 0x101), host)
	if verdict != relayCookie {
		t.Fatalf("the initiation under load without mac2 went %v, want a cookie reply", verdict)
	}
	if !macs.ConsumeReply(decodeCookieReply(t, reply)) {
		t.Fatal("the host's generator refused the cookie reply")
	}
	fill("an initiation carrying mac2", 0x102, 0x103, 0x104, 0x105, 0x106, 0x107, 0x108)
	expectClassified(t, "an initiation past the bound", drop, classifyHost(r, initiationWith(&macs, 0x109), host))
	expectClassified(t, "the exit's response to the first",
		classified{Verdict: relayOnward, Host: host.String()}, classifyNode(r, responseTo(0x200, 0x100), exit))
	fill("the initiation after the response", 0x10a)
	expectClassified(t, "the next initiation", drop, classifyHost(r, initiationWith(&macs, 0x10b), host))
	clock.advance(pendingLifetime)
	fill("an initiation past the pending lifetime", 0x10c, 0x10d, 0x10e, 0x10f, 0x110, 0x111, 0x112, 0x113)
}

// TestRelayAsksForCookiesUnderLoad checks the cookie exchange, the bound
// lowered to 8 so one pending session reaches its eighth: an initiation
// without mac2 gets a cookie reply to its sender index and is recorded
// nowhere; the host's generator, keyed to the exit's key, consumes the
// reply, and its next initiation, carrying mac2, is admitted. The load
// outlasts the pending sessions by UnderLoadAfterTime, after which an
// initiation without mac2 is admitted again.
func TestRelayAsksForCookiesUnderLoad(t *testing.T) {
	exit := addr.MustIAFrom(20, 0xff000000028d)
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	r, exitPub := newExitRelay(t, exit, clock)
	r.maxPending = 8
	hostA := netip.MustParseAddrPort("198.51.100.7:41641")
	hostB := netip.MustParseAddrPort("198.51.100.8:41641")
	toExit := classified{Verdict: relayOnward, Node: exit}

	expectClassified(t, "the initiation before the load", toExit,
		classifyHost(r, initiationTo(exitPub, 0x11), hostA))
	var macs device.CookieGenerator
	macs.Init(device.NoisePublicKey(exitPub))
	_, reply, verdict := r.fromHost(initiationWith(&macs, 0x21), hostB)
	if verdict != relayCookie {
		t.Fatalf("the initiation under load without mac2 went %v, want a cookie reply", verdict)
	}
	expectClassified(t, "the exit's response to the initiation the cookie answered",
		classified{Verdict: relayToDevice}, classifyNode(r, responseTo(0x31, 0x21), exit))
	cookie := decodeCookieReply(t, reply)
	if cookie.Type != device.MessageCookieReplyType || cookie.Receiver != 0x21 {
		t.Errorf("the cookie reply is of type %d to %#x, want type %d to the sender index 0x21",
			cookie.Type, cookie.Receiver, device.MessageCookieReplyType)
	}
	if !macs.ConsumeReply(cookie) {
		t.Fatal("the host's generator refused the cookie reply")
	}
	expectClassified(t, "the host's next initiation, carrying mac2", toExit,
		classifyHost(r, initiationWith(&macs, 0x22), hostB))

	// The exit answers both sessions; the load lasts UnderLoadAfterTime
	// past the last initiation that met it.
	for _, s := range []struct{ host, node uint32 }{{0x11, 0x41}, {0x22, 0x42}} {
		if _, v := r.fromNode(responseTo(s.node, s.host), exit); v != relayOnward {
			t.Fatalf("the exit's response to %#x went %v, want onward", s.host, v)
		}
	}
	clock.advance(device.UnderLoadAfterTime - time.Millisecond)
	if _, _, v := r.fromHost(initiationTo(exitPub, 0x23), hostB); v != relayCookie {
		t.Errorf("an initiation without mac2 before the load passed went %v, want a cookie reply", v)
	}
	clock.advance(time.Millisecond)
	expectClassified(t, "an initiation without mac2 once the load passed", toExit,
		classifyHost(r, initiationTo(exitPub, 0x24), hostB))
}

// TestRelayKeepsCheckersAcrossDirectories checks the checkers across
// directories, the relay under load throughout: a cookie issued before a
// directory re-applies the exit's ISD-AS and key, whatever else its entry
// changes, still admits the host's initiation carrying its mac2, while a
// directory changing the exit's key verifies the new key alone, under a
// checker that issued no cookie yet.
func TestRelayKeepsCheckersAcrossDirectories(t *testing.T) {
	exit := addr.MustIAFrom(20, 0xff000000028e)
	r, exitPub := newExitRelay(t, exit, &fakeClock{t: time.Unix(1_000_000, 0)})
	// An eighth of four is none: every initiation meets the load.
	r.maxPending = 4
	host := netip.MustParseAddrPort("198.51.100.7:41641")
	var macs device.CookieGenerator
	macs.Init(device.NoisePublicKey(exitPub))
	_, reply, verdict := r.fromHost(initiationWith(&macs, 0x11), host)
	if verdict != relayCookie {
		t.Fatalf("the initiation without mac2 went %v, want a cookie reply", verdict)
	}
	if !macs.ConsumeReply(decodeCookieReply(t, reply)) {
		t.Fatal("the host's generator refused the cookie reply")
	}

	entry := Entry{IA: exit, PublicKey: exitPub, HostEndpoint: netip.MustParseAddrPort("203.0.113.7:41641")}
	r.setNodes([]Entry{entry})
	expectClassified(t, "the initiation carrying the issued cookie's mac2",
		classified{Verdict: relayOnward, Node: exit}, classifyHost(r, initiationWith(&macs, 0x12), host))

	_, newPub := newKeyPair(t)
	entry.PublicKey = newPub
	r.setNodes([]Entry{entry})
	expectClassified(t, "an initiation keyed to the exit's old key", classified{Verdict: relayDrop},
		classifyHost(r, initiationWith(&macs, 0x13), host))
	if _, _, v := r.fromHost(initiationTo(newPub, 0x14), host); v != relayCookie {
		t.Errorf("an initiation keyed to the exit's new key went %v, want a cookie reply", v)
	}
}

// relayLab is the SCION network the relay tests' nodes share: one internal
// link every conn on it submits to, which hands each packet addressed to the
// host relay service — unchanged — to the relay socket serving the ISD-AS
// the packet names, and drops every other packet.
type relayLab struct {
	link *net.UDPConn

	mtx    sync.Mutex
	relays map[addr.IA]*net.UDPAddr
}

// newRelayLab stands the lab's link until the test ends.
func newRelayLab(t *testing.T) *relayLab {
	t.Helper()
	link, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	l := &relayLab{link: link, relays: make(map[addr.IA]*net.UDPAddr)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.forward()
	}()
	t.Cleanup(func() {
		_ = link.Close()
		<-done
	})
	return l
}

// forward hands each packet the link receives onward until the link closes.
func (l *relayLab) forward() {
	buf := make([]byte, 64<<10)
	for {
		n, err := l.link.Read(buf)
		if err != nil {
			return
		}
		var scn slayers.SCION
		if err := scn.DecodeFromBytes(buf[:n], gopacket.NilDecodeFeedback); err != nil {
			continue
		}
		dst, err := scn.DstAddr()
		if err != nil || dst.Type() != addr.HostTypeSVC || dst.SVC() != SvcHostRelay {
			continue
		}
		l.mtx.Lock()
		to, ok := l.relays[scn.DstIA]
		l.mtx.Unlock()
		if ok {
			_, _ = l.link.WriteToUDP(buf[:n], to)
		}
	}
}

// newConn is a Config.NewConn binding the conns of ia on the lab, their
// one-hop writes leaving through the links the topic names.
func (l *relayLab) newConn(ia addr.IA, links *bus.Topic[bus.LinkState]) func() (*scion.Conn, error) {
	return func() (*scion.Conn, error) {
		return scion.NewConn(scion.ConnConfig{
			IA:           ia,
			Bind:         "127.0.0.1:0",
			InternalAddr: l.link.LocalAddr().String(),
			MACKey:       testMACKey,
			Links:        links,
		})
	}
}

// attach puts an application of ia on the lab: its conns submit to the
// link, and its paths compose from the segments.
func (l *relayLab) attach(ia addr.IA, segs ...*pathdb.Segment) func(*Config) {
	return func(cfg *Config) {
		cfg.NewConn = l.newConn(ia, nil)
		cfg.Paths = &scion.PathProvider{IA: ia, DB: &memDB{segs: segs}}
	}
}

// serve hands the lab's packets for ia's relay service to the conn.
func (l *relayLab) serve(ia addr.IA, c *scion.Conn) {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	l.relays[ia] = net.UDPAddrFromAddrPort(c.LocalAddr().(*scion.Addr).Addr)
}

// runApp runs the application until the test ends, joining its stop before
// the application closes.
func runApp(t *testing.T, a *App) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	returned := make(chan error, 1)
	go func() { returned <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-returned; err != nil {
			t.Errorf("Run = %v", err)
		}
	})
}

// TestRelayCarriesDatagramsUnchanged checks the relay on its sockets: a
// host's initiation keyed to another node's key leaves for that node's relay
// service byte for byte, the node's response returns to the host's endpoint
// byte for byte, and the transport messages after it follow the recorded
// indices both ways the same; an initiation keyed to the node's own key and
// a datagram naming no recorded index reach the host device — a node's with
// a relay endpoint naming the node; a node's initiation toward a host and a
// host's keyed to no node's key drop; a DERP-sourced datagram reaches the
// host device unclassified; and the counters count each.
func TestRelayCarriesDatagramsUnchanged(t *testing.T) {
	lab := newRelayLab(t)
	homeIA := addr.MustIAFrom(20, 0xff0000000286)
	exitIA := addr.MustIAFrom(20, 0xff0000000287)
	db := newFlippableTrustDB(t, homeIA)
	db.enroll(t)
	home, _ := newTestWireguard(t, homeIA, db,
		lab.attach(homeIA, upSegmentAt(t, time.Now(), exitIA, homeIA)))
	lab.serve(homeIA, home.relay.conn)
	linkState := new(bus.Topic[bus.LinkState])
	linkState.Publish(bus.NewLinkState(bus.Link{Entry: links.Link{IfID: 1, NeighborIA: homeIA}}))
	exit, err := lab.newConn(exitIA, linkState)()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exit.Close() })
	lab.serve(exitIA, exit)
	_, exitPub := newKeyPair(t)
	_, strangerPub := newKeyPair(t)
	home.applyDirectory(t.Context(), Directory{Nodes: []Entry{
		{IA: homeIA, PublicKey: home.PublicKey(), Overlay: netip.MustParsePrefix("100.64.0.0/24")},
		{IA: exitIA, PublicKey: exitPub, Overlay: netip.MustParsePrefix("100.64.1.0/24")},
	}})
	devices := make(chan datagram, 16)
	if err := home.host.subscribe(&hostBind{}, devices); err != nil {
		t.Fatal(err)
	}
	runApp(t, home)

	host, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	hostLeg := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"),
		uint16(host.LocalAddr().(*net.UDPAddr).Port)).String()
	homePort := net.UDPAddrFromAddrPort(netip.AddrPortFrom(testHost, home.HostPort()))
	fromHost := func(pkt []byte) {
		t.Helper()
		if _, err := host.WriteToUDP(pkt, homePort); err != nil {
			t.Fatal(err)
		}
	}
	fromExit := func(pkt []byte) {
		t.Helper()
		if _, err := exit.WriteTo(pkt, &scion.Addr{IA: homeIA, Service: SvcHostRelay}); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 64<<10)
	atHost := func() []byte {
		t.Helper()
		_ = host.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := host.Read(buf)
		if err != nil {
			t.Fatalf("the host received nothing: %v", err)
		}
		return slices.Clone(buf[:n])
	}
	atExit := func() []byte {
		t.Helper()
		_ = exit.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, from, err := exit.ReadFrom(buf)
		if err != nil {
			t.Fatalf("the exit received nothing: %v", err)
		}
		if ia := from.(*scion.Addr).IA; !ia.Equal(homeIA) {
			t.Errorf("the exit's datagram came from %s, want the home node %s", ia, homeIA)
		}
		return slices.Clone(buf[:n])
	}
	// arrival is one datagram the host device received: its bytes and the
	// leg its endpoint names.
	type arrival struct {
		Data []byte
		Leg  string
	}
	atDevice := func() arrival {
		t.Helper()
		select {
		case dg := <-devices:
			return arrival{Data: dg.data, Leg: dg.src.DstToString()}
		case <-time.After(5 * time.Second):
			t.Fatal("nothing reached the host device")
			return arrival{}
		}
	}
	check := func(what string, want, got any) {
		t.Helper()
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("%s (-want +got):\n%s", what, diff)
		}
	}

	own := initiationTo(home.PublicKey(), 0x01)
	fromHost(own)
	check("the initiation keyed to the home node", arrival{Data: own, Leg: hostLeg}, atDevice())

	initiation := initiationTo(exitPub, 0x11)
	fromHost(initiation)
	check("the initiation the exit received", initiation, atExit())
	response := responseTo(0x22, 0x11)
	fromExit(response)
	check("the response the host received", response, atHost())
	up := transportTo(0x22, "up")
	fromHost(up)
	check("the transport the exit received", up, atExit())
	down := transportTo(0x11, "down")
	fromExit(down)
	check("the transport the host received", down, atHost())

	stray := transportTo(0x99, "stray")
	fromHost(stray)
	check("the host's datagram to no recorded index", arrival{Data: stray, Leg: hostLeg}, atDevice())
	forHome := transportTo(0x98, "for the home node's own session")
	fromExit(forHome)
	check("the exit's datagram to no recorded index",
		arrival{Data: forHome, Leg: "relay:" + exitIA.String()}, atDevice())

	// Each reader takes its datagrams in order, so the datagram after a
	// drop reaching the host device marks the drop counted.
	fromExit(initiationTo(strangerPub, 0x33))
	after := transportTo(0x97, "after the node's initiation")
	fromExit(after)
	check("the exit's datagram after its initiation",
		arrival{Data: after, Leg: "relay:" + exitIA.String()}, atDevice())
	fromHost(initiationTo(strangerPub, 0x44))
	after = transportTo(0x96, "after the host's initiation")
	fromHost(after)
	check("the host's datagram after its initiation", arrival{Data: after, Leg: hostLeg}, atDevice())

	// A DERP-sourced datagram reaches the host device unclassified, an
	// initiation keyed to the exit's key among them.
	_, derpHost := newKeyPair(t)
	viaDERP := initiationTo(exitPub, 0x55)
	(&derpBridge{cfg: derpBridgeConfig{Socket: home.host}}).deliver(
		derp.ReceivedPacket{Source: nodePublicOf(derpHost), Data: viaDERP})
	check("the DERP-sourced initiation", arrival{Data: viaDERP, Leg: "derp:" + derpHost.String()}, atDevice())

	counts := home.Counters()
	check("the relay's counters", map[string]int64{"relayed": 4, "drops": 2, "host": 6},
		map[string]int64{
			"relayed": counts["wireguard.relayed_datagrams_total"],
			"drops":   counts["wireguard.relay_drops_total"],
			"host":    counts["wireguard.host_datagrams_total"],
		})
}

// TestRelayAnswersCookiesUnderLoad checks the cookie exchange on the relay's
// sockets, the relay's bound lowered to 2 so every initiation meets the
// load: a host's initiation without mac2 gets a cookie reply from the
// shared port and reaches neither the exit nor the host device; the host's
// generator consumes the reply, and its next initiations, carrying mac2,
// leave for the exit byte for byte until the pending sessions reach their
// bound, where one drops; and the counters count each.
func TestRelayAnswersCookiesUnderLoad(t *testing.T) {
	lab := newRelayLab(t)
	homeIA := addr.MustIAFrom(20, 0xff000000028f)
	exitIA := addr.MustIAFrom(20, 0xff0000000290)
	db := newFlippableTrustDB(t, homeIA)
	db.enroll(t)
	home, _ := newTestWireguard(t, homeIA, db,
		lab.attach(homeIA, upSegmentAt(t, time.Now(), exitIA, homeIA)))
	// An eighth of two is none: every initiation meets the load.
	home.relay.maxPending = 2
	lab.serve(homeIA, home.relay.conn)
	linkState := new(bus.Topic[bus.LinkState])
	linkState.Publish(bus.NewLinkState(bus.Link{Entry: links.Link{IfID: 1, NeighborIA: homeIA}}))
	exit, err := lab.newConn(exitIA, linkState)()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exit.Close() })
	lab.serve(exitIA, exit)
	_, exitPub := newKeyPair(t)
	home.applyDirectory(t.Context(), Directory{Nodes: []Entry{
		{IA: homeIA, PublicKey: home.PublicKey(), Overlay: netip.MustParsePrefix("100.64.0.0/24")},
		{IA: exitIA, PublicKey: exitPub, Overlay: netip.MustParsePrefix("100.64.1.0/24")},
	}})
	devices := make(chan datagram, 16)
	if err := home.host.subscribe(&hostBind{}, devices); err != nil {
		t.Fatal(err)
	}
	runApp(t, home)

	host, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	sharedPort := netip.AddrPortFrom(testHost, home.HostPort())
	fromHost := func(pkt []byte) {
		t.Helper()
		if _, err := host.WriteToUDPAddrPort(pkt, sharedPort); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 64<<10)
	atHost := func() []byte {
		t.Helper()
		_ = host.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, from, err := host.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("the host received nothing: %v", err)
		}
		if from := netip.AddrPortFrom(from.Addr().Unmap(), from.Port()); from != sharedPort {
			t.Errorf("the host's datagram came from %s, want the shared port %s", from, sharedPort)
		}
		return slices.Clone(buf[:n])
	}
	atExit := func() []byte {
		t.Helper()
		_ = exit.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := exit.ReadFrom(buf)
		if err != nil {
			t.Fatalf("the exit received nothing: %v", err)
		}
		return slices.Clone(buf[:n])
	}
	check := func(what string, want, got any) {
		t.Helper()
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("%s (-want +got):\n%s", what, diff)
		}
	}

	var macs device.CookieGenerator
	macs.Init(device.NoisePublicKey(exitPub))
	fromHost(initiationWith(&macs, 0x11))
	cookie := decodeCookieReply(t, atHost())
	check("the cookie reply's type and receiver index",
		[]uint32{device.MessageCookieReplyType, 0x11}, []uint32{cookie.Type, cookie.Receiver})
	if !macs.ConsumeReply(cookie) {
		t.Fatal("the host's generator refused the cookie reply")
	}
	for _, sender := range []uint32{0x12, 0x13} {
		initiation := initiationWith(&macs, sender)
		fromHost(initiation)
		check("the initiation carrying mac2 the exit received", initiation, atExit())
	}

	// The reader takes the datagrams in order, so the datagram after the
	// drop reaching the host device first marks the drop counted, and the
	// initiation the cookie answered never reached the device.
	fromHost(initiationWith(&macs, 0x14))
	after := transportTo(0x99, "after the drop")
	fromHost(after)
	select {
	case dg := <-devices:
		check("the first datagram the host device received", after, dg.data)
	case <-time.After(5 * time.Second):
		t.Fatal("nothing reached the host device")
	}
	counts := home.Counters()
	check("the relay's counters", map[string]int64{"cookies": 1, "relayed": 2, "drops": 1, "host": 5},
		map[string]int64{
			"cookies": counts["wireguard.relay_cookies_total"],
			"relayed": counts["wireguard.relayed_datagrams_total"],
			"drops":   counts["wireguard.relay_drops_total"],
			"host":    counts["wireguard.host_datagrams_total"],
		})
}

// TestRelayedSessionCompletes checks a relayed session end to end: a host
// whose peer for the exit node names the exit's key at the home node's
// endpoint completes a WireGuard handshake with the exit through the home
// node's relay — the exit holding the host, another node's, from the
// directory alone, and answering over the path the relayed datagrams
// arrived on. The host's packet reaches the exit's own address, and the
// exit's answer, produced by its own services for a host another node owns,
// enters its host device and returns through the relay. The home node
// relays every datagram of it and opens none.
func TestRelayedSessionCompletes(t *testing.T) {
	lab := newRelayLab(t)
	homeIA := addr.MustIAFrom(20, 0xff0000000288)
	exitIA := addr.MustIAFrom(20, 0xff0000000289)
	homeDB := newFlippableTrustDB(t, homeIA)
	homeDB.enroll(t)
	exitDB := newFlippableTrustDB(t, exitIA)
	exitDB.enroll(t)
	home, _ := newTestWireguard(t, homeIA, homeDB,
		lab.attach(homeIA, upSegmentAt(t, time.Now(), exitIA, homeIA)))
	exit, _ := newTestWireguard(t, exitIA, exitDB, lab.attach(exitIA))
	lab.serve(homeIA, home.relay.conn)
	lab.serve(exitIA, exit.relay.conn)
	runApp(t, home)
	runApp(t, exit)

	hostKey, hostPub := newKeyPair(t)
	hostAddr := netip.MustParseAddr("100.64.0.10")
	exitOwn := netip.MustParseAddr("100.64.1.1")
	homeEntry := Entry{IA: homeIA, PublicKey: home.PublicKey(), Overlay: netip.MustParsePrefix("100.64.0.0/24")}
	exitEntry := Entry{IA: exitIA, PublicKey: exit.PublicKey(), Overlay: netip.MustParsePrefix("100.64.1.0/24")}
	hostEntry := HostEntry{PublicKey: hostPub, Addr: hostAddr, IA: homeIA}
	home.applyDirectory(t.Context(), Directory{
		Nodes: []Entry{homeEntry, exitEntry}, Hosts: []HostEntry{hostEntry},
	})
	exit.applyDirectory(t.Context(), Directory{
		Nodes: []Entry{exitEntry}, Hosts: []HostEntry{hostEntry},
	})
	delivered := make(chan []byte, 4)
	t.Cleanup(exit.Router().Deliver(exitOwn, func(pkt []byte) {
		delivered <- slices.Clone(pkt)
	}))

	hostPipe := newPipe("client", OverlayMTU, &counters{})
	hostDev := device.NewDevice(hostPipe, conn.NewDefaultBind(), testLogger)
	t.Cleanup(func() {
		hostDev.Close()
		_ = hostPipe.Close()
	})
	if err := hostDev.IpcSet(strings.Join([]string{
		"private_key=" + hex.EncodeToString(hostKey[:]),
		"public_key=" + exit.PublicKey().String(),
		"endpoint=" + netip.AddrPortFrom(testHost, home.HostPort()).String(),
		"allowed_ip=" + netip.PrefixFrom(exitOwn, 32).String(),
	}, "\n")); err != nil {
		t.Fatal(err)
	}
	if err := hostDev.Up(); err != nil {
		t.Fatal(err)
	}

	hostPipe.inbound <- ipPacket(t, hostAddr, exitOwn, []byte("to the exit"))
	select {
	case pkt := <-delivered:
		if got := string(pkt[header.IPv4MinimumSize:]); got != "to the exit" {
			t.Errorf("the exit's own address received %q, want %q", got, "to the exit")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the host's packet never reached the exit's own address")
	}
	exit.Router().Route(ipPacket(t, exitOwn, hostAddr, []byte("from the exit")))
	select {
	case pkt := <-hostPipe.outbound:
		if got := string(pkt[header.IPv4MinimumSize:]); got != "from the exit" {
			t.Errorf("the host received %q, want %q", got, "from the exit")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the exit's answer never reached the host")
	}

	allowed := []string{netip.PrefixFrom(hostAddr, 32).String()}
	if diff := cmp.Diff(devicePeer{Endpoint: "relay:" + homeIA.String(), Handshaken: true, AllowedIPs: allowed},
		devicePeers(t, exit.hosts.dev)[hostPub.String()]); diff != "" {
		t.Errorf("the exit's peer for the host (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(devicePeer{AllowedIPs: allowed},
		devicePeers(t, home.hosts.dev)[hostPub.String()]); diff != "" {
		t.Errorf("the home node's peer for the host (-want +got):\n%s", diff)
	}
	counts := home.Counters()
	if got := counts["wireguard.relayed_datagrams_total"]; got < 4 {
		t.Errorf("the home node relayed %d datagrams, want the handshake's two and a transport each way", got)
	}
	if got := counts["wireguard.relay_drops_total"]; got != 0 {
		t.Errorf("the home node's relay dropped %d datagrams, want none", got)
	}
}
