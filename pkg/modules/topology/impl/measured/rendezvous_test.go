package measured

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"google.golang.org/protobuf/proto"

	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/links/impl/memory"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
)

// rendezvousFixture is a rendezvous acceptor on a loopback address with a
// memory link store.
type rendezvousFixture struct {
	store *memory.DB
	addr  netip.AddrPort
	*Rendezvous
}

var (
	rendezvousIA  = addr.MustIAFrom(20, 0xfd0000000021)
	strangerKeyIA = addr.MustIAFrom(20, 0xfd0000000023)
)

func newRendezvousFixture(t *testing.T, mutate func(*RendezvousConfig)) *rendezvousFixture {
	t.Helper()
	store := memory.New()
	cfg := RendezvousConfig{
		Bind:        "127.0.0.1:0",
		MinInterval: 10 * time.Millisecond,
		Store:       store,
		MaxLinks:    8,
		LinkHost:    netip.MustParseAddr("127.0.0.1"),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	r, err := NewRendezvous(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ap := r.conn.LocalAddr().AddrPort()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = r.Close()
	})
	go r.Run(ctx)
	return &rendezvousFixture{store: store, addr: ap, Rendezvous: r}
}

// linkAddr draws a link address the establishment dials claim and bind —
// the probe-and-release shape the band allocation performs.
func linkAddr(t *testing.T) netip.AddrPort {
	t.Helper()
	local, err := AllocateLinkAddr(underlay.Kernel, netip.MustParseAddr("127.0.0.1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return local
}

// TestRendezvousRoundTrip checks the exchange: the joiner's echo returns
// with the acceptor's link address and interface ID, and both sides of the
// link are recorded — the acceptor's entry a candidate aimed at the joiner's
// observed source, the dial leaving from the socket that will serve and
// holding it for the round trip alone.
func TestRendezvousRoundTrip(t *testing.T) {
	f := newRendezvousFixture(t, nil)
	local := linkAddr(t)

	reply, _, rtt, err := RendezvousEcho(context.Background(), underlay.Kernel,
		local, f.addr, rendezvousIA, local)
	if err != nil {
		t.Fatal(err)
	}
	if rtt <= 0 {
		t.Errorf("round trip = %v, want positive", rtt)
	}
	entry, err := f.store.ByNeighbor(context.Background(), rendezvousIA)
	if err != nil || entry == nil {
		t.Fatalf("no entry recorded (%v)", err)
	}
	if entry.State != links.StateCandidate {
		t.Errorf("entry state = %v, want candidate", entry.State)
	}
	// The record is the observation whole: the bound address itself, host
	// and port both.
	if entry.Remote != local {
		t.Errorf("entry remote = %v, want the dial's bind %v", entry.Remote, local)
	}
	if reply.LinkAddr != entry.Local {
		t.Errorf("reply link address = %v, want the entry's %v", reply.LinkAddr, entry.Local)
	}
	if reply.IfID != entry.IfID {
		t.Errorf("reply interface ID = %d, want the entry's %d", reply.IfID, entry.IfID)
	}
	// A link reply names no reflexive address: a binding reply alone
	// carries one.
	if reply.Reflexive.IsValid() {
		t.Errorf("link reply's reflexive address = %v, want none", reply.Reflexive)
	}

	// The dial held the address for the round trip alone: it binds again
	// once the exchange has returned.
	held, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(local))
	if err != nil {
		t.Fatalf("the establishment dial kept hold of %v: %v", local, err)
	}
	_ = held.Close()

	// A re-request from the same address is idempotent: the recorded side
	// re-answers, no second entry, no retarget.
	reply2, _, _, err := RendezvousEcho(context.Background(), underlay.Kernel,
		local, f.addr, rendezvousIA, local)
	if err != nil {
		t.Fatal(err)
	}
	if reply2.IfID != entry.IfID {
		t.Error("a re-request allocated a second interface ID")
	}
	entries, err := f.store.All(context.Background())
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v (%v), want the one", entries, err)
	}
	if entries[0].Remote != local {
		t.Errorf("the re-request moved the entry's remote: %v", entries[0].Remote)
	}

	// A dial from another socket — the peer moved, or a pre-change joiner
	// dialed ephemeral — retargets the candidate onto the new observation.
	moved := linkAddr(t)
	if _, _, _, err := RendezvousEcho(context.Background(), underlay.Kernel,
		moved, f.addr, rendezvousIA, moved); err != nil {
		t.Fatal(err)
	}
	entry, err = f.store.ByNeighbor(context.Background(), rendezvousIA)
	if err != nil || entry == nil {
		t.Fatalf("no entry recorded (%v)", err)
	}
	if entry.Remote != moved {
		t.Errorf("entry remote = %v, want the new observation %v", entry.Remote, moved)
	}
}

// TestRendezvousNamesCandidate checks identity adoption as the exchange's
// own act: a bootstrap claim with the zero ISD-AS mints an unnamed candidate
// at the dial's observed source, whatever the claim names — behind a NAT, an
// address inside it — and the same socket's named dial, the joiner's
// identity completed, names that entry instead of minting a second one. No
// live entry is left unnamed past the exchange.
func TestRendezvousNamesCandidate(t *testing.T) {
	f := newRendezvousFixture(t, nil)
	local := linkAddr(t)
	inside := netip.MustParseAddrPort("10.0.0.5:31001")

	if _, _, _, err := RendezvousEcho(context.Background(), underlay.Kernel,
		local, f.addr, addr.IA(0), inside); err != nil {
		t.Fatal(err)
	}
	entry, err := f.store.ByRemote(context.Background(), local)
	if err != nil || entry == nil {
		t.Fatalf("no unnamed candidate recorded at the dial's source (%v)", err)
	}
	if !entry.NeighborIA.IsZero() {
		t.Fatalf("bootstrap claim recorded %v, want unnamed", entry.NeighborIA)
	}

	reply, _, _, err := RendezvousEcho(context.Background(), underlay.Kernel,
		local, f.addr, rendezvousIA, inside)
	if err != nil {
		t.Fatal(err)
	}
	named, err := f.store.ByNeighbor(context.Background(), rendezvousIA)
	if err != nil || named == nil {
		t.Fatalf("the named dial named no entry (%v)", err)
	}
	if named.IfID != entry.IfID {
		t.Error("the named dial minted a second entry instead of naming the claim's")
	}
	if reply.LinkAddr != named.Local || reply.IfID != named.IfID {
		t.Error("the named dial's reply re-answered another entry's side")
	}
	entries, err := f.store.All(context.Background())
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v (%v), want the one named", entries, err)
	}
}

// TestRendezvousLosesRecordRace checks a claim that loses the race to
// record its peer: the in-band link service records the peer between the
// acceptor's lookup and its insert, the store refuses the second live
// entry, and the claim answers with the recorded entry's side. The test
// calls the handler: a dial would resend a refused request and mask the
// handler's own retry.
func TestRendezvousLosesRecordRace(t *testing.T) {
	var store *staleStore
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		store = &staleStore{DB: cfg.Store.(*memory.DB)}
		cfg.Store = store
	})
	recorded := liveLink(rendezvousIA, 40001)
	if err := store.Insert(context.Background(), recorded); err != nil {
		t.Fatal(err)
	}
	store.armed.Store(true)
	req := RendezvousRequest{IA: rendezvousIA, LinkAddr: recorded.Remote}
	raw, err := f.handle(context.Background(), marshaled(t, req), net.UDPAddrFromAddrPort(recorded.Remote))
	if err != nil {
		t.Fatal(err)
	}
	reply, err := ParseRendezvousReply(raw)
	if err != nil {
		t.Fatal(err)
	}
	if reply.LinkAddr != recorded.Local || reply.IfID != recorded.IfID {
		t.Errorf("reply = %v/%d, want the recorded entry's %v/%d",
			reply.LinkAddr, reply.IfID, recorded.Local, recorded.IfID)
	}
	want := []links.State{links.StateEstablished}
	if got := statesOf(t, f.store, rendezvousIA); !slices.Equal(got, want) {
		t.Errorf("the peer's entries = %v, want the recorded one alone", got)
	}
}

// TestRendezvousLosesPortRace checks a claim that loses the race for the
// port it drew: another writer records an entry on that address between
// the acceptor's draw and its insert, the store refuses a second live entry
// on it, and the claim mints its candidate on a fresh address, the one the
// reply carries. The test calls the handler: a dial would resend a refused
// request and mask the handler's own retry.
func TestRendezvousLosesPortRace(t *testing.T) {
	var store *squattedStore
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		store = &squattedStore{DB: cfg.Store.(*memory.DB)}
		cfg.Store = store
	})
	store.armed.Store(true)
	claim := netip.MustParseAddrPort("127.0.0.1:4242")
	req := RendezvousRequest{IA: rendezvousIA, LinkAddr: claim}
	raw, err := f.handle(context.Background(), marshaled(t, req), net.UDPAddrFromAddrPort(claim))
	if err != nil {
		t.Fatal(err)
	}
	reply, err := ParseRendezvousReply(raw)
	if err != nil {
		t.Fatal(err)
	}
	lostPortRace(t, store, rendezvousIA, reply.LinkAddr)
}

// TestRendezvousRefusesTakenRemote checks a claim at another neighbor's
// link address: the store refuses a second serving entry with one remote,
// so a claim minting a candidate there, or retargeting an unproven entry
// onto it, is turned away and leaves the table as it was — a request no one
// authenticates cannot hand the data plane a link set it refuses.
func TestRendezvousRefusesTakenRemote(t *testing.T) {
	f := newRendezvousFixture(t, nil)
	taken := liveLink(rendezvousIA, 40001)
	unproven := liveLink(strangerKeyIA, 40003)
	unproven.State = links.StateCandidate
	for _, l := range []*links.Link{taken, unproven} {
		if err := f.store.Insert(context.Background(), l); err != nil {
			t.Fatal(err)
		}
	}
	fresh := addr.MustIAFrom(20, 0xfd0000000025)
	for _, ia := range []addr.IA{fresh, strangerKeyIA} {
		req := RendezvousRequest{IA: ia, LinkAddr: taken.Remote}
		_, err := f.handle(context.Background(), marshaled(t, req), net.UDPAddrFromAddrPort(taken.Remote))
		if !errors.Is(err, links.ErrDuplicateRemote) {
			t.Errorf("a claim of %s at a taken address returned %v, want ErrDuplicateRemote",
				ia, err)
		}
	}
	if got := statesOf(t, f.store, fresh); len(got) != 0 {
		t.Errorf("the refused claim left entries %v", got)
	}
	got, err := f.store.ByNeighbor(context.Background(), strangerKeyIA)
	if err != nil || got == nil || got.Remote != unproven.Remote {
		t.Errorf("the unproven entry after the refused retarget = %+v (%v), want its remote %v",
			got, err, unproven.Remote)
	}
}

// TestParseRendezvousAddr checks the neighbor argument's grammar: an address
// keeps the port it spells, a bare host names the fixed rendezvous port.
func TestParseRendezvousAddr(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.0.2.7:4242", "192.0.2.7:4242"},
		{"192.0.2.7", "192.0.2.7:30043"},
		{"fd00::1", "[fd00::1]:30043"},
		{"[fd00::1]:4242", "[fd00::1]:4242"},
	}
	for _, tc := range cases {
		got, err := ParseRendezvousAddr(tc.in)
		if err != nil {
			t.Errorf("ParseRendezvousAddr(%q): %v", tc.in, err)
			continue
		}
		if want := netip.MustParseAddrPort(tc.want); got != want {
			t.Errorf("ParseRendezvousAddr(%q) = %v, want %v", tc.in, got, want)
		}
	}
	if ap, err := ParseRendezvousAddr("nope"); err == nil {
		t.Errorf("ParseRendezvousAddr(%q) = %v, want an error", "nope", ap)
	}
}

// TestRendezvousNoReplyAllocatesNothing checks the negative: a request
// whose nonce echo never returns allocates nothing on the joiner's side —
// and a dial to a silent port allocates nothing anywhere. A dial to a silent
// port but the endpoint's names the confusion its error carries, and a dial
// to any other silent port carries none.
func TestRendezvousNoReplyAllocatesNothing(t *testing.T) {
	dial := func(t *testing.T, target netip.AddrPort) error {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _, _, err := RendezvousEcho(ctx, underlay.Kernel, netip.MustParseAddrPort("127.0.0.1:0"),
			target, rendezvousIA, netip.MustParseAddrPort("127.0.0.1:4242"))
		return err
	}
	dead := netip.MustParseAddrPort("127.0.0.1:1")
	if err := dial(t, dead); err == nil {
		t.Fatal("a dial to a silent port succeeded")
	} else if strings.Contains(err.Error(), "acceptor") {
		t.Errorf("a dial to a port but the endpoint's names the acceptor: %v", err)
	}
	endpoint := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), scionrpc.EndpointPort)
	if err := dial(t, endpoint); err == nil {
		t.Fatal("a dial to a silent endpoint port succeeded")
	} else if !strings.Contains(err.Error(), "acceptor binds") {
		t.Errorf("a dial to the endpoint's port carries no silence hint: %v", err)
	}
}

// TestRendezvousRateCap checks the acceptor's rate cap: a flood of requests
// from one source is answered once per interval — the source, not the claim,
// is what the cap counts.
func TestRendezvousRateCap(t *testing.T) {
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.MinInterval = time.Second
	})
	claim := netip.MustParseAddrPort("127.0.0.1:4242")

	conn, err := net.ListenUDP("udp",
		net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	replies := 0
	buf := make([]byte, 128)
	for i := range 5 {
		req := RendezvousRequest{IA: rendezvousIA, LinkAddr: claim}
		req.Nonce[0] = byte(i)
		if _, err := conn.WriteToUDP(marshaled(t, req), udpAddr(f.addr)); err != nil {
			t.Fatal(err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				break // the wait elapsed
			}
			if reply, err := ParseRendezvousReply(buf[:n]); err == nil && reply.Nonce[0] == byte(i) {
				replies++
				break
			}
		}
	}
	if replies > 1 {
		t.Errorf("a request flood was answered %d times inside the rate cap", replies)
	}
	// What the flood did allocate is bounded to the one peer it claimed.
	entries, err := f.store.All(context.Background())
	if err != nil || len(entries) > 1 {
		t.Fatalf("the flood minted %d entries (%v)", len(entries), err)
	}
}

// TestRendezvousLinkCap checks the link-count cap: with the store at it, a
// new peer is refused while a peer already in the table re-answers.
func TestRendezvousLinkCap(t *testing.T) {
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.MaxLinks = 1
	})
	claim := netip.MustParseAddrPort("127.0.0.1:4242")
	if err := f.store.Insert(context.Background(), &links.Link{
		NeighborIA: strangerKeyIA,
		Local:      netip.MustParseAddrPort("127.0.0.1:40001"),
		Remote:     netip.MustParseAddrPort("127.0.0.1:40002"),
		State:      links.StateEstablished,
	}); err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := RendezvousEcho(context.Background(), underlay.Kernel,
		netip.MustParseAddrPort("127.0.0.1:0"), f.addr, rendezvousIA, claim); err == nil {
		t.Error("a request past the link cap was admitted")
	}
	// A returning neighbor is never blocked by the cap.
	if _, _, _, err := RendezvousEcho(context.Background(), underlay.Kernel,
		netip.MustParseAddrPort("127.0.0.1:0"), f.addr, strangerKeyIA, claim); err != nil {
		t.Errorf("a returning neighbor was refused at the cap: %v", err)
	}
}

// marshaled returns the message's datagram, failing the test when it does
// not marshal.
func marshaled(t *testing.T, m interface{ Marshal() ([]byte, error) }) []byte {
	t.Helper()
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// marshaledProto returns the protobuf message's wire form, failing the test
// when it does not marshal.
func marshaledProto(t *testing.T, m proto.Message) []byte {
	t.Helper()
	raw, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestRendezvousWireFormat checks the request and reply datagrams: each
// round-trips, a reply without a reflexive address included, and a field a
// later release adds is skipped; a datagram of another format, a truncated
// one, a nonce of another length, and an address that does not parse are
// refused.
func TestRendezvousWireFormat(t *testing.T) {
	req := RendezvousRequest{
		IA:       rendezvousIA,
		LinkAddr: netip.MustParseAddrPort("192.0.2.7:4242"),
	}
	for i := range req.Nonce {
		req.Nonce[i] = byte(i)
	}
	raw := marshaled(t, req)
	if got, err := ParseRendezvousRequest(raw); err != nil || got != req {
		t.Fatalf("request round trip = %+v (%v), want %+v", got, err, req)
	}

	reply := RendezvousReply{
		LinkAddr: netip.MustParseAddrPort("192.0.2.8:4243"),
		IfID:     7,
		IA:       rendezvousIA,
	}
	copy(reply.Nonce[:], req.Nonce[:])
	if got, err := ParseRendezvousReply(marshaled(t, reply)); err != nil || got != reply {
		t.Fatalf("reply round trip = %+v (%v), want %+v", got, err, reply)
	}
	echoed := reply
	echoed.Reflexive = netip.MustParseAddrPort("198.51.100.6:54321")
	if got, err := ParseRendezvousReply(marshaled(t, echoed)); err != nil || got != echoed {
		t.Errorf("echoing reply round trip = %+v (%v), want %+v", got, err, echoed)
	}
	// Field 15 as a varint: a field a later release adds, skipped.
	if got, err := ParseRendezvousReply(append(marshaled(t, echoed), 0x78, 0x01)); err != nil ||
		got != echoed {
		t.Errorf("a reply with an unknown field = %+v (%v), want %+v", got, err, echoed)
	}

	refused := map[string][]byte{
		// The earlier hand-written form: a two-byte version, then the nonce.
		"another format":      append([]byte{0, 1}, req.Nonce[:]...),
		"a truncated request": raw[:len(raw)-3],
		"an empty datagram":   nil,
		"a short nonce": marshaledProto(t, &nodev1.RendezvousRequest{
			Nonce: req.Nonce[:8], IsdAs: uint64(req.IA), LinkAddr: "192.0.2.7:4242",
		}),
		"an unparsable address": marshaledProto(t, &nodev1.RendezvousRequest{
			Nonce: req.Nonce[:], IsdAs: uint64(req.IA), LinkAddr: "nowhere",
		}),
	}
	for name, b := range refused {
		if _, err := ParseRendezvousRequest(b); err == nil {
			t.Errorf("%s parsed", name)
		}
	}
}

// TestRendezvousBindingWireFormat checks the binding request and its
// reply: the request round-trips claiming no link address, padded past the
// longest binding reply, which round-trips naming no link address; a
// binding request that claims a link address is refused.
func TestRendezvousBindingWireFormat(t *testing.T) {
	req := RendezvousRequest{Nonce: [16]byte{1, 2, 3}, Binding: true}
	raw := marshaled(t, req)
	if got, err := ParseRendezvousRequest(raw); err != nil || got != req {
		t.Errorf("binding request round trip = %+v (%v), want %+v", got, err, req)
	}
	longest := RendezvousReply{
		Nonce:     req.Nonce,
		IA:        addr.MustIAFrom(65535, 0xffffffffffff),
		Reflexive: netip.MustParseAddrPort("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"),
	}
	reply := marshaled(t, longest)
	if len(raw) < len(reply) {
		t.Errorf("a binding request of %d bytes buys a reply of %d", len(raw), len(reply))
	}
	if got, err := ParseRendezvousReply(reply); err != nil || got != longest {
		t.Errorf("binding reply round trip = %+v (%v), want %+v", got, err, longest)
	}
	claiming := marshaledProto(t, &nodev1.RendezvousRequest{
		Nonce: req.Nonce[:], Binding: true, LinkAddr: "192.0.2.7:4242",
	})
	if _, err := ParseRendezvousRequest(claiming); err == nil {
		t.Error("a binding request claiming a link address parsed")
	}
}

// TestRendezvousBindingRecordsNothing checks the acceptor's answer to a
// binding request: each socket of one host learns its own reflexive
// address and the acceptor records nothing; a second request from one
// source within the interval is refused, and so are a request naming an
// ISD-AS and one shorter than its reply.
func TestRendezvousBindingRecordsNothing(t *testing.T) {
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = rendezvousIA
		cfg.MinInterval = time.Hour
	})
	for range 2 {
		conn, err := underlay.Kernel.NewUDP(
			net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")), netip.AddrPort{})
		if err != nil {
			t.Fatal(err)
		}
		bound := conn.LocalAddr().AddrPort()
		got, err := reflexiveAddr(context.Background(), conn, f.addr)
		_ = conn.Close()
		if err != nil {
			t.Fatalf("a fresh socket's reflexive address: %v", err)
		}
		if want := netip.AddrPortFrom(bound.Addr().Unmap(), bound.Port()); got != want {
			t.Errorf("the reflexive address = %v, want the socket's own %v", got, want)
		}
	}
	if entries, err := f.store.All(context.Background()); err != nil || len(entries) != 0 {
		t.Errorf("the binding requests recorded %v (%v), want nothing", entries, err)
	}

	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}
	raw := marshaled(t, RendezvousRequest{Binding: true})
	if _, err := f.handle(context.Background(), raw, src); err != nil {
		t.Fatalf("a binding request was refused: %v", err)
	}
	if _, err := f.handle(context.Background(), raw, src); err == nil {
		t.Error("a second binding request from one source within the interval was answered")
	}
	other := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4243}
	named := marshaled(t, RendezvousRequest{IA: rendezvousIA, Binding: true})
	if _, err := f.handle(context.Background(), named, other); err == nil {
		t.Error("a binding request naming an ISD-AS was answered")
	}
	unpadded := marshaledProto(t, &nodev1.RendezvousRequest{Nonce: make([]byte, 16), Binding: true})
	if _, err := f.handle(context.Background(), unpadded, other); err == nil {
		t.Error("a binding request shorter than its reply was answered")
	}
}

// TestRendezvousEchoNeedsTheLinkAddress checks the dialer's reading of an
// answer: a reply that names no link address — a binding reply to a
// claim — is refused, for the dial records the acceptor's side.
func TestRendezvousEchoNeedsTheLinkAddress(t *testing.T) {
	acceptor := udpSocket(t)
	go func() {
		buf := make([]byte, 192)
		n, src, err := acceptor.ReadFromUDP(buf)
		if err != nil {
			return
		}
		req, err := ParseRendezvousRequest(buf[:n])
		if err != nil {
			return
		}
		reply := RendezvousReply{Nonce: req.Nonce, IA: rendezvousIA, Reflexive: observedAddr(src)}
		raw, err := reply.Marshal()
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = acceptor.WriteToUDP(raw, src)
	}()
	_, _, _, err := RendezvousEcho(context.Background(), underlay.Kernel,
		netip.MustParseAddrPort("127.0.0.1:0"), boundAddr(acceptor), rendezvousIA,
		netip.MustParseAddrPort("127.0.0.1:4242"))
	if err == nil {
		t.Error("a reply naming no link address was taken")
	}
}

// TestRendezvousEchoEndsWithItsContext checks the rendezvous echo's wait: a
// dial no acceptor answers, its context ending once the first request is
// out, returns the context's error well inside the attempt's
// RendezvousAttemptWait — the end cuts the wait short, and no next attempt
// starts.
func TestRendezvousEchoEndsWithItsContext(t *testing.T) {
	host := netip.MustParseAddr("127.0.0.1")
	silent, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	echoed := make(chan error, 1)
	start := time.Now()
	go func() {
		_, _, _, err := RendezvousEcho(ctx, underlay.Kernel, netip.AddrPortFrom(host, 0),
			silent.LocalAddr().(*net.UDPAddr).AddrPort(),
			addr.IA(0), netip.AddrPortFrom(host, 4242))
		echoed <- err
	}()
	if _, _, err := silent.ReadFromUDP(make([]byte, 192)); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-echoed; !errors.Is(err, context.Canceled) {
		t.Errorf("RendezvousEcho = %v, want the context's end", err)
	}
	// The attempt's deadline is set after start: a wait the end does not
	// cut short holds the dial a full RendezvousAttemptWait.
	if held := time.Since(start); held >= RendezvousAttemptWait {
		t.Errorf("RendezvousEcho returned after %v, want under RendezvousAttemptWait", held)
	}
}

// lateConn is a socket whose acceptor answers the request of each attempt
// after that attempt's delay, in a bubble's fake time, the reply echoing the
// request's nonce.
type lateConn struct {
	underlay.UDPConn
	delays   []time.Duration
	replies  chan []byte
	deadline time.Time
}

func (c *lateConn) WriteToUDP(b []byte, _ *net.UDPAddr) (int, error) {
	req, err := ParseRendezvousRequest(b)
	if err != nil {
		return 0, err
	}
	reply, err := RendezvousReply{Nonce: req.Nonce, IA: rendezvousIA}.Marshal()
	if err != nil {
		return 0, err
	}
	delay := c.delays[0]
	c.delays = c.delays[1:]
	time.AfterFunc(delay, func() { c.replies <- reply })
	return len(b), nil
}

func (c *lateConn) SetReadDeadline(t time.Time) error {
	c.deadline = t
	return nil
}

func (c *lateConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	select {
	case reply := <-c.replies:
		return copy(b, reply), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:30043")), nil
	case <-time.After(time.Until(c.deadline)):
		return 0, nil, os.ErrDeadlineExceeded
	}
}

// TestEchoOnTimesALateReplyFromItsRequest checks a reply that misses its
// attempt's wait: arriving during the next attempt, it answers the run, its
// round trip timed from its own request — neither from the next request,
// which would read it short, nor dropped for the next reply.
func TestEchoOnTimesALateReplyFromItsRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		late := RendezvousAttemptWait + 100*time.Millisecond
		conn := &lateConn{
			delays:  []time.Duration{late, 300 * time.Millisecond, 300 * time.Millisecond},
			replies: make(chan []byte, RendezvousAttempts),
		}
		_, _, rtt, err := echoOn(t.Context(), conn, netip.MustParseAddrPort("192.0.2.1:30043"),
			RendezvousRequest{Binding: true})
		if err != nil || rtt != late {
			t.Errorf("echoOn = %v (%v), want the late reply's %v", rtt, err, late)
		}
	})
}

// TestRendezvousEchoSpeaksForTheLink checks an answered dial: before the
// socket is released, one empty datagram leaves it for the acceptor's link
// address — the answer's port on the host the reply arrived from, the claim
// rule's record — so a NAT maps the link's own flow first.
func TestRendezvousEchoSpeaksForTheLink(t *testing.T) {
	host := netip.MustParseAddr("127.0.0.1")
	listen := func() *net.UDPConn {
		t.Helper()
		c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, 0)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	// A stand-in acceptor answering every request with the wildcard at the
	// link socket's port, the answer a wildcard-bound acceptor gives.
	acceptor, link := listen(), listen()
	linkPort := link.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	go func() {
		buf := make([]byte, 192)
		for {
			n, src, err := acceptor.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req, err := ParseRendezvousRequest(buf[:n])
			if err != nil {
				continue
			}
			reply := RendezvousReply{
				Nonce:     req.Nonce,
				LinkAddr:  netip.AddrPortFrom(netip.IPv4Unspecified(), linkPort),
				IA:        rendezvousIA,
				Reflexive: observedAddr(src),
			}
			raw, err := reply.Marshal()
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = acceptor.WriteToUDP(raw, src)
		}
	}()
	target := acceptor.LocalAddr().(*net.UDPAddr).AddrPort()
	// The datagrams the reads wait on left before each dial returned: the
	// deadline only bounds a regression's hang.
	if err := link.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)

	local := linkAddr(t)
	if _, _, _, err := RendezvousEcho(context.Background(), underlay.Kernel,
		local, target, rendezvousIA, local); err != nil {
		t.Fatal(err)
	}
	n, src, err := link.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the link socket heard nothing from the dial: %v", err)
	}
	if got := observedAddr(src); n != 0 || got != local {
		t.Errorf("the link socket read %d bytes from %v, want an empty datagram from the dial's bind %v",
			n, got, local)
	}
}

// TestRendezvousRecordsTheObservation checks the acceptor's record: a claim
// — a joiner's dial from the socket that will serve, unnamed before its
// identity completes — records the request's observed source whole, host
// and port both, whatever the claim spells, for the observation names the
// dialing socket's mapping. The wildcard bind rides the same rule: a
// wildcard-bound dialer claims the wildcard, and what it cannot name the
// exchange observes.
func TestRendezvousRecordsTheObservation(t *testing.T) {
	wildcard := netip.MustParseAddr("0.0.0.0")
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.Bind = "0.0.0.0:0"
		cfg.LinkHost = wildcard
	})
	// The dial aims at the acceptor's port on the v4 loopback, the form a
	// published host spells.
	loopback := netip.MustParseAddr("127.0.0.1")
	target := netip.AddrPortFrom(loopback, f.addr.Port())

	// A named dial whose claim spells the wildcard at a port drawn from the
	// link band: the dial binds the wildcard at the claimed port, and the
	// record is the observation — the loopback host the request arrived from
	// under the bound port.
	claim, err := AllocateLinkAddr(underlay.Kernel, wildcard, nil)
	if err != nil {
		t.Fatal(err)
	}
	reply, observed, _, err := RendezvousEcho(context.Background(), underlay.Kernel,
		claim, target, rendezvousIA, claim)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := f.store.ByNeighbor(context.Background(), rendezvousIA)
	if err != nil || entry == nil {
		t.Fatalf("no entry recorded (%v)", err)
	}
	if want := netip.AddrPortFrom(loopback, claim.Port()); entry.Remote != want {
		t.Errorf("entry remote = %v, want the observed host under the bound port %v",
			entry.Remote, want)
	}
	if !entry.Local.Addr().IsUnspecified() {
		t.Errorf("entry local = %v, want the wildcard bind value", entry.Local)
	}
	// The dialer's side keeps the claim rule: the answer's port on the host
	// the reply arrived from — the acceptor's routable host on the path the
	// dial proved.
	if observed.Addr() != loopback {
		t.Errorf("the reply's source = %v, want the loopback host", observed)
	}
	remote := recordedLinkAddr(reply.LinkAddr, observed)
	if want := netip.AddrPortFrom(loopback, reply.LinkAddr.Port()); remote != want {
		t.Errorf("recorded remote = %v, want the reply's source under the answer's port %v",
			remote, want)
	}
	if reply.LinkAddr != entry.Local {
		t.Errorf("reply link address = %v, want the entry's %v", reply.LinkAddr, entry.Local)
	}

	// A named dial whose claim lies — a pre-change joiner claiming an
	// address its ephemeral socket does not bind — records the observation
	// anyway: the mapping of whatever socket dialed.
	ephemeral := netip.AddrPortFrom(loopback, 0)
	lying := netip.MustParseAddrPort("192.0.2.9:4242")
	if _, _, _, err := RendezvousEcho(context.Background(), underlay.Kernel,
		ephemeral, target, rendezvousIA, lying); err != nil {
		t.Fatal(err)
	}
	entry, err = f.store.ByNeighbor(context.Background(), rendezvousIA)
	if err != nil || entry == nil {
		t.Fatalf("no entry recorded (%v)", err)
	}
	if !entry.Remote.IsValid() || entry.Remote == lying ||
		entry.Remote.Addr() != loopback || entry.Remote.Port() == 0 {
		t.Errorf("the lying claim's record = %v, want the ephemeral dial's observation",
			entry.Remote)
	}

	// An unnamed claim records the observation too: a joiner's first dial,
	// claiming an address its socket's mapping is not — behind a NAT, the
	// address inside it — records the socket it came from.
	first := linkAddr(t)
	if _, _, _, err := RendezvousEcho(context.Background(), underlay.Kernel,
		first, target, addr.IA(0), lying); err != nil {
		t.Fatal(err)
	}
	unnamed, err := f.store.ByRemote(context.Background(), first)
	if err != nil || unnamed == nil || !unnamed.NeighborIA.IsZero() {
		t.Errorf("the unnamed claim's record at %v = %+v (%v), want an unnamed entry",
			first, unnamed, err)
	}
}

// TestRendezvousRunReleasesOnCancel checks the acceptor's stop: once its
// context ends, Run returns with its socket closed and released, and the
// address binds again at once. The acceptor binds on the loopback host the
// provider's release check uses, where only a wildcard bind can take the
// released port.
func TestRendezvousRunReleasesOnCancel(t *testing.T) {
	r, err := NewRendezvous(RendezvousConfig{
		Bind:     "127.0.0.122:0",
		Store:    memory.New(),
		MaxLinks: 8,
		LinkHost: netip.MustParseAddr("127.0.0.122"),
	})
	if err != nil {
		t.Fatal(err)
	}
	bound := r.conn.LocalAddr().AddrPort()
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(returned)
	}()
	cancel()
	<-returned
	rebound, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(bound))
	if err != nil {
		t.Fatalf("the acceptor's address did not bind again: %v", err)
	}
	_ = rebound.Close()
}
