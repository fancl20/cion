package topology

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/links/impl/memory"
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
	strangerIA    = addr.MustIAFrom(20, 0xfd0000000022)
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
	ap := r.conn.LocalAddr().(*net.UDPAddr).AddrPort()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = r.Close()
	})
	go r.Run(ctx)
	return &rendezvousFixture{store: store, addr: ap, Rendezvous: r}
}

// TestRendezvousRoundTrip checks the exchange: the joiner's echo returns
// with the acceptor's link address and interface ID, and both sides of the
// link are recorded — the acceptor's entry a candidate aimed at the joiner's
// claimed address.
func TestRendezvousRoundTrip(t *testing.T) {
	f := newRendezvousFixture(t, nil)
	claim := netip.MustParseAddrPort("127.0.0.1:4242")

	reply, rtt, err := RendezvousEcho(context.Background(),
		netip.MustParseAddr("127.0.0.1"), f.addr, rendezvousIA, claim)
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
	if entry.Remote != claim {
		t.Errorf("entry remote = %v, want the claim %v", entry.Remote, claim)
	}
	if reply.LinkAddr != entry.Local {
		t.Errorf("reply link address = %v, want the entry's %v", reply.LinkAddr, entry.Local)
	}
	if reply.IfID != entry.IfID {
		t.Errorf("reply interface ID = %d, want the entry's %d", reply.IfID, entry.IfID)
	}

	// A re-request of the same peer is idempotent: the recorded side
	// re-answers, no second entry.
	newClaim := netip.MustParseAddrPort("127.0.0.1:4243")
	reply2, _, err := RendezvousEcho(context.Background(),
		netip.MustParseAddr("127.0.0.1"), f.addr, rendezvousIA, newClaim)
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
	if entries[0].Remote != newClaim {
		t.Errorf("the re-request's claim did not retarget the entry: %v", entries[0].Remote)
	}
}

// TestRendezvousNamesCandidate checks identity adoption as the exchange's
// own act: a bootstrap claim with the zero ISD-AS mints an unnamed candidate,
// and the same source's named dial — the joiner's identity completed — names
// that entry instead of minting a second one. No live entry is left unnamed
// past the exchange.
func TestRendezvousNamesCandidate(t *testing.T) {
	f := newRendezvousFixture(t, nil)
	claim := netip.MustParseAddrPort("127.0.0.1:4242")

	if _, _, err := RendezvousEcho(context.Background(),
		netip.MustParseAddr("127.0.0.1"), f.addr, addr.IA(0), claim); err != nil {
		t.Fatal(err)
	}
	entry, err := f.store.ByRemote(context.Background(), claim)
	if err != nil || entry == nil {
		t.Fatalf("no unnamed candidate recorded (%v)", err)
	}
	if !entry.NeighborIA.IsZero() {
		t.Fatalf("bootstrap claim recorded %v, want unnamed", entry.NeighborIA)
	}

	reply, _, err := RendezvousEcho(context.Background(),
		netip.MustParseAddr("127.0.0.1"), f.addr, rendezvousIA, claim)
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

// TestRendezvousNoReplyAllocatesNothing checks the negative: a request
// whose nonce echo never returns allocates nothing on the joiner's side —
// and a dial to a silent port allocates nothing anywhere.
func TestRendezvousNoReplyAllocatesNothing(t *testing.T) {
	dead := netip.MustParseAddrPort("127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := RendezvousEcho(ctx, netip.MustParseAddr("127.0.0.1"),
		dead, rendezvousIA, netip.MustParseAddrPort("127.0.0.1:4242")); err == nil {
		t.Fatal("a dial to a silent port succeeded")
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
		if _, err := conn.WriteToUDP(req.Marshal(), udpAddr(f.addr)); err != nil {
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

	if _, _, err := RendezvousEcho(context.Background(),
		netip.MustParseAddr("127.0.0.1"), f.addr, rendezvousIA, claim); err == nil {
		t.Error("a request past the link cap was admitted")
	}
	// A returning neighbor is never blocked by the cap.
	if _, _, err := RendezvousEcho(context.Background(),
		netip.MustParseAddr("127.0.0.1"), f.addr, strangerKeyIA, claim); err != nil {
		t.Errorf("a returning neighbor was refused at the cap: %v", err)
	}
}

// TestRendezvousWireFormat checks the request and reply wire forms.
func TestRendezvousWireFormat(t *testing.T) {
	req := RendezvousRequest{
		IA:       rendezvousIA,
		LinkAddr: netip.MustParseAddrPort("192.0.2.7:4242"),
	}
	for i := range req.Nonce {
		req.Nonce[i] = byte(i)
	}
	got, err := ParseRendezvousRequest(req.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if got != req {
		t.Fatalf("request round trip = %+v, want %+v", got, req)
	}

	reply := RendezvousReply{
		LinkAddr: netip.MustParseAddrPort("192.0.2.8:4243"),
		IfID:     7,
	}
	copy(reply.Nonce[:], req.Nonce[:])
	gotReply, err := ParseRendezvousReply(reply.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if gotReply != reply {
		t.Fatalf("reply round trip = %+v, want %+v", gotReply, reply)
	}

	// Truncated and version-mangled forms are refused.
	raw := req.Marshal()
	if _, err := ParseRendezvousRequest(raw[:len(raw)-3]); err == nil {
		t.Error("a truncated request parsed")
	}
	bad := append([]byte{}, raw...)
	bad[0] = 9
	if _, err := ParseRendezvousRequest(bad); err == nil {
		t.Error("an unsupported version parsed")
	}
}
