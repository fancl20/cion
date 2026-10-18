package measured

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/links/impl/memory"
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
	// The reply echoes the request's observed source: the dialer's own
	// address as the acceptor saw it, the host what it learns from.
	if reply.Observed.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("observed source = %v, want the dialer's bind host", reply.Observed)
	}
	if reply.Observed.Port() == 0 {
		t.Error("the observed source carries no port")
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
	raw, err := f.handle(context.Background(), req.Marshal(), net.UDPAddrFromAddrPort(recorded.Remote))
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
	raw, err := f.handle(context.Background(), req.Marshal(), net.UDPAddrFromAddrPort(claim))
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
		_, err := f.handle(context.Background(), req.Marshal(), net.UDPAddrFromAddrPort(taken.Remote))
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
		_, _, err := RendezvousEcho(ctx, netip.MustParseAddr("127.0.0.1"),
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
	if gotReply.Observed.IsValid() {
		t.Error("a reply that echoes no source parsed one")
	}

	echoed := reply
	echoed.Observed = netip.MustParseAddrPort("198.51.100.6:54321")
	gotEchoed, err := ParseRendezvousReply(echoed.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if gotEchoed.Observed != echoed.Observed {
		t.Errorf("observed source round trip = %v, want %v",
			gotEchoed.Observed, echoed.Observed)
	}
	// A reader tolerates what follows the field it knows: bytes appended
	// after the observed source are a later version's, read past.
	if _, err := ParseRendezvousReply(append(echoed.Marshal(), 0, 0)); err != nil {
		t.Errorf("a reply with trailing bytes parsed no: %v", err)
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
		_, _, err := RendezvousEcho(ctx, host, silent.LocalAddr().(*net.UDPAddr).AddrPort(),
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
	bound := r.conn.LocalAddr().(*net.UDPAddr).AddrPort()
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
