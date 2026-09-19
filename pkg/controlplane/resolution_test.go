package controlplane

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/control_plane"
	"google.golang.org/protobuf/proto"

	"github.com/fancl20/cion/pkg/scion"
)

// TestServiceResolution checks the drafts' exchange end to end (control
// plane draft, Section 5): a request on the one-hop path, addressed to the
// peer's CS service, is answered with the registered service's underlay
// address — the endpoint socket the CS service maps to.
func TestServiceResolution(t *testing.T) {
	iaA := addr.MustIAFrom(20, 0xff0000000041)
	iaB := addr.MustIAFrom(20, 0xff0000000042)
	wpki := newTestWebPKI(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	a := startTestNode(t, iaA, iaB, extA, extB)
	b := startTestNode(t, iaB, iaA, extB, extA)
	serveCore(t, b, wpki)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolved, err := ResolveService(ctx, a.newConn(t, 0),
		&scion.Addr{IA: iaB, Service: addr.SvcCS})
	if err != nil {
		t.Fatalf("resolving the peer's control service: %v", err)
	}
	want := netip.AddrPortFrom(b.controlIP, EndpointPort)
	if resolved != want {
		t.Errorf("resolved address = %v, want the registered endpoint %v", resolved, want)
	}
}

// TestServiceResolutionUnregistered checks the negative: a service no
// backend answers is refused cleanly — the bounded attempts return their
// error, nothing hangs, and no state anywhere records the ask.
func TestServiceResolutionUnregistered(t *testing.T) {
	iaA := addr.MustIAFrom(20, 0xff0000000051)
	iaB := addr.MustIAFrom(20, 0xff0000000052)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	a := startTestNode(t, iaA, iaB, extA, extB)
	b := startTestNode(t, iaB, iaA, extB, extA)

	ctx, cancel := context.WithTimeout(context.Background(),
		ResolutionAttempts*ResolutionAttemptWait+time.Second)
	defer cancel()
	unregistered := &scion.Addr{IA: iaB, Service: addr.SVC(0x7ff2)}
	if _, err := ResolveService(ctx, a.newConn(t, 0), unregistered); err == nil {
		t.Fatal("a service with no backend resolved")
	}
	entries, err := b.store.All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].NeighborIA.Equal(iaA) {
		t.Errorf("the refused resolution changed the peer's store: %v", entries)
	}
}

// TestParseResolutionResponse checks the client's read of a reply: the QUIC
// transport's address served, unknown transports ignored per the drafts, and
// a missing or malformed port an error rather than an address.
func TestParseResolutionResponse(t *testing.T) {
	quic := &control_plane.Transport{Address: "192.0.2.10:30044"}
	raw, err := proto.Marshal(&control_plane.ServiceResolutionResponse{
		Transports: map[string]*control_plane.Transport{
			TransportQUIC: quic,
			"DTLS":        {Address: "[2001:db8::1]:1"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parseResolutionResponse(raw)
	if !ok {
		t.Fatal("a response with the QUIC transport did not parse")
	}
	if want := netip.MustParseAddrPort("192.0.2.10:30044"); got != want {
		t.Errorf("parsed address = %v, want %v", got, want)
	}

	unknown, err := proto.Marshal(&control_plane.ServiceResolutionResponse{
		Transports: map[string]*control_plane.Transport{"DTLS": quic},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parseResolutionResponse(unknown); ok {
		t.Error("a response without the QUIC transport parsed")
	}
	for name, transport := range map[string]*control_plane.Transport{
		"zero port":    {Address: "192.0.2.10:0"},
		"no port":      {Address: "192.0.2.10"},
		"malformed":    {Address: "not-an-address"},
		"no transport": {},
	} {
		raw, err := proto.Marshal(&control_plane.ServiceResolutionResponse{
			Transports: map[string]*control_plane.Transport{TransportQUIC: transport},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := parseResolutionResponse(raw); ok {
			t.Errorf("a %s parsed as an address", name)
		}
	}
	if _, ok := parseResolutionResponse([]byte{0xff, 0xff}); ok {
		t.Error("garbage parsed as a response")
	}
}
