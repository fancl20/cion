package scionrpc

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/scion"
)

// TestPeerAuthorityRoundTrip checks the authority encoding both destination
// forms and the named egress interface keep: an underlay peer, a service
// peer, and the one-hop form beside either decode back to themselves.
func TestPeerAuthorityRoundTrip(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000021)
	for _, peer := range []*scion.Addr{
		{IA: ia, Addr: netip.MustParseAddrPort("192.0.2.7:30042")},
		{IA: ia, Service: addr.SVC(0x7ff2)},
		{IA: ia, Service: addr.SVC(0x7ff2), IfID: 7},
	} {
		got, err := peerFromAuthority(PeerAuthority(peer))
		if err != nil {
			t.Fatalf("decoding the authority of %s: %v", peer, err)
		}
		if !got.IA.Equal(peer.IA) || got.Addr != peer.Addr ||
			got.Service != peer.Service || got.IfID != peer.IfID {
			t.Errorf("authority round trip = %v, want %v", got, peer)
		}
	}
}

// TestSCIONClientServiceWithoutBackend checks the publish-side negative: a
// dial toward a service with no registered backend fails — the receiving
// router answers SCMP destination unreachable, the sender sees the dial time
// out — rather than hanging or succeeding.
func TestSCIONClientServiceWithoutBackend(t *testing.T) {
	iaA := addr.MustIAFrom(20, 0xff0000000031)
	iaB := addr.MustIAFrom(20, 0xff0000000032)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	a := startTestNode(t, iaA, iaB, extA, extB)
	startTestNode(t, iaB, iaA, extB, extA)

	conn := a.newConn(t, 0)
	qclt := &quic.Transport{Conn: conn}
	t.Cleanup(func() { _ = qclt.Close() })
	// The dial's TLS is never exercised: no backend answers the handshake.
	hclt := NewSCIONClient(PeerClientConfig{Conn: conn}, qclt, false)
	unregistered := &scion.Addr{IA: iaB, Service: addr.SVC(0x7ff2)}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://"+PeerAuthority(unregistered)+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hclt.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("a dial to a service with no backend succeeded")
	}
}
