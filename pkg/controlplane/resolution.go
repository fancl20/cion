package controlplane

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/proto/control_plane"
	"google.golang.org/protobuf/proto"

	"github.com/fancl20/cion/pkg/scion"
)

// TransportQUIC names the QUIC transport of a service-resolution response —
// the one transport the drafts list and the one the control endpoint serves
// (control plane draft, Section 5).
const TransportQUIC = "QUIC"

// Resolution pacing: one resolution runs at most ResolutionAttempts request
// rounds, waiting ResolutionAttemptWait for each reply.
const (
	ResolutionAttempts    = 3
	ResolutionAttemptWait = 500 * time.Millisecond
)

// ResolveService resolves a peer's service through the drafts' service
// discovery (control plane draft, Section 5): an empty ServiceResolutionRequest
// to the peer's service address — the CS service on a one-hop path for a
// neighbor, or the path the peer address carries — answered by the service's
// QUIC transport address. The request needs no state the sender does not
// already hold: the service destination reaches the registered backend
// wherever a path exists, and the reply reverses the request's. A service no
// backend answers is refused cleanly — the reply never comes, and the
// bounded attempts return their error.
//
// The exchange reads the conn for its wait's duration, so the conn must be
// the exchange's alone: a conn a QUIC transport reads shares its packets
// with this loop, and either reader can swallow the other's. Callers wire a
// dedicated conn.
func ResolveService(ctx context.Context, conn *scion.Conn, peer *scion.Addr) (netip.AddrPort, error) {
	req, err := proto.Marshal(&control_plane.ServiceResolutionRequest{})
	if err != nil {
		return netip.AddrPort{}, err
	}
	buf := make([]byte, 1024)
	for attempt := 0; attempt < ResolutionAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return netip.AddrPort{}, err
		}
		sent := time.Now()
		if _, err := conn.WriteTo(req, peer); err != nil {
			return netip.AddrPort{}, err
		}
		if err := conn.SetReadDeadline(sent.Add(ResolutionAttemptWait)); err != nil {
			return netip.AddrPort{}, err
		}
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				break // the wait elapsed: lost, retry
			}
			// A reply of another peer's — a concurrent resolution sharing
			// the conn — is not this one's answer.
			if a, ok := from.(*scion.Addr); ok && !a.IA.Equal(peer.IA) {
				continue
			}
			if addr, ok := parseResolutionResponse(buf[:n]); ok {
				return addr, nil
			}
		}
	}
	return netip.AddrPort{}, fmt.Errorf("no resolution response from %s", peer)
}

// parseResolutionResponse decodes a resolution reply and returns its QUIC
// transport address; unknown transports are ignored, as the drafts direct,
// and a missing or malformed port is an error rather than an address.
func parseResolutionResponse(b []byte) (netip.AddrPort, bool) {
	var resp control_plane.ServiceResolutionResponse
	if err := proto.Unmarshal(b, &resp); err != nil {
		return netip.AddrPort{}, false
	}
	t, ok := resp.Transports[TransportQUIC]
	if !ok || t == nil {
		return netip.AddrPort{}, false
	}
	addr, err := netip.ParseAddrPort(t.Address)
	if err != nil || addr.Port() == 0 {
		return netip.AddrPort{}, false
	}
	return addr, true
}
