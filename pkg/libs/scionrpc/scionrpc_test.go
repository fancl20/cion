package scionrpc

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/scion"
)

// TestRemoteAddr checks the readers of a request's remote address: the SCION
// address the HTTP/3 server puts in the request's context, and nothing — a
// nil address and the zero underlay — where the context carries none or an
// address of another kind.
func TestRemoteAddr(t *testing.T) {
	remote := &scion.Addr{
		IA:   addr.MustIAFrom(20, 0xff0000000002),
		Addr: netip.MustParseAddrPort("198.51.100.7:41234"),
		IfID: 7,
	}
	ctx := context.WithValue(t.Context(), http3.RemoteAddrContextKey, remote)
	if got := RemoteAddr(ctx); got != remote {
		t.Errorf("RemoteAddr = %v, want %v", got, remote)
	}
	if got := RemoteUnderlay(ctx); got != remote.Addr {
		t.Errorf("RemoteUnderlay = %v, want %v", got, remote.Addr)
	}

	udp := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 41234}
	for name, ctx := range map[string]context.Context{
		"no address":    t.Context(),
		"a UDP address": context.WithValue(t.Context(), http3.RemoteAddrContextKey, udp),
	} {
		if got := RemoteAddr(ctx); got != nil {
			t.Errorf("%s: RemoteAddr = %v, want nil", name, got)
		}
		if got := RemoteUnderlay(ctx); got.IsValid() {
			t.Errorf("%s: RemoteUnderlay = %v, want the zero address", name, got)
		}
	}
}
