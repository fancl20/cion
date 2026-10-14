package controlplane

import (
	"context"
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go/http3"

	"github.com/fancl20/cion/pkg/libs/scion"
)

// TestArrivalInterface checks the beacon handler's read of the arrival
// interface: the interface the one-hop path recorded, and a refusal where
// the request carries no remote address, or one without an interface.
func TestArrivalInterface(t *testing.T) {
	from := func(remote *scion.Addr) context.Context {
		return context.WithValue(t.Context(), http3.RemoteAddrContextKey, remote)
	}
	peer := netip.MustParseAddrPort("198.51.100.7:41234")

	got, err := arrivalInterface(from(&scion.Addr{IA: nodeIATest, Addr: peer, IfID: 7}))
	if err != nil || got != 7 {
		t.Errorf("arrivalInterface = %d, %v; want 7", got, err)
	}
	if _, err := arrivalInterface(from(&scion.Addr{IA: nodeIATest, Addr: peer})); err == nil {
		t.Error("a remote address without an arrival interface was accepted")
	}
	if _, err := arrivalInterface(t.Context()); err == nil {
		t.Error("a request without a remote address was accepted")
	}
}
