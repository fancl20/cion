package controlplane

import (
	"context"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

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

// TestRegistrantServer checks where a registration's missing trust material
// is asked: the registrant's control service over the reverse of the path
// the request arrived on, over the arrival link when it came one hop, and a
// refusal where the request carries no remote address.
func TestRegistrantServer(t *testing.T) {
	from := func(remote *scion.Addr) context.Context {
		return context.WithValue(t.Context(), http3.RemoteAddrContextKey, remote)
	}
	peer := netip.MustParseAddrPort("198.51.100.7:41234")
	reversed := &spath.Decoded{}

	for _, tc := range []struct {
		name   string
		remote *scion.Addr
		want   *scion.Addr
	}{
		{
			name:   "over a path",
			remote: &scion.Addr{IA: nodeIATest, Addr: peer, Path: reversed},
			want:   &scion.Addr{IA: nodeIATest, Service: addr.SvcCS, Path: reversed},
		},
		{
			name:   "one hop",
			remote: &scion.Addr{IA: nodeIATest, Addr: peer, IfID: 7},
			want:   &scion.Addr{IA: nodeIATest, Service: addr.SvcCS, IfID: 7},
		},
	} {
		got, err := registrantServer(from(tc.remote))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if diff := cmp.Diff(tc.want, got, cmpopts.EquateComparable(netip.AddrPort{}),
			cmp.Comparer(func(a, b *spath.Decoded) bool { return a == b })); diff != "" {
			t.Errorf("%s: registrant server (-want +got):\n%s", tc.name, diff)
		}
	}
	if _, err := registrantServer(t.Context()); err == nil {
		t.Error("a request without a remote address was accepted")
	}
}
