package bus

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/scionproto/scion/pkg/addr"
)

// TestTailnetState checks the tailnet view: it holds its entries copied,
// the nodes ordered by ISD-AS and the hosts by public key, so views of the
// same entries in any order are equal and a change to any field the view
// carries is not; the zero view equals the view of nothing.
func TestTailnetState(t *testing.T) {
	a, b := addr.MustIAFrom(1, 1), addr.MustIAFrom(1, 2)
	slice := netip.MustParsePrefix("100.64.1.0/24")
	nodeA := TailnetNode{IA: a, PublicKey: [32]byte{1}, Slice: slice,
		HostEndpoint: netip.MustParseAddrPort("192.0.2.1:51820")}
	nodeB := TailnetNode{IA: b, PublicKey: [32]byte{2}, Slice: netip.MustParsePrefix("100.64.2.0/24"),
		HostEndpoint: netip.MustParseAddrPort("192.0.2.2:51820")}
	hostA := TailnetHost{PublicKey: [32]byte{0xa}, Addr: netip.MustParseAddr("100.64.2.7"), IA: b}
	hostB := TailnetHost{PublicKey: [32]byte{0xb}, Addr: netip.MustParseAddr("100.64.1.7"), IA: a}

	nodes, hosts := []TailnetNode{nodeB, nodeA}, []TailnetHost{hostB, hostA}
	s := NewTailnetState(slice, nodes, hosts)
	want := TailnetState{Slice: slice, Nodes: []TailnetNode{nodeA, nodeB}, Hosts: []TailnetHost{hostA, hostB}}
	if diff := cmp.Diff(want, s,
		cmpopts.EquateComparable(netip.Prefix{}, netip.Addr{}, netip.AddrPort{})); diff != "" {
		t.Errorf("the view (-want +got):\n%s", diff)
	}
	nodes[0].IA, hosts[0].Addr = addr.MustIAFrom(1, 3), netip.MustParseAddr("100.64.9.9")
	if s.Nodes[1].IA != b || s.Hosts[1].Addr != hostB.Addr {
		t.Error("the view changed with the lists it was built of")
	}

	if same := NewTailnetState(slice, want.Nodes, want.Hosts); !same.Equal(s) {
		t.Error("views of the same entries in another order are not equal")
	}
	movedB := nodeB
	movedB.HostEndpoint = netip.MustParseAddrPort("192.0.2.9:51820")
	movedHost := hostA
	movedHost.Addr = netip.MustParseAddr("100.64.2.8")
	for name, changed := range map[string]TailnetState{
		"no slice":          NewTailnetState(netip.Prefix{}, want.Nodes, want.Hosts),
		"a departed node":   NewTailnetState(slice, want.Nodes[:1], want.Hosts),
		"a node's endpoint": NewTailnetState(slice, []TailnetNode{nodeA, movedB}, want.Hosts),
		"a departed host":   NewTailnetState(slice, want.Nodes, want.Hosts[1:]),
		"a host's address":  NewTailnetState(slice, want.Nodes, []TailnetHost{movedHost, hostB}),
	} {
		if changed.Equal(s) {
			t.Errorf("the view with %s equals the view without the change", name)
		}
	}

	var zero TailnetState
	if !zero.Equal(NewTailnetState(netip.Prefix{}, []TailnetNode{}, nil)) {
		t.Error("the zero view differs from the view of nothing")
	}
}
