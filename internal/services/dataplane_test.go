package services

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/links"
)

// TestGenerationSwapKeepsObservations checks which observations outlive the
// generation swap: an established link's, while it keeps its addresses,
// reads the same in the swap's gap, while no generation serves, and once
// the next generation serves the link; a candidate's, and an established
// link's whose remote or local address changed, start afresh.
func TestGenerationSwapKeepsObservations(t *testing.T) {
	n := setupFounderNode(t, func(*NodeConfig) {})
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 124)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	seen := peer.LocalAddr().(*net.UDPAddr).AddrPort()

	entry := func(neighbor uint64, local, remote string, state links.State) *links.Link {
		l := &links.Link{
			NeighborIA: addr.MustIAFrom(n.ident.ia.ISD(), addr.AS(neighbor)),
			Local:      netip.MustParseAddrPort(local),
			Remote:     netip.MustParseAddrPort(remote),
			State:      state,
		}
		if err := n.linkStore.Insert(t.Context(), l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	kept := entry(0xfd0000000097, "127.0.0.124:30046", "127.0.0.124:30047", links.StateEstablished)
	reaimed := entry(0xfd0000000098, "127.0.0.124:30048", "127.0.0.124:30049", links.StateEstablished)
	candidate := entry(0xfd0000000099, "127.0.0.124:30050", "127.0.0.124:30051", links.StateCandidate)
	all := []*links.Link{kept, reaimed, candidate}

	gen, err := n.startGeneration(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	n.setGeneration(gen)
	for _, l := range all {
		if _, err := peer.WriteToUDP([]byte("from the peer"), net.UDPAddrFromAddrPort(l.Local)); err != nil {
			t.Fatal(err)
		}
	}
	// Each arrival records its observation before it nudges the link state.
	deadline := time.After(10 * time.Second)
	for _, l := range all {
		for n.observedSource(l.IfID) != seen {
			select {
			case <-n.linkNudges:
			case <-deadline:
				t.Fatalf("interface %d observed %v, want the peer's %v", l.IfID, n.observedSource(l.IfID), seen)
			}
		}
	}

	// swap retires the serving generation, checks the observations read in
	// the gap, and serves the next generation built from the store.
	swap := func(want map[*links.Link]netip.AddrPort) {
		t.Helper()
		gen.stop()
		n.setGeneration(nil)
		for l, w := range want {
			if got := n.observedSource(l.IfID); got != w {
				t.Errorf("interface %d in the swap's gap observed %v, want %v", l.IfID, got, w)
			}
		}
		next, err := n.startGeneration(t.Context(), gen)
		if err != nil {
			t.Fatal(err)
		}
		n.setGeneration(next)
		gen = next
	}
	reaimed.Remote = netip.MustParseAddrPort("127.0.0.124:30052")
	if err := n.linkStore.Update(t.Context(), reaimed); err != nil {
		t.Fatal(err)
	}
	swap(map[*links.Link]netip.AddrPort{kept: seen, reaimed: seen, candidate: seen})
	for l, want := range map[*links.Link]netip.AddrPort{kept: seen, reaimed: {}, candidate: {}} {
		if got := n.observedSource(l.IfID); got != want {
			t.Errorf("interface %d in the next generation observed %v, want %v", l.IfID, got, want)
		}
	}

	kept.Local = netip.MustParseAddrPort("127.0.0.124:30053")
	if err := n.linkStore.Update(t.Context(), kept); err != nil {
		t.Fatal(err)
	}
	swap(map[*links.Link]netip.AddrPort{kept: seen})
	defer gen.stop()
	if got := n.observedSource(kept.IfID); got.IsValid() {
		t.Errorf("interface %d on a new local address observed %v, want none", kept.IfID, got)
	}
}
