package bus

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/links"
)

// TestLinkState asserts the derivations: the table names every live entry's
// neighbor, the usable links leave the down ones out, an interface no entry
// holds is up, observed nowhere, and not established.
func TestLinkState(t *testing.T) {
	a, b := addr.MustIAFrom(1, 0xff0000000001), addr.MustIAFrom(1, 0xff0000000002)
	seen := netip.MustParseAddrPort("192.0.2.1:30000")
	s := NewLinkState(
		Link{Entry: links.Link{IfID: 1, NeighborIA: a, State: links.StateEstablished}, Observed: seen},
		Link{Entry: links.Link{IfID: 2, NeighborIA: b, State: links.StateCandidate}, Down: true},
	)
	if diff := cmp.Diff(map[uint16]addr.IA{1: a, 2: b}, s.Table()); diff != "" {
		t.Errorf("Table() mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(map[uint16]addr.IA{1: a}, s.Usable()); diff != "" {
		t.Errorf("Usable() mismatch (-want +got):\n%s", diff)
	}
	for _, c := range []struct {
		ifID        uint16
		up          bool
		observed    netip.AddrPort
		established bool
	}{
		{ifID: 1, up: true, observed: seen, established: true},
		{ifID: 2, up: false},
		{ifID: 3, up: true},
	} {
		if got := s.Up(c.ifID); got != c.up {
			t.Errorf("Up(%d) = %v, want %v", c.ifID, got, c.up)
		}
		if got := s.Established(c.ifID); got != c.established {
			t.Errorf("Established(%d) = %v, want %v", c.ifID, got, c.established)
		}
		if got := s.Observed(c.ifID); got != c.observed {
			t.Errorf("Observed(%d) = %v, want %v", c.ifID, got, c.observed)
		}
	}
}

// TestZeroLinkState asserts that the state before the node's first publish
// holds no table and filters nothing, while a published state of no links
// filters every interface out.
func TestZeroLinkState(t *testing.T) {
	var zero LinkState
	if zero.Table() != nil || zero.Usable() != nil {
		t.Errorf("zero state: Table() = %v, Usable() = %v, want nil", zero.Table(), zero.Usable())
	}
	if !zero.Up(1) {
		t.Error("zero state: Up(1) = false, want true")
	}
	empty := NewLinkState()
	if empty.Usable() == nil {
		t.Error("NewLinkState(): Usable() = nil, want an empty filter")
	}
}
