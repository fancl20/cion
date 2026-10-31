package bus

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/scionproto/scion/pkg/addr"
)

// TestDirectory checks the directory: the zero directory holds no scope; a
// directory orders its scopes by ID, returns each by ID with its entries and
// each entry by ISD-AS, names the scope each link joins, and returns a
// node's entry signed last among its scopes.
func TestDirectory(t *testing.T) {
	var zero Directory
	if zero.Scopes() != nil {
		t.Errorf("the zero directory's scopes = %v, want nil", zero.Scopes())
	}
	a, b := addr.MustIAFrom(1, 1), addr.MustIAFrom(1, 2)
	early, late := DirectoryID{1}, DirectoryID{2}
	at := time.Unix(1_700_000_000, 0)
	host := netip.MustParseAddrPort("192.0.2.1:31000")
	lateEntries := []DirectoryEntry{
		{IA: a, Published: at},
		{IA: b, Addresses: []Address{{RendezvousAddr: host, Reach: Reach{BehindNAT: true}}},
			Published: at.Add(time.Minute)},
	}
	d := NewDirectory(map[uint16]DirectoryID{7: late},
		NewScope(late, lateEntries...), NewScope(early, DirectoryEntry{IA: b, Published: at}))
	if got := []DirectoryID{d.Scopes()[0].ID(), d.Scopes()[1].ID()}; got[0] != early || got[1] != late {
		t.Errorf("the scopes' order = %v, want the lesser ID first", got)
	}
	s, ok := d.Scope(late)
	if !ok {
		t.Fatalf("the directory lacks the scope %v", late)
	}
	if diff := cmp.Diff(lateEntries, s.Entries(), cmpopts.EquateComparable(netip.AddrPort{})); diff != "" {
		t.Errorf("entries (-want +got):\n%s", diff)
	}
	if e, ok := s.Entry(b); !ok || !e.Addresses[0].Reach.BehindNAT {
		t.Errorf("entry %v = %+v (%t), want its report", b, e, ok)
	}
	if _, ok := s.Entry(addr.MustIAFrom(1, 3)); ok {
		t.Error("a node the scope lacks has an entry")
	}
	if id, ok := d.LinkScope(7); !ok || id != late {
		t.Errorf("the link's scope = %v (%t), want %v", id, ok, late)
	}
	if _, ok := d.LinkScope(8); ok {
		t.Error("a link that joins no directory names a scope")
	}
	if e, ok := d.Latest(b); !ok || !e.Published.Equal(at.Add(time.Minute)) {
		t.Errorf("the latest entry of %v = %+v (%t), want the one signed last", b, e, ok)
	}
}
