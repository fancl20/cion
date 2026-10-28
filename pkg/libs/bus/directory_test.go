package bus

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/scionproto/scion/pkg/addr"
)

// TestDirectory checks the directory: the zero directory holds no entry,
// and a directory returns its entries and each by ISD-AS.
func TestDirectory(t *testing.T) {
	var zero Directory
	if zero.Entries() != nil {
		t.Errorf("the zero directory's entries = %v, want nil", zero.Entries())
	}
	a, b := addr.MustIAFrom(1, 1), addr.MustIAFrom(1, 2)
	entries := []DirectoryEntry{{IA: a}, {IA: b, Reach: Reach{BehindNAT: true}}}
	d := NewDirectory(entries...)
	if diff := cmp.Diff(entries, d.Entries(), cmpopts.EquateComparable(netip.AddrPort{})); diff != "" {
		t.Errorf("entries (-want +got):\n%s", diff)
	}
	if e, ok := d.Entry(b); !ok || !e.Reach.BehindNAT {
		t.Errorf("entry %v = %+v (%t), want its report", b, e, ok)
	}
	if _, ok := d.Entry(addr.MustIAFrom(1, 3)); ok {
		t.Error("a node the directory lacks has an entry")
	}
}
