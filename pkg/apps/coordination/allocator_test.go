package coordination

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/apps/wireguard/impl/dbtest"
)

// TestAllocateIssuesInOrder checks the sequence: allocation starts after
// the slice's first address — the node's own — and takes the next free,
// the same key re-registers to the same address, a new key takes the next.
func TestAllocateIssuesInOrder(t *testing.T) {
	node := mustIA("1-ff00:0:1")
	directory := wireguard.Directory{Nodes: []wireguard.Entry{
		testNode(node, "100.64.1.0/24", "198.51.100.10:51820"),
	}}
	first, err := allocate(dbtest.MustKey(1), directory, node)
	if err != nil {
		t.Fatal(err)
	}
	if want := "100.64.1.2"; first.Addr.String() != want {
		t.Fatalf("the first allocation = %s, want the next after the node's own %s",
			first.Addr, want)
	}
	if !first.IA.Equal(node) {
		t.Fatalf("the first allocation's owner = %s, want the named node", first.IA)
	}
	// Idempotence: the same key re-registers to the same address.
	directory.Hosts = append(directory.Hosts, first)
	again, err := allocate(dbtest.MustKey(1), directory, node)
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Fatalf("a re-registration = %+v, want the same record %+v", again, first)
	}
	// A new key takes the next address.
	next, err := allocate(dbtest.MustKey(2), directory, node)
	if err != nil {
		t.Fatal(err)
	}
	if want := "100.64.1.3"; next.Addr.String() != want {
		t.Fatalf("the second allocation = %s, want %s", next.Addr, want)
	}
}

// TestAllocateNamedNode checks the placement: the named node's slice takes
// the host however full it is beside the others, and a key the registry
// holds answers its record whatever node is named — the record never
// moves.
func TestAllocateNamedNode(t *testing.T) {
	directory := wireguard.Directory{Nodes: []wireguard.Entry{
		testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"),
		testNode(mustIA("1-ff00:0:2"), "100.64.2.0/24", "198.51.100.20:51820"),
	}}
	directory.Hosts = append(directory.Hosts,
		wireguard.HostEntry{PublicKey: dbtest.MustKey(0xa), Addr: ip("100.64.1.2"), IA: mustIA("1-ff00:0:1")},
	)
	host, err := allocate(dbtest.MustKey(1), directory, mustIA("1-ff00:0:1"))
	if err != nil {
		t.Fatal(err)
	}
	if !host.IA.Equal(mustIA("1-ff00:0:1")) || host.Addr != ip("100.64.1.3") {
		t.Fatalf("placement = %s at %s, want the named 1-ff00:0:1 at 100.64.1.3", host.IA, host.Addr)
	}
	directory.Hosts = append(directory.Hosts, host)
	held, err := allocate(dbtest.MustKey(1), directory, mustIA("1-ff00:0:2"))
	if err != nil {
		t.Fatal(err)
	}
	if held != host {
		t.Fatalf("a held key named elsewhere = %+v, want its record %+v", held, host)
	}
}

// TestAllocateRefusals checks the allocator's refusals, each naming the
// node: a node the directory holds no entry of, an entry publishing no host
// endpoint, and a full slice refuse rather than place the host elsewhere.
func TestAllocateRefusals(t *testing.T) {
	// A full /29: network, node's own, five allocatable minus five issued.
	// Sized so the issued set exhausts it exactly.
	full := wireguard.Directory{Nodes: []wireguard.Entry{
		testNode(mustIA("1-ff00:0:1"), "100.64.1.0/29", "198.51.100.10:51820"),
		testNode(mustIA("1-ff00:0:2"), "100.64.2.0/24", "198.51.100.20:51820"),
	}}
	for i := range 5 {
		full.Hosts = append(full.Hosts, wireguard.HostEntry{
			PublicKey: dbtest.MustKey(byte(i + 1)),
			Addr:      ipMasked("100.64.1.", byte(2+i)),
			IA:        mustIA("1-ff00:0:1"),
		})
	}
	silent := testNode(mustIA("1-ff00:0:3"), "100.64.3.0/24", "198.51.100.30:51820")
	silent.HostEndpoint = netip.AddrPort{}
	full.Nodes = append(full.Nodes, silent)

	for _, tc := range []struct {
		name string
		node string
	}{
		{"a full slice", "1-ff00:0:1"},
		{"a node the directory holds no entry of", "1-ff00:0:9"},
		{"an entry publishing no host endpoint", "1-ff00:0:3"},
	} {
		_, err := allocate(dbtest.MustKey(0x7f), full, mustIA(tc.node))
		if err == nil {
			t.Errorf("%s allocated, want refusal", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.node) {
			t.Errorf("%s refused with %q, want the node named", tc.name, err)
		}
	}
}
