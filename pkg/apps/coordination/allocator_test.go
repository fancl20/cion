package coordination

import (
	"testing"

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// TestAllocateIssuesInOrder checks the sequence: allocation starts after
// the slice's first address — the node's own — and takes the next free,
// the same key re-registers to the same address, a new key takes the next.
func TestAllocateIssuesInOrder(t *testing.T) {
	directory := wireguard.Directory{Nodes: []wireguard.Entry{
		testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"),
	}}
	first, err := allocate(testHostKey(1), directory)
	if err != nil {
		t.Fatal(err)
	}
	if want := "100.64.1.2"; first.Addr.String() != want {
		t.Fatalf("the first allocation = %s, want the next after the node's own %s",
			first.Addr, want)
	}
	if !first.IA.Equal(mustIA("1-ff00:0:1")) {
		t.Fatalf("the first allocation's owner = %s, want the only node", first.IA)
	}
	// Idempotence: the same key re-registers to the same address.
	directory.Hosts = append(directory.Hosts, first)
	again, err := allocate(testHostKey(1), directory)
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Fatalf("a re-registration = %+v, want the same record %+v", again, first)
	}
	// A new key takes the next address.
	next, err := allocate(testHostKey(2), directory)
	if err != nil {
		t.Fatal(err)
	}
	if want := "100.64.1.3"; next.Addr.String() != want {
		t.Fatalf("the second allocation = %s, want %s", next.Addr, want)
	}
}

// TestAllocatePlacement checks the owning node's choice: the freest slice
// takes the host, and ties break to the lowest ISD-AS.
func TestAllocatePlacement(t *testing.T) {
	directory := wireguard.Directory{Nodes: []wireguard.Entry{
		testNode(mustIA("1-ff00:0:3"), "100.64.3.0/24", "198.51.100.30:51820"),
		testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"),
		testNode(mustIA("1-ff00:0:2"), "100.64.2.0/24", "198.51.100.20:51820"),
	}}
	// The second node's slice is the emptiest beside the first's one host.
	directory.Hosts = append(directory.Hosts,
		wireguard.HostEntry{PublicKey: testHostKey(0xa), Addr: ip("100.64.1.2"), IA: mustIA("1-ff00:0:1")},
		wireguard.HostEntry{PublicKey: testHostKey(0xb), Addr: ip("100.64.3.2"), IA: mustIA("1-ff00:0:3")},
	)
	host, err := allocate(testHostKey(1), directory)
	if err != nil {
		t.Fatal(err)
	}
	if !host.IA.Equal(mustIA("1-ff00:0:2")) {
		t.Fatalf("placement = %s, want the freest slice 1-ff00:0:2", host.IA)
	}
	// Ties break to the lowest ISD-AS: with one host in each of two equal
	// slices, the lower ISD-AS takes the next.
	tie := wireguard.Directory{Nodes: []wireguard.Entry{
		testNode(mustIA("1-ff00:0:2"), "100.64.2.0/24", "198.51.100.20:51820"),
		testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"),
	}}
	tie.Hosts = append(tie.Hosts,
		wireguard.HostEntry{PublicKey: testHostKey(0xb), Addr: ip("100.64.2.2"), IA: mustIA("1-ff00:0:2")},
		wireguard.HostEntry{PublicKey: testHostKey(0xa), Addr: ip("100.64.1.2"), IA: mustIA("1-ff00:0:1")},
	)
	host, err = allocate(testHostKey(2), tie)
	if err != nil {
		t.Fatal(err)
	}
	if !host.IA.Equal(mustIA("1-ff00:0:1")) {
		t.Fatalf("tie-break placement = %s, want the lowest 1-ff00:0:1", host.IA)
	}
}

// TestAllocateRefusals checks the allocator's two refusals: a full slice
// refuses its node new hosts, and overlapping live slices — the operator's
// error — refuse registrations into either, with the pair named, while a
// clean slice beside them still takes hosts. An empty directory holds no
// placement at all.
func TestAllocateRefusals(t *testing.T) {
	// A full /29: network, node's own, five allocatable minus five issued.
	// Sized so the issued set exhausts it exactly.
	full := wireguard.Directory{Nodes: []wireguard.Entry{
		testNode(mustIA("1-ff00:0:1"), "100.64.1.0/29", "198.51.100.10:51820"),
	}}
	for i := 0; i < 5; i++ {
		full.Hosts = append(full.Hosts, wireguard.HostEntry{
			PublicKey: testHostKey(byte(i + 1)),
			Addr:      ipMasked("100.64.1.", byte(2+i)),
			IA:        mustIA("1-ff00:0:1"),
		})
	}
	if _, err := allocate(testHostKey(0x7f), full); err == nil {
		t.Error("a full slice allocated, want refusal")
	}

	// Overlapping slices refuse with the pair named; the clean third slice
	// beside them still takes the host.
	overlap := wireguard.Directory{Nodes: []wireguard.Entry{
		testNode(mustIA("1-ff00:0:1"), "100.64.1.0/24", "198.51.100.10:51820"),
		testNode(mustIA("1-ff00:0:2"), "100.64.1.0/25", "198.51.100.20:51820"),
		testNode(mustIA("1-ff00:0:3"), "100.64.3.0/24", "198.51.100.30:51820"),
	}}
	host, err := allocate(testHostKey(1), overlap)
	if err != nil {
		t.Fatal(err)
	}
	if !host.IA.Equal(mustIA("1-ff00:0:3")) {
		t.Fatalf("placement beside overlaps = %s, want the clean 1-ff00:0:3", host.IA)
	}
	// With only the overlapping pair left, the refusal names it.
	overlap.Nodes = overlap.Nodes[:2]
	_, err = allocate(testHostKey(2), overlap)
	if err == nil {
		t.Fatal("an overlapping-slice directory allocated, want refusal")
	}

	if _, err := allocate(testHostKey(1), wireguard.Directory{}); err == nil {
		t.Error("an empty directory allocated, want refusal")
	}
}
