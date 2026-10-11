package measured

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/links/impl/memory"
	"github.com/fancl20/cion/pkg/modules/topology"
)

// bandHost is the loopback host the band's episodes bind on, one no other
// test of the package takes.
var bandHost = netip.MustParseAddr("127.0.0.123")

// inBand reports whether the address is a port of the link band on the
// band's host.
func inBand(a netip.AddrPort) bool {
	return a.Addr() == bandHost &&
		a.Port() >= LinkPortBase && a.Port() < LinkPortBase+LinkPortSpan
}

// heldBand returns live entries holding every port of the band on the
// band's host but the given ones: seeded entries, live with no remote.
func heldBand(free ...uint16) []*links.Link {
	var entries []*links.Link
	for port := uint16(LinkPortBase); port < LinkPortBase+LinkPortSpan; port++ {
		held := true
		for _, f := range free {
			held = held && port != f
		}
		if held {
			entries = append(entries, &links.Link{
				Local: netip.AddrPortFrom(bandHost, port),
				State: links.StateCandidate,
			})
		}
	}
	return entries
}

// TestAllocateLinkAddrDrawsFromBand checks that every allocation lands in
// the link band.
func TestAllocateLinkAddrDrawsFromBand(t *testing.T) {
	for range 50 {
		got, err := AllocateLinkAddr(bandHost, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !inBand(got) {
			t.Fatalf("allocated %v, want a port of %d-%d on %v", got,
				LinkPortBase, LinkPortBase+LinkPortSpan-1, bandHost)
		}
	}
}

// TestLinkBandBelowEphemeralRange checks the band's premise on the host the
// suite runs on: the kernel's ephemeral range, where every bind of port 0
// lands, leaves the band alone.
func TestLinkBandBelowEphemeralRange(t *testing.T) {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		t.Skipf("reading the kernel's ephemeral range: %v", err)
	}
	var low, high int
	if _, err := fmt.Sscan(string(raw), &low, &high); err != nil {
		t.Fatalf("parsing the kernel's ephemeral range %q: %v", raw, err)
	}
	if LinkPortBase <= high && low < LinkPortBase+LinkPortSpan {
		t.Errorf("the band %d-%d overlaps the kernel's ephemeral range %d-%d",
			LinkPortBase, LinkPortBase+LinkPortSpan-1, low, high)
	}
}

// TestAllocateLinkAddrSkipsHeldPorts checks what an allocation skips: with
// the live entries holding every port of the band but two and a socket
// holding one of the two, every draw takes the other, whatever its offset;
// a retired entry's port is free to draw; and with both held, the
// allocation fails.
func TestAllocateLinkAddrSkipsHeldPorts(t *testing.T) {
	bound, free := uint16(LinkPortBase+10), uint16(LinkPortBase+500)
	entries := heldBand(bound, free)
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(bandHost, bound)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	want := netip.AddrPortFrom(bandHost, free)
	for range 20 {
		got, err := AllocateLinkAddr(bandHost, entries)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("allocated %v, want the one free %v", got, want)
		}
	}
	retired := &links.Link{Local: want, State: links.StateRetired}
	if got, err := AllocateLinkAddr(bandHost, append(entries, retired)); err != nil || got != want {
		t.Errorf("allocated (%v, %v) beside a retired entry on %v, want it", got, err, want)
	}
	live := &links.Link{Local: want, State: links.StateEstablished}
	if got, err := AllocateLinkAddr(bandHost, append(entries, live)); err == nil {
		t.Errorf("an allocation over a band held whole returned %v", got)
	}
}

// TestSeedDrawsAgainstEarlierSeeds checks that each seed draws its link
// address against the table as the earlier seeds left it: two seeds over a
// band with two free ports take both, whatever the draws' offsets.
func TestSeedDrawsAgainstEarlierSeeds(t *testing.T) {
	first, second := uint16(LinkPortBase+100), uint16(LinkPortBase+101)
	want := map[netip.AddrPort]bool{
		netip.AddrPortFrom(bandHost, first):  true,
		netip.AddrPortFrom(bandHost, second): true,
	}
	for range 10 {
		store := memory.New()
		for _, l := range heldBand(first, second) {
			if err := store.Insert(context.Background(), l); err != nil {
				t.Fatal(err)
			}
		}
		z, err := New(Config{
			ControlHost: bandHost,
			Neighbors:   []string{"192.0.2.1:30043", "192.0.2.2:30043"},
		})
		if err != nil {
			t.Fatal(err)
		}
		z.Wire(topology.Pieces{IA: zeroconfDraw, Store: store})
		if err := z.Seed(context.Background()); err != nil {
			t.Fatal(err)
		}
		entries, err := store.All(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		got := make(map[netip.AddrPort]bool)
		for _, l := range entries {
			if l.Rendezvous.IsValid() {
				got[l.Local] = true
			}
		}
		if !maps.Equal(got, want) {
			t.Fatalf("the seeds' local addresses = %v, want %v", got, want)
		}
	}
}
