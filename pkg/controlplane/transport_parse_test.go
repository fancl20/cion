package controlplane

import (
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
)

// TestParseDatagramPacket checks the wire round trip of the datagram
// encoding the transport produces and parses.
func TestParseDatagramPacket(t *testing.T) {
	local := netip.MustParseAddrPort("127.0.0.1:30044")
	peer := netip.MustParseAddrPort("127.0.0.1:30111")
	conn, err := NewSCIONConn(SCIONConnConfig{
		IA:           addr.MustIAFrom(20, 0xff0000000001),
		Bind:         local.String(),
		InternalAddr: "127.0.0.1:30041",
		MACKey:       testMACKeyBytes,
		Links:        map[uint16]addr.IA{1: addr.MustIAFrom(20, 0xff0000000002)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck

	peerAddr := &Addr{IA: addr.MustIAFrom(20, 0xff0000000002), Addr: peer}
	raw, err := conn.datagramPacket(peerAddr, 1, []byte("quic payload"))
	if err != nil {
		t.Fatal(err)
	}
	payload, from, err := parseDatagramPacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "quic payload" {
		t.Fatalf("payload = %q", payload)
	}
	// The packet is one the local side sent, so the source is the local
	// endpoint; at the peer, the same parse yields the sender's address.
	if !from.IA.Equal(conn.LocalAddr().(*Addr).IA) {
		t.Fatalf("source IA = %v, want %v", from.IA, conn.LocalAddr().(*Addr).IA)
	}
	if from.Addr != conn.LocalAddr().(*Addr).Addr {
		t.Fatalf("source address = %v, want %v", from.Addr, conn.LocalAddr().(*Addr).Addr)
	}
	if from.IfID != 0 {
		t.Fatalf("ingress interface = %d, want 0 (not filled by a router)", from.IfID)
	}
}
