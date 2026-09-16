package scion

import (
	"net/netip"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
)

// TestParseDatagramPacket checks the wire round trip of the datagram
// encoding the transport produces and parses.
func TestParseDatagramPacket(t *testing.T) {
	local := netip.MustParseAddrPort("127.0.0.1:30044")
	peer := netip.MustParseAddrPort("127.0.0.1:30111")
	conn, err := NewConn(ConnConfig{
		IA:           addr.MustIAFrom(20, 0xff0000000001),
		Bind:         local.String(),
		InternalAddr: "127.0.0.1:30041",
		MACKey:       testMACKeyBytes,
		Links:        func() map[uint16]addr.IA { return map[uint16]addr.IA{1: addr.MustIAFrom(20, 0xff0000000002)} },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck

	peerAddr := &Addr{IA: addr.MustIAFrom(20, 0xff0000000002), Addr: peer}
	raw, err := conn.writePacket(peerAddr, slayers.L4UDP, func(scn *slayers.SCION) ([]byte, error) {
		return serializeUDP(scn, local.Port(), peer.Port(), []byte("quic payload"))
	})
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

// TestWritePacketServiceHeader checks the wire form of a service
// destination: the SCION header carries a service host, and the inner UDP
// destination port is zero — the destination names no port, the receiving
// AS's registration owns it.
func TestWritePacketServiceHeader(t *testing.T) {
	local := netip.MustParseAddrPort("127.0.0.1:30044")
	conn, err := NewConn(ConnConfig{
		IA:           addr.MustIAFrom(20, 0xff0000000001),
		Bind:         local.String(),
		InternalAddr: "127.0.0.1:30041",
		MACKey:       testMACKeyBytes,
		Links:        func() map[uint16]addr.IA { return map[uint16]addr.IA{1: addr.MustIAFrom(20, 0xff0000000002)} },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck

	svc := addr.SVC(0x7ff1)
	peerAddr := &Addr{IA: addr.MustIAFrom(20, 0xff0000000002), Service: svc}
	raw, err := conn.writePacket(peerAddr, slayers.L4UDP, func(scn *slayers.SCION) ([]byte, error) {
		return serializeUDP(scn, local.Port(), peerAddr.Addr.Port(), []byte("payload"))
	})
	if err != nil {
		t.Fatal(err)
	}
	pkt := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.NoCopy)
	scn := pkt.Layer(slayers.LayerTypeSCION).(*slayers.SCION)
	dst, err := scn.DstAddr()
	if err != nil {
		t.Fatal(err)
	}
	if dst.Type() != addr.HostTypeSVC || dst.SVC() != svc {
		t.Errorf("destination host = %v, want the service %v", dst, svc)
	}
	udp := pkt.Layer(slayers.LayerTypeSCIONUDP).(*slayers.UDP)
	if udp.DstPort != 0 {
		t.Errorf("destination port = %d, want 0", udp.DstPort)
	}
}
