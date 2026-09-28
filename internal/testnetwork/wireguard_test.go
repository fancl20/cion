package testnetwork

import (
	"context"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	wgconn "golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// The WireGuard application's integration tests' topology: the core A and the
// leaf B, each running the application; the hosts' entries arrive by the
// registry the core's store holds, exactly the coordination service's record —
// these tests hand it there until the coordination suites drive real logins.
var (
	wireguardA = addr.MustIAFrom(20, 0xff0000000051)
	wireguardB = addr.MustIAFrom(20, 0xff0000000052)
)

// newHostKey generates a host key pair in a throwaway directory.
func newHostKey(t *testing.T) (wireguard.PrivateKey, wireguard.PublicKey) {
	t.Helper()
	key, err := wireguard.LoadOrCreateKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return key, key.PublicKey()
}

// rawHost is a host whose device interface is a channel TUN: the test
// writes and reads its IP packets directly.
type rawHost struct {
	dev  *device.Device
	tun  *tuntest.ChannelTUN
	addr netip.Addr
}

// newRawHost builds a raw host bound to the node's shared port.
func newRawHost(t *testing.T, nodeKey wireguard.PublicKey, hostKey wireguard.PrivateKey,
	hostAddr netip.Addr, nodeAddr netip.AddrPort) *rawHost {

	t.Helper()
	tun := tuntest.NewChannelTUN()
	dev := device.NewDevice(tun.TUN(), wgconn.NewDefaultBind(),
		device.NewLogger(device.LogLevelSilent, "cion-host-test"))
	ipc := strings.Join([]string{
		"private_key=" + hex.EncodeToString(hostKey[:]),
		"public_key=" + nodeKey.String(),
		"endpoint=" + nodeAddr.String(),
		"allowed_ip=0.0.0.0/0",
		"persistent_keepalive_interval=1",
	}, "\n")
	if err := dev.IpcSet(ipc); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	return &rawHost{dev: dev, tun: tun, addr: hostAddr}
}

// hasMeshPeer reports whether the application holds the peer's mesh device.
func hasMeshPeer(a *wireguard.App, peer addr.IA) bool {
	for _, ia := range a.MeshPeers() {
		if ia.Equal(peer) {
			return true
		}
	}
	return false
}

// hasHostPeer reports whether the application's host device holds the
// host's entry.
func hasHostPeer(a *wireguard.App, host wireguard.HostEntry) bool {
	for _, h := range a.HostPeers() {
		if h.PublicKey == host.PublicKey && h.Addr == host.Addr {
			return true
		}
	}
	return false
}

// nodeHostPort returns the node's shared host-facing underlay endpoint.
func nodeHostPort(n *Node) netip.AddrPort {
	return netip.AddrPortFrom(n.ControlIP, n.Wireguard.HostPort())
}

// registerHost records one host's registry entry in the core's store — the
// record the coordination service's gate writes, handed here by the tests that
// stand in for the service.
func registerHost(t *testing.T, core *Node, host wireguard.HostEntry) {
	t.Helper()
	if err := core.WireguardStore.PublishHost(context.Background(), host); err != nil {
		t.Fatal(err)
	}
}

// startWireguardNodes brings up the two-node WireGuard topology: the core A
// and the leaf B, meshed over their seeded link.
func startWireguardNodes(t *testing.T, ipA, ipB netip.Addr) (*Node, *Node) {
	t.Helper()
	wpki := NewWebPKI(t)
	extA, extB := FreeUDPAddrOn(t, ipA), FreeUDPAddrOn(t, ipB)
	a := StartNode(t, NodeConfig{
		IA: wireguardA, Host: ipA, Core: true, WPKI: wpki,
		Links: []Link{{Local: extA, Remote: extB, Neighbor: wireguardB}},
		Wireguard: &WireguardOptions{
			Subnet: "100.64.1.0/24",
		},
	})
	b := StartNode(t, NodeConfig{
		IA: wireguardB, Host: ipB, WPKI: wpki,
		Links: []Link{{Local: extB, Remote: extA, Neighbor: wireguardA}},
		Wireguard: &WireguardOptions{
			Subnet: "100.64.2.0/24",
		},
	})
	Poll(t, "A's mesh peer", func() bool { return hasMeshPeer(a.Wireguard, wireguardB) })
	Poll(t, "B's mesh peer", func() bool { return hasMeshPeer(b.Wireguard, wireguardA) })
	return a, b
}

// TestWireguardMeshExchange is the mesh proof on the tailnet boundary: the
// host entries land in the core's registry, both nodes program their host
// devices from their fetched directories, and a host exchanges ICMP through
// its node's device, the mesh, and the far node's delivery to its own host.
func TestWireguardMeshExchange(t *testing.T) {
	t.Parallel()
	hostAKey, hostAPub := newHostKey(t)
	hostBKey, hostBPub := newHostKey(t)
	hostAAddr := netip.MustParseAddr("100.64.1.10")
	hostBAddr := netip.MustParseAddr("100.64.2.10")

	a, b := startWireguardNodes(t, addrIP(0x21), addrIP(0x22))
	registerHost(t, a, wireguard.HostEntry{
		PublicKey: hostAPub, Addr: hostAAddr, IA: wireguardA, Note: "test"})
	registerHost(t, a, wireguard.HostEntry{
		PublicKey: hostBPub, Addr: hostBAddr, IA: wireguardB, Note: "test"})
	// The nodes program themselves from the fetched set: both host devices
	// gain their peers within one fetch cadence.
	Poll(t, "A's host peer", func() bool {
		return hasHostPeer(a.Wireguard, wireguard.HostEntry{
			PublicKey: hostAPub, Addr: hostAAddr})
	})
	Poll(t, "B's host peer", func() bool {
		return hasHostPeer(b.Wireguard, wireguard.HostEntry{
			PublicKey: hostBPub, Addr: hostBAddr})
	})

	// Hosts: standard clients of their local nodes.
	hostA := newRawHost(t, a.Wireguard.PublicKey(), hostAKey, hostAAddr, nodeHostPort(a))
	hostB := newRawHost(t, b.Wireguard.PublicKey(), hostBKey, hostBAddr, nodeHostPort(b))

	// Host A echoes host B across the mesh: through A's host device, the
	// tunnel, and B's delivery to its own host.
	// The channel TUN's directions: Outbound feeds the device packets to
	// encrypt, Inbound takes its decrypted ones.
	hostA.tun.Outbound <- echoRequestPacket(hostAAddr, hostBAddr, 0x4242, 1, []byte("mesh"))
	select {
	case pkt := <-hostB.tun.Inbound:
		// The host answers the echo the way a host's stack would.
		if got := header.ICMPv4(header.IPv4(pkt).Payload()).Type(); got != header.ICMPv4Echo {
			t.Fatalf("host B received ICMP type %d, want echo", got)
		}
		hostB.tun.Outbound <- echoReplyFrom(pkt)
	case <-time.After(TestTimeout):
		t.Fatal("host B never received the echo through the mesh")
	}
	select {
	case pkt := <-hostA.tun.Inbound:
		icmpHdr := header.ICMPv4(header.IPv4(pkt).Payload())
		if icmpHdr.Type() != header.ICMPv4EchoReply {
			t.Fatalf("host A received ICMP type %d, want echo reply", icmpHdr.Type())
		}
		if icmpHdr.Ident() != 0x4242 {
			t.Errorf("reply identifier = %#x, want 0x4242", icmpHdr.Ident())
		}
		if got := netipOf(header.IPv4(pkt).SourceAddress()); got != hostBAddr {
			t.Errorf("reply source = %s, want %s", got, hostBAddr)
		}
	case <-time.After(TestTimeout):
		t.Fatal("host A never received the echoed reply")
	}
}

// echoRequestPacket builds an ICMP echo request between two overlay
// addresses.
func echoRequestPacket(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(payload))
	ipHdr := header.IPv4(pkt)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     addressOf(src),
		DstAddr:     addressOf(dst),
	})
	icmpHdr := header.ICMPv4(ipHdr.Payload())
	icmpHdr.SetType(header.ICMPv4Echo)
	icmpHdr.SetIdent(id)
	icmpHdr.SetSequence(seq)
	copy(icmpHdr.Payload(), payload)
	return pkt
}

// echoReplyFrom builds an echo reply for a received echo request packet.
func echoReplyFrom(pkt []byte) []byte {
	ipHdr := header.IPv4(pkt)
	reply := make([]byte, len(pkt))
	rIP := header.IPv4(reply)
	rIP.Encode(&header.IPv4Fields{
		TotalLength: ipHdr.TotalLength(),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     ipHdr.DestinationAddress(),
		DstAddr:     ipHdr.SourceAddress(),
	})
	rIP.SetChecksum(internetChecksum(reply[:header.IPv4MinimumSize]))
	req := header.ICMPv4(ipHdr.Payload())
	rICMP := header.ICMPv4(rIP.Payload())
	rICMP.SetType(header.ICMPv4EchoReply)
	rICMP.SetIdent(req.Ident())
	rICMP.SetSequence(req.Sequence())
	copy(rICMP.Payload(), req.Payload())
	rICMP.SetChecksum(internetChecksum(rIP.Payload()))
	return reply
}

// internetChecksum is the ones-complement checksum IPv4 and ICMP carry.
func internetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// addressOf converts an overlay address for a netstack header.
func addressOf(ip netip.Addr) tcpip.Address {
	return tcpip.AddrFromSlice(ip.AsSlice())
}

// netipOf converts a netstack address back.
func netipOf(a tcpip.Address) netip.Addr {
	ip, ok := netip.AddrFromSlice(a.AsSlice())
	if !ok {
		return netip.Addr{}
	}
	return ip
}
