package testnetwork

import (
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	wgconn "golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wgnetstack "golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// The WireGuard application's integration tests' topology: the core A — the
// internet exit — and the leaf B, each running the application; the hosts
// are in-process WireGuard clients, plain internet clients of their local
// node.
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

// netstackHost is a host with a whole userspace TCP/IP stack: a real socket
// surface to dial the internet from.
type netstackHost struct {
	dev *device.Device
	net *wgnetstack.Net
}

// newNetstackHost builds a netstack-hosted host bound to the node's shared
// port.
func newNetstackHost(t *testing.T, nodeKey wireguard.PublicKey, hostKey wireguard.PrivateKey,
	hostAddr netip.Addr, nodeAddr netip.AddrPort) *netstackHost {

	t.Helper()
	tun, net, err := wgnetstack.CreateNetTUN([]netip.Addr{hostAddr}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, wgconn.NewDefaultBind(),
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
	return &netstackHost{dev: dev, net: net}
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

// nodeHostPort returns the node's shared host-facing underlay endpoint.
func nodeHostPort(n *Node) netip.AddrPort {
	return netip.AddrPortFrom(n.ControlIP, n.Wireguard.HostPort())
}

// startWireguardNodes brings up the two-node WireGuard topology: the core
// A — the internet exit — and the leaf B whose hosts send through it. A's
// own host is optional (a zero key runs A with none); B's hosts use A.
func startWireguardNodes(
	t *testing.T,
	ipA, ipB netip.Addr,
	hostAPub wireguard.PublicKey, hostAAddr netip.Addr,
	hostBPub wireguard.PublicKey, hostBAddr netip.Addr,
) (*Node, *Node) {

	t.Helper()
	wpki := NewWebPKI(t)
	extA, extB := FreeUDPAddrOn(t, ipA), FreeUDPAddrOn(t, ipB)
	var hostAPeers []wireguard.HostPeer
	if hostAPub != (wireguard.PublicKey{}) {
		hostAPeers = append(hostAPeers,
			wireguard.HostPeer{PublicKey: hostAPub, Addr: hostAAddr, Exit: wireguardA})
	}
	a := StartNode(t, NodeConfig{
		IA: wireguardA, Host: ipA, Core: true, WPKI: wpki,
		Links: []Link{{Local: extA, Remote: extB, Neighbor: wireguardB}},
		Wireguard: &WireguardOptions{
			Subnet: "10.64.1.0/24",
			Egress: true,
			Exits:  []addr.IA{wireguardA},
			Peers:  hostAPeers,
		},
	})
	b := StartNode(t, NodeConfig{
		IA: wireguardB, Host: ipB, WPKI: wpki,
		Links: []Link{{Local: extB, Remote: extA, Neighbor: wireguardA}},
		Wireguard: &WireguardOptions{
			Subnet: "10.64.2.0/24",
			Exits:  []addr.IA{wireguardA},
			Peers:  []wireguard.HostPeer{{PublicKey: hostBPub, Addr: hostBAddr, Exit: wireguardA}},
		},
	})
	Poll(t, "A's mesh peer", func() bool { return hasMeshPeer(a.Wireguard, wireguardB) })
	Poll(t, "B's mesh peer", func() bool { return hasMeshPeer(b.Wireguard, wireguardA) })
	return a, b
}

// TestWireguardMeshExchange is proposal 0006's mesh proof: the nodes
// publish and fetch the directory, mesh devices handshake over the SCION
// transport, and an in-process host exchanges ICMP through node B's host
// device, the mesh, and node A's delivery to its own in-process host.
func TestWireguardMeshExchange(t *testing.T) {
	hostAKey, hostAPub := newHostKey(t)
	hostBKey, hostBPub := newHostKey(t)
	hostAAddr := netip.MustParseAddr("10.64.1.10")
	hostBAddr := netip.MustParseAddr("10.64.2.10")

	// Loopback addresses of this test's own; the egress test's nodes keep
	// theirs.
	a, b := startWireguardNodes(t, addrIP(0x21), addrIP(0x22),
		hostAPub, hostAAddr, hostBPub, hostBAddr)

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

// internetHost returns a local non-loopback address to serve the "internet"
// on: the hosts' userspace stacks reject loopback sources as martian packets
// the way strict stacks do, so the stand-in internet must be a real address.
func internetHost(t *testing.T) netip.Addr {
	t.Helper()
	ipStr := os.Getenv("CION_TEST_INTERNET_HOST")
	if ipStr == "" {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range addrs {
			ap, ok := a.(*net.IPNet)
			if !ok || ap.IP.IsLoopback() {
				continue
			}
			// Interface addresses may carry the IPv4 as 4-in-6.
			if ip, ok := netip.AddrFromSlice(ap.IP); ok && ip.Unmap().Is4() {
				return ip.Unmap()
			}
		}
		t.Skip("no non-loopback IPv4 address to serve the internet stand-in on")
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil || !ip.Is4() {
		t.Skipf("CION_TEST_INTERNET_HOST %q is not an IPv4 address", ipStr)
	}
	return ip
}

// TestWireguardEgressProxiesInternet is proposal 0006's egress proof: an
// exit proxies a host's TCP flow to a local "internet" service and returns
// the reply — the host's handshake completing at the exit, the flow spliced
// to one outbound connection from the node's own address.
func TestWireguardEgressProxiesInternet(t *testing.T) {
	// The "internet": an echo service on the host's real address.
	listener, err := net.Listen("tcp", netip.AddrPortFrom(internetHost(t), 0).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	internet := listener.Addr().(*net.TCPAddr).AddrPort()

	hostBKey, hostBPub := newHostKey(t)
	hostBAddr := netip.MustParseAddr("10.64.2.10")
	_, b := startWireguardNodes(t, addrIP(0x23), addrIP(0x24),
		wireguard.PublicKey{}, netip.Addr{}, hostBPub, hostBAddr)

	host := newNetstackHost(t, b.Wireguard.PublicKey(), hostBKey, hostBAddr, nodeHostPort(b))
	conn, err := host.net.DialTCPAddrPort(internet)
	if err != nil {
		t.Fatalf("the host's TCP flow through the exit failed: %v", err)
	}
	defer func() { _ = conn.Close() }()
	msg := []byte("through the exit")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(TestTimeout)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("the internet's reply never returned through the exit: %v", err)
	}
	if string(got) != string(msg) {
		t.Errorf("echo = %q, want %q", got, msg)
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
