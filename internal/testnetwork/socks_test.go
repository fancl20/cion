package testnetwork

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"tailscale.com/tsnet"

	"github.com/fancl20/cion/internal/socksclient"
	"github.com/fancl20/cion/pkg/apps/socks"
)

// The SOCKS egress suites ride the coordination lab: the core-and-leaf
// assembly with the tsnet host double, every node offering the service on its
// slice's first address by default, and the netmap carrying those addresses
// beside the allocated hosts — one login serving every exit, the exit a flow
// uses the destination it names.

// socksPort dials the SOCKS service on a serving address.
func socksPort(ip netip.Addr) netip.AddrPort {
	return netip.AddrPortFrom(ip, socks.Port)
}

// servingAddresses maps each node's ISD-AS to its serving address — the
// slice's first, the address the allocator never issues.
func servingAddresses(t *testing.T, a *assemblyNode) map[addr.IA]netip.Addr {
	t.Helper()
	directory, err := a.app.Wireguard().Directory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	serving := make(map[addr.IA]netip.Addr, len(directory.Nodes))
	for _, entry := range directory.Nodes {
		serving[entry.IA] = entry.Overlay.Masked().Addr().Next()
	}
	return serving
}

// internetTCPEcho stands a loopback echo service standing for the internet.
func internetTCPEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
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
	return listener.Addr().(*net.TCPAddr).AddrPort()
}

// internetUDPEcho stands a loopback UDP echo service standing for the
// internet.
func internetUDPEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// socksDial dials the SOCKS service on the serving address from the host,
// retrying while the join completes.
func socksDial(t *testing.T, srv *tsnet.Server, exit netip.Addr) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()
	deadline := time.Now().Add(TestTimeout)
	for {
		conn, err := srv.Dial(ctx, "tcp", socksPort(exit).String())
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("the host's SOCKS dial of %s never connected: %v", exit, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestEgressSocksService is the SOCKS egress proof on the coordination lab:
// a host SOCKS-dials its own node's serving address and the far node's — TCP
// by CONNECT and UDP by association — one host, two exits, the choice the
// destination alone; and a direct dial to an internet destination never
// enters the tunnel, the map carrying the tailnet and nothing else.
func TestEgressSocksService(t *testing.T) {
	t.Parallel()
	// The topology: the core A and the leaf B of the coordination suites,
	// every node offering the service by default.
	wpki := packageWebPKI
	place := placeCoordination(t)
	// The lab takes its own loopback hosts: every node binds the fixed
	// control-endpoint port on its host, so a host shared with another lab
	// is a bind collision whenever the two run concurrently.
	a := coordCore(t, wpki, addrIP(0x57), place, nil)
	b := coordLeaf(t, wpki, addrIP(0x58), a, place, nil)
	t.Cleanup(func() {
		t.Logf("node A counters: %v", a.app.Wireguard().Counters())
		t.Logf("node B counters: %v", b.app.Wireguard().Counters())
	})

	// The mesh stands before any host joins, in both directions.
	Poll(t, "the leaf reaches the core", func() bool {
		return pingFrom(context.Background(), b, a.app.IA(), a.host)
	})
	Poll(t, "the core reaches the leaf", func() bool {
		return pingFrom(context.Background(), a, b.app.IA(), b.host)
	})
	Poll(t, "the core's registry holding B's entry", func() bool {
		return len(servingAddresses(t, a)) == 2
	})

	// The internet the exits reach: loopback echoes beside the tailnet.
	tcpNet := internetTCPEcho(t)
	udpNet := internetUDPEcho(t)

	// One host, one login — the netmap it holds naming every exit.
	host := tailnetHost(t, "host-egress", place.controlURL, "")
	ips := hostUp(t, host)
	if len(ips) != 1 || !ips[0].Is4() || !TailnetRange.Contains(ips[0]) {
		t.Fatalf("the host's addresses = %v, want one of the tailnet range", ips)
	}
	owner := ownerOf(t, a, b, ips[0])
	serving := servingAddresses(t, a)
	near, far := serving[owner], serving[otherIA(t, a, owner)]
	Poll(t, "the owning node's host device programmed", func() bool {
		return len(nodeOf(t, a, b, owner).app.Wireguard().HostPeers()) == 1
	})
	// The host's session with its node begins with the host's own
	// outbound exchange.
	warmSession(t, host, far)

	// The near case: the host's own node serves. TCP by CONNECT.
	nearConn, err := socksclient.Connect(socksDial(t, host, near), tcpNet.String())
	if err != nil {
		t.Fatalf("CONNECT through the host's own node: %v", err)
	}
	defer func() { _ = nearConn.Close() }()
	msg := []byte("through the near exit")
	if _, err := nearConn.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = nearConn.SetReadDeadline(time.Now().Add(TestTimeout))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(nearConn, got); err != nil {
		t.Fatalf("the near exit's echo never returned: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("the near exit echoed %q, want %q", got, msg)
	}

	// UDP by association: the reply names the exit's own address, the
	// datagram relays, and the reply returns with its header rewritten.
	pc, err := host.ListenPacket("udp4", ips[0].String()+":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	relay, err := socksclient.Associate(socksDial(t, host, near), pc)
	if err != nil {
		t.Fatalf("UDP ASSOCIATE through the host's own node: %v", err)
	}
	if relay.Addr.Addr() != near {
		t.Errorf("the reply named %s, want the exit's own %s", relay.Addr.Addr(), near)
	}
	udpMsg := []byte("udp through the near exit")
	if err := relay.WriteTo(udpMsg, udpNet); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetDeadline(time.Now().Add(TestTimeout))
	udpGot := make([]byte, len(udpMsg)+64)
	n, from, err := relay.ReadFrom(udpGot)
	if err != nil {
		t.Fatalf("the near exit's UDP reply never returned: %v", err)
	}
	if string(udpGot[:n]) != string(udpMsg) {
		t.Fatalf("the near exit echoed %q, want %q", udpGot[:n], udpMsg)
	}
	if from != udpNet {
		t.Errorf("the reply's header named %s, want the destination %s", from, udpNet)
	}

	// The far case: the mesh carries the serving address to the other
	// node — the same host, the same login, the destination alone changed.
	farConn, err := socksclient.Connect(socksDial(t, host, far), tcpNet.String())
	if err != nil {
		t.Fatalf("CONNECT through the far node: %v", err)
	}
	defer func() { _ = farConn.Close() }()
	farMsg := []byte("through the far exit")
	if _, err := farConn.Write(farMsg); err != nil {
		t.Fatal(err)
	}
	_ = farConn.SetReadDeadline(time.Now().Add(TestTimeout))
	farGot := make([]byte, len(farMsg))
	if _, err := io.ReadFull(farConn, farGot); err != nil {
		t.Fatalf("the far exit's echo never returned through the mesh: %v", err)
	}
	if string(farGot) != string(farMsg) {
		t.Fatalf("the far exit echoed %q, want %q", farGot, farMsg)
	}

	// The unroutable negative: a destination no slice claims never enters
	// the tunnel — the map carries the tailnet and nothing else, and the
	// client's own dial says so.
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()
	if conn, err := host.Dial(ctx, "tcp", "192.0.2.1:80"); err == nil {
		_ = conn.Close()
		t.Fatal("a direct dial to an internet destination connected, want no route")
	}
}

// otherIA returns the one node of the pair that is not the given one.
func otherIA(t *testing.T, a *assemblyNode, ia addr.IA) addr.IA {
	t.Helper()
	if a.app.IA().Equal(ia) {
		serving := servingAddresses(t, a)
		for other := range serving {
			if !other.Equal(ia) {
				return other
			}
		}
	}
	return a.app.IA()
}

// nodeOf returns the assembly node of the pair holding the ISD-AS.
func nodeOf(t *testing.T, a, b *assemblyNode, ia addr.IA) *assemblyNode {
	t.Helper()
	if a.app.IA().Equal(ia) {
		return a
	}
	return b
}
