package dataplane

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
)

const testTimeout = 2 * time.Second

// scionLikeDatagram returns a datagram with a minimal SCION-like header that
// is good enough for computeProcID dispatch (valid L4 protocol and IPv4
// addresses of the right total length).
func scionLikeDatagram(payload []byte) []byte {
	buf := make([]byte, 36+len(payload))
	buf[4] = byte(slayers.L4UDP)
	buf[9] = 0x00 // dst and src host address types: IPv4 (T4Ip)
	copy(buf[36:], payload)
	return buf
}

// badL4Datagram returns a well-sized datagram with an unsupported L4 protocol.
func badL4Datagram() []byte {
	data := scionLikeDatagram(nil)
	data[4] = 0x99
	return data
}

// newTestPool returns a packet pool of the given size, with all the packets
// allocated and ready for use.
func newTestPool(size, headroom int) PacketPool {
	pool := makePacketPool(size, headroom)
	buffers := make([][bufSize]byte, size)
	packets := make([]Packet, size)
	for i := range size {
		pool.Put(packets[i].init(&buffers[i]))
	}
	return pool
}

func newTestMetrics(t *testing.T, ifID uint16) *InterfaceMetrics {
	t.Helper()
	m, err := NewMetrics()
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	return m.NewInterfaceMetrics(ifID, addr.MustIAFrom(1, 1), addr.MustIAFrom(1, 2))
}

// recvFromQueues returns the first packet received from any of the queues.
func recvFromQueues(t *testing.T, qs []chan *Packet) *Packet {
	t.Helper()
	cases := make([]reflect.SelectCase, len(qs))
	for i, q := range qs {
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(q)}
	}
	timer := time.After(testTimeout)
	cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(timer)})
	chosen, val, _ := reflect.Select(cases)
	if chosen == len(qs) {
		t.Fatal("timed out waiting for packet")
	}
	return val.Interface().(*Packet)
}

// TestExternalLinkSendReceive exercises both directions of an external link
// over the UDP/IP underlay.
func TestExternalLinkSendReceive(t *testing.T) {
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	remoteAddr := remote.LocalAddr().String()

	provider := NewUDPProvider(64, 0, 0)
	link, err := provider.NewExternalLink(
		64, nil, "127.0.0.1:0", remoteAddr, 1, newTestMetrics(t, 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	extLink, ok := link.(*connectedLink)
	if !ok {
		t.Fatalf("unexpected link type: %T", link)
	}

	ctx := context.Background()
	pool := newTestPool(256, 512)
	procQs := []chan *Packet{make(chan *Packet, 4), make(chan *Packet, 4)}
	provider.Start(ctx, pool, procQs)
	defer provider.Stop()

	// Send: a packet queued on the link must arrive at the remote address.
	out := scionLikeDatagram([]byte("hello over external link"))
	pkt := pool.Get()
	pkt.RawPacket = pkt.RawPacket[:len(out)]
	copy(pkt.RawPacket, out)
	if !extLink.Send(pkt) {
		t.Fatal("send queue full")
	}

	remote.SetReadDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
	got := make([]byte, bufSize)
	n, err := remote.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], out) {
		t.Fatalf("received %q, want %q", got[:n], out)
	}

	// Receive: a datagram from the connected remote address must be
	// dispatched to one of the processor queues.
	in := scionLikeDatagram([]byte("hello from remote"))
	var local *net.UDPAddr
	for _, c := range provider.allConnections {
		local = c.conn.conn.LocalAddr().(*net.UDPAddr)
	}
	if _, err := remote.WriteToUDP(in, local); err != nil {
		t.Fatal(err)
	}
	rpkt := recvFromQueues(t, procQs)
	if rpkt.Link.IfID() != 1 {
		t.Fatalf("ingress link IfID = %d, want 1", rpkt.Link.IfID())
	}
	if !bytes.Equal(rpkt.RawPacket, in) {
		t.Fatalf("received %q, want %q", rpkt.RawPacket, in)
	}
}

// TestInternalLinkSendReceive exercises both directions of the internal link
// over the UDP/IP underlay, including address resolution.
func TestInternalLinkSendReceive(t *testing.T) {
	provider := NewUDPProvider(64, 0, 0)
	link, err := provider.NewInternalLink("127.0.0.1:31041", 64, newTestMetrics(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	intLink, ok := link.(*internalLink)
	if !ok {
		t.Fatalf("unexpected link type: %T", link)
	}

	ctx := context.Background()
	pool := newTestPool(256, 512)
	procQs := []chan *Packet{make(chan *Packet, 4), make(chan *Packet, 4)}
	provider.Start(ctx, pool, procQs)
	defer provider.Stop()

	// Receive: a SCION-like datagram from a local host must be dispatched to
	// one of the processor queues with the source address recorded.
	host, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 31041,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	in := scionLikeDatagram([]byte("hello from host"))
	if _, err := host.Write(in); err != nil {
		t.Fatal(err)
	}
	rpkt := recvFromQueues(t, procQs)
	if rpkt.Link.Scope() != Internal {
		t.Fatalf("ingress link scope = %d, want Internal", rpkt.Link.Scope())
	}
	src := (*net.UDPAddr)(rpkt.RemoteAddr)
	if src == nil || !src.AddrPort().Addr().IsLoopback() {
		t.Fatalf("source address = %v, want loopback", src)
	}

	// Resolve and send: a packet destined to a local host must be delivered
	// to that host's underlay address.
	dst, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()

	out := scionLikeDatagram([]byte("hello to host"))
	pkt := pool.Get()
	pkt.RawPacket = pkt.RawPacket[:len(out)]
	copy(pkt.RawPacket, out)
	dstHost := addr.HostIP(netip.MustParseAddr("127.0.0.1"))
	if err := intLink.Resolve(pkt, dstHost, uint16(dst.LocalAddr().(*net.UDPAddr).Port)); err != nil {
		t.Fatal(err)
	}
	if !intLink.Send(pkt) {
		t.Fatal("send queue full")
	}

	dst.SetReadDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
	got := make([]byte, bufSize)
	n, err := dst.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], out) {
		t.Fatalf("received %q, want %q", got[:n], out)
	}
}

// TestInternalLinkResolveSVC checks that SVC destinations resolve to the
// registered service address.
func TestInternalLinkResolveSVC(t *testing.T) {
	provider := NewUDPProvider(64, 0, 0)
	link, err := provider.NewInternalLink("127.0.0.1:0", 64, newTestMetrics(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	intLink := link.(*internalLink)

	svcAddr := netip.MustParseAddrPort("127.0.0.1:30041")
	if err := provider.AddSvc(addr.SvcCS, addr.HostIP(svcAddr.Addr()), svcAddr.Port()); err != nil {
		t.Fatal(err)
	}

	pool := newTestPool(16, 512)
	pkt := pool.Get()
	if err := intLink.Resolve(pkt, addr.HostSVC(addr.SvcCS), 1234); err != nil {
		t.Fatal(err)
	}
	got := (*net.UDPAddr)(pkt.RemoteAddr)
	if got == nil || got.AddrPort() != svcAddr {
		t.Fatalf("resolved address = %v, want %v", got, svcAddr)
	}
}

// TestInternalLinkResolveErrors checks the address validation error paths.
func TestInternalLinkResolveErrors(t *testing.T) {
	provider := NewUDPProvider(64, 0, 0)
	link, err := provider.NewInternalLink("127.0.0.1:0", 64, newTestMetrics(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	intLink := link.(*internalLink)
	pool := newTestPool(16, 512)

	errs := map[string]addr.Host{
		"unregistered SVC": addr.HostSVC(addr.SvcCS),
		"v4-mapped v6":     addr.HostIP(netip.MustParseAddr("::ffff:127.0.0.1")),
		"unspecified":      addr.HostIP(netip.MustParseAddr("0.0.0.0")),
	}
	for name, host := range errs {
		pkt := pool.Get()
		if err := intLink.Resolve(pkt, host, 30041); err == nil {
			t.Errorf("%s: Resolve succeeded, want error", name)
		}
	}
}

func TestComputeProcID(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		ok   bool
	}{
		{"valid", scionLikeDatagram(nil), true},
		{"short", []byte{0, 0, 0, 0}, false},
		{"bad L4", badL4Datagram(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := computeProcID(tc.data, 4, fnv1aOffset32)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && id >= 4 {
				t.Fatalf("id = %d, want < 4", id)
			}
		})
	}
}
