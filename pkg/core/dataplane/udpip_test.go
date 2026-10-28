package dataplane

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"

	"github.com/fancl20/cion/pkg/libs/underlay"
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
	defer func() { _ = remote.Close() }()
	remoteAddr := remote.LocalAddr().String()

	provider := NewUDPProvider(64, 0, 0, underlay.Kernel, nil)
	link, err := provider.NewExternalLink(
		64, nil, nil, "127.0.0.1:0", remoteAddr, 1, newTestMetrics(t, 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	extLink, ok := link.(*externalLink)
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

	_ = remote.SetReadDeadline(time.Now().Add(testTimeout))
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
		local = c.conn.LocalAddr()
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
	provider := NewUDPProvider(64, 0, 0, underlay.Kernel, nil)
	internal := freeUDPAddr(t)
	link, err := provider.NewInternalLink(internal, 64, newTestMetrics(t, 0))
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
	host, err := net.DialUDP("udp4", nil, mustUDPAddr(t, internal))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()

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
	defer func() { _ = dst.Close() }()

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

	_ = dst.SetReadDeadline(time.Now().Add(testTimeout))
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
	provider := NewUDPProvider(64, 0, 0, underlay.Kernel, nil)
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
	provider := NewUDPProvider(64, 0, 0, underlay.Kernel, nil)
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

// newPeerSocket binds a loopback UDP socket the test reads a link's sends
// at.
func newPeerSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// onehopDatagram returns a datagram whose SCION-like header carries the
// one-hop path type — the mark of the node's own conversation with the peer,
// the traffic an external link's answer tier carries.
func onehopDatagram(payload []byte) []byte {
	buf := scionLikeDatagram(payload)
	buf[8] = byte(onehop.PathType)
	return buf
}

// TestExternalLinkReaimAndObserved checks the unconnected link's live state:
// an arrival from a source the recorded locator does not name is processed
// all the same and records itself as the link's last observed source — the
// new answer the control plane reads, reported once per move — while the
// locator it names moves nothing; the link's own conversation answers that
// source — the one-hop send and the raw write alike — while transit keeps
// the recorded locator; a re-aim then changes transit's destination without
// rebuilding anything, and the answers follow only an arrival from the new
// locator itself.
func TestExternalLinkReaimAndObserved(t *testing.T) {
	aimed := newPeerSocket(t)
	moved := newPeerSocket(t)
	stranger := newPeerSocket(t)

	var moves atomic.Int32
	provider := NewUDPProvider(64, 0, 0, underlay.Kernel, func() { moves.Add(1) })
	observed := new(Observation)
	link, err := provider.NewExternalLink(
		64, nil, observed, "127.0.0.1:0", aimed.LocalAddr().String(), 3, newTestMetrics(t, 3),
	)
	if err != nil {
		t.Fatal(err)
	}
	el := link.(*externalLink)

	ctx := context.Background()
	pool := newTestPool(256, 512)
	procQs := []chan *Packet{make(chan *Packet, 4)}
	provider.Start(ctx, pool, procQs)
	defer provider.Stop()

	// An arrival from a source the entry does not name: dispatched — the
	// source filter is the discriminator's, above this layer — and recorded
	// as the link's last observed source, moving no locator.
	in := scionLikeDatagram([]byte("from a stranger"))
	if _, err := stranger.WriteToUDP(in, el.raw.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	rpkt := recvFromQueues(t, procQs)
	if rpkt.Link.IfID() != 3 || !bytes.Equal(rpkt.RawPacket, in) {
		t.Fatalf("arrival from the stranger dispatched as %d/%q", rpkt.Link.IfID(), rpkt.RawPacket)
	}
	if got := observed.Load(); got != stranger.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Errorf("observed source = %v, want the stranger's %v", got, stranger.LocalAddr())
	}
	// A second arrival from the same source moves nothing and reports
	// nothing.
	if _, err := stranger.WriteToUDP(in, el.raw.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	recvFromQueues(t, procQs)
	if got := moves.Load(); got != 1 {
		t.Errorf("observation moves reported = %d, want 1", got)
	}

	// The locator the arrival named moved nothing: a transit send still
	// lands at the recorded address.
	out := scionLikeDatagram([]byte("still aimed"))
	pkt := pool.Get()
	pkt.RawPacket = pkt.RawPacket[:len(out)]
	copy(pkt.RawPacket, out)
	if !el.Send(pkt) {
		t.Fatal("send queue full")
	}
	// The link's own conversation answers the arrival's source instead: the
	// one-hop send and the session's raw write both land at the stranger.
	_ = aimed.SetReadDeadline(time.Now().Add(testTimeout))
	got := make([]byte, bufSize)
	n, err := aimed.Read(got)
	if err != nil {
		t.Fatalf("the pre-re-aim transit did not arrive at the recorded address: %v", err)
	}
	if !bytes.Equal(got[:n], out) {
		t.Fatalf("received %q, want %q", got[:n], out)
	}
	answer := onehopDatagram([]byte("the answer"))
	pkt2 := pool.Get()
	pkt2.RawPacket = pkt2.RawPacket[:len(answer)]
	copy(pkt2.RawPacket, answer)
	if !el.Send(pkt2) {
		t.Fatal("send queue full")
	}
	if err := el.WriteRaw(answer); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		_ = stranger.SetReadDeadline(time.Now().Add(testTimeout))
		n, err := stranger.Read(got)
		if err != nil {
			t.Fatalf("an answer did not arrive at the observed source: %v", err)
		}
		if !bytes.Equal(got[:n], answer) {
			t.Fatalf("received %q, want %q", got[:n], answer)
		}
	}

	// The re-aim: one field, no rebuild. Transit follows the new locator at
	// once; the answers keep paying the observation back until the new
	// locator's own arrival names it.
	provider.Aim(3, moved.LocalAddr().(*net.UDPAddr).AddrPort())
	pkt3 := pool.Get()
	pkt3.RawPacket = pkt3.RawPacket[:len(out)]
	copy(pkt3.RawPacket, out)
	if !el.Send(pkt3) {
		t.Fatal("send queue full")
	}
	_ = moved.SetReadDeadline(time.Now().Add(testTimeout))
	n, err = moved.Read(got)
	if err != nil {
		t.Fatalf("the post-re-aim transit did not arrive at the new locator: %v", err)
	}
	if !bytes.Equal(got[:n], out) {
		t.Fatalf("received %q, want %q", got[:n], out)
	}
	if err := el.WriteRaw(answer); err != nil {
		t.Fatal(err)
	}
	_ = stranger.SetReadDeadline(time.Now().Add(testTimeout))
	if n, err := stranger.Read(got); err != nil || !bytes.Equal(got[:n], answer) {
		t.Fatalf("the raw write followed the re-aim: %v", err)
	}
	if _, err := moved.WriteToUDP(in, el.raw.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if rpkt := recvFromQueues(t, procQs); rpkt.Link.IfID() != 3 {
		t.Fatalf("the new locator's arrival dispatched as %d", rpkt.Link.IfID())
	}
	if got := moves.Load(); got != 2 {
		t.Errorf("observation moves reported = %d, want 2", got)
	}
	if err := el.WriteRaw(answer); err != nil {
		t.Fatal(err)
	}
	_ = moved.SetReadDeadline(time.Now().Add(testTimeout))
	if n, err := moved.Read(got); err != nil || !bytes.Equal(got[:n], answer) {
		t.Fatalf("the raw write did not follow the new locator's arrival: %v", err)
	}
}

// TestExternalLinkContinuesItsObservation checks an observation record's
// continuation across providers, as across generations: a link built on the
// local address and the record a stopped link filled answers at the
// observed source before any arrival of its own, and an arrival from that
// source moves nothing and reports nothing.
func TestExternalLinkContinuesItsObservation(t *testing.T) {
	aimed := newPeerSocket(t)
	moved := newPeerSocket(t)
	movedAddr := moved.LocalAddr().(*net.UDPAddr).AddrPort()
	observed := new(Observation)
	ctx := context.Background()
	pool := newTestPool(256, 512)
	procQs := []chan *Packet{make(chan *Packet, 4)}
	in := scionLikeDatagram([]byte("from the moved peer"))

	first := NewUDPProvider(64, 0, 0, underlay.Kernel, nil)
	link, err := first.NewExternalLink(
		64, nil, observed, "127.0.0.1:0", aimed.LocalAddr().String(), 3, newTestMetrics(t, 3),
	)
	if err != nil {
		t.Fatal(err)
	}
	local := link.(*externalLink).raw.LocalAddr()
	first.Start(ctx, pool, procQs)
	if _, err := moved.WriteToUDP(in, local); err != nil {
		t.Fatal(err)
	}
	recvFromQueues(t, procQs)
	first.Stop()
	if got := observed.Load(); got != movedAddr {
		t.Fatalf("the first link observed %v, want the moved peer's %v", got, movedAddr)
	}

	var moves atomic.Int32
	second := NewUDPProvider(64, 0, 0, underlay.Kernel, func() { moves.Add(1) })
	link, err = second.NewExternalLink(
		64, nil, observed, local.String(), aimed.LocalAddr().String(), 3, newTestMetrics(t, 3),
	)
	if err != nil {
		t.Fatal(err)
	}
	el := link.(*externalLink)
	second.Start(ctx, pool, procQs)
	defer second.Stop()

	// Before any arrival of its own, the link answers at the observation.
	answer := onehopDatagram([]byte("the answer"))
	if err := el.WriteRaw(answer); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, bufSize)
	_ = moved.SetReadDeadline(time.Now().Add(testTimeout))
	if n, err := moved.Read(got); err != nil || !bytes.Equal(got[:n], answer) {
		t.Fatalf("the continued link's answer did not arrive at the observation: %v", err)
	}
	if _, err := moved.WriteToUDP(in, local); err != nil {
		t.Fatal(err)
	}
	recvFromQueues(t, procQs)
	if got := moves.Load(); got != 0 {
		t.Errorf("observation moves reported = %d, want none", got)
	}
}

// TestExternalLinksShareLocator checks that two links whose locators
// coincide both build: the socket table keys on the interface, the remote
// address having stopped naming the link.
func TestExternalLinksShareLocator(t *testing.T) {
	shared := newPeerSocket(t)
	provider := NewUDPProvider(64, 0, 0, underlay.Kernel, nil)
	for _, ifID := range []uint16{1, 2} {
		if _, err := provider.NewExternalLink(
			64, nil, nil, "127.0.0.1:0", shared.LocalAddr().String(), ifID,
			newTestMetrics(t, ifID),
		); err != nil {
			t.Fatalf("the second link at one locator did not build: %v", err)
		}
	}
	if provider.NumConnections() != 2 {
		t.Errorf("connections = %d, want the two links'", provider.NumConnections())
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
