package scion

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"

	"github.com/fancl20/cion/pkg/dataplane"
)

// TestEchoWireRoundTrip checks the echo encoding the socket produces and
// parses: type, identifier, sequence, and payload survive, and the request's
// identifier is the sending socket's port, so the data plane delivers the
// reply back to it.
func TestEchoWireRoundTrip(t *testing.T) {
	conn, err := NewConn(ConnConfig{
		IA:           addr.MustIAFrom(20, 0xff0000000001),
		Bind:         "127.0.0.1:0",
		InternalAddr: "127.0.0.1:30041",
		MACKey:       testMACKeyBytes,
		Links:        func() map[uint16]addr.IA { return map[uint16]addr.IA{1: addr.MustIAFrom(20, 0xff0000000002)} },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	peerAddr := &Addr{
		IA:   addr.MustIAFrom(20, 0xff0000000002),
		Addr: conn.LocalAddr().(*Addr).Addr,
	}
	request, err := conn.writePacket(peerAddr, slayers.L4SCMP, func(scn *slayers.SCION) ([]byte, error) {
		return serializeEcho(scn, slayers.SCMPTypeEchoRequest, conn.LocalPort(), 7, []byte("ping"))
	})
	if err != nil {
		t.Fatal(err)
	}
	echo, _, err := parseEchoPacket(request)
	if err != nil {
		t.Fatal(err)
	}
	if echo.Reply {
		t.Error("parsed a request as a reply")
	}
	if echo.Identifier != conn.LocalPort() {
		t.Errorf("request identifier = %d, want the socket's port %d",
			echo.Identifier, conn.LocalPort())
	}
	if echo.Seq != 7 {
		t.Errorf("sequence = %d, want 7", echo.Seq)
	}
	if string(echo.Payload) != "ping" {
		t.Errorf("payload = %q, want %q", echo.Payload, "ping")
	}

	reply, err := conn.writePacket(peerAddr, slayers.L4SCMP, func(scn *slayers.SCION) ([]byte, error) {
		return serializeEcho(scn, slayers.SCMPTypeEchoReply, echo.Identifier, echo.Seq, echo.Payload)
	})
	if err != nil {
		t.Fatal(err)
	}
	echo, _, err = parseEchoPacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	if !echo.Reply {
		t.Error("parsed a reply as a request")
	}
	if echo.Identifier != conn.LocalPort() || echo.Seq != 7 {
		t.Errorf("reply identifier/sequence = %d/%d, want %d/7",
			echo.Identifier, echo.Seq, conn.LocalPort())
	}
}

// TestEchoExchange checks a request-reply exchange between two nodes: the
// request rides a one-hop path, the reply rides the reversed arrival path,
// and the reply's identifier is the pinger's port.
func TestEchoExchange(t *testing.T) {
	iaA := addr.MustIAFrom(20, 0xff0000000001)
	iaB := addr.MustIAFrom(20, 0xff0000000002)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	a := startTestNode(t, iaA, iaB, extA, extB)
	b := startTestNode(t, iaB, iaA, extB, extA)

	// The pinger binds an ephemeral port — it becomes the echo identifier;
	// the responder binds the endhost port, where the data plane delivers
	// echo requests.
	connA := a.newConn(t, 0)
	connB := b.newConn(t, dataplane.EndhostPort)

	peerB := &Addr{IA: iaB, Addr: connB.LocalAddr().(*Addr).Addr}
	if err := connA.WriteEchoRequestTo(peerB, 1, []byte("probe")); err != nil {
		t.Fatal(err)
	}
	if err := connB.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	echo, from, err := connB.ReadEchoFrom()
	if err != nil {
		t.Fatal(err)
	}
	if echo.Reply {
		t.Fatal("responder received a reply, want a request")
	}
	if echo.Identifier != connA.LocalPort() {
		t.Errorf("request identifier = %d, want the pinger's port %d",
			echo.Identifier, connA.LocalPort())
	}
	if !from.IA.Equal(iaA) {
		t.Errorf("request source IA = %v, want %v", from.IA, iaA)
	}

	// The responder answers on the arrival address; the reply returns to the
	// pinger's socket by its identifier.
	if err := connB.WriteEchoReplyTo(from, echo.Identifier, echo.Seq, echo.Payload); err != nil {
		t.Fatal(err)
	}
	if err := connA.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	echo, from, err = connA.ReadEchoFrom()
	if err != nil {
		t.Fatal(err)
	}
	if !echo.Reply {
		t.Fatal("pinger received a request, want a reply")
	}
	if !from.IA.Equal(iaB) {
		t.Errorf("reply source IA = %v, want %v", from.IA, iaB)
	}
	if echo.Identifier != connA.LocalPort() || echo.Seq != 1 {
		t.Errorf("reply identifier/sequence = %d/%d, want %d/1",
			echo.Identifier, echo.Seq, connA.LocalPort())
	}
	if string(echo.Payload) != "probe" {
		t.Errorf("reply payload = %q, want %q", echo.Payload, "probe")
	}
}

// TestReadEchoReply checks the requester's read: the reply to its own
// request returns past every other echo message, and an interface-down
// signal quoting that request fails the read with an EchoLostError, past
// the signals quoting another socket's request or an earlier one. Each
// signal names its own interface, telling which one ended the read.
func TestReadEchoReply(t *testing.T) {
	router, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(testHost, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = router.Close() }()
	newConn := func(ia, peer addr.IA) *Conn {
		t.Helper()
		conn, err := NewConn(ConnConfig{
			IA:           ia,
			Bind:         netip.AddrPortFrom(testHost, 0).String(),
			InternalAddr: router.LocalAddr().String(),
			MACKey:       testMACKeyBytes,
			Links:        func() map[uint16]addr.IA { return map[uint16]addr.IA{testIfID: peer} },
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	conn := newConn(iaLeaf, iaMid)
	// The peer only serializes the echoes the router delivers to conn.
	peer := newConn(iaMid, iaLeaf)
	local := conn.LocalAddr().(*Addr).Addr
	own := conn.LocalPort()

	echo := func(typ slayers.SCMPType, id, seq uint16) []byte {
		t.Helper()
		raw, err := peer.writePacket(&Addr{IA: iaLeaf, Addr: local}, slayers.L4SCMP,
			func(scn *slayers.SCION) ([]byte, error) {
				return serializeEcho(scn, typ, id, seq, []byte("probe"))
			})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	refusal := func(ifID, id, seq uint16) []byte {
		return interfaceDownPacket(t, iaMid, iaLeaf, iaMid, ifID,
			echoPacket(t, iaLeaf, iaMid, slayers.SCMPTypeEchoRequest, id, seq))
	}
	deliver := func(packets ...[]byte) {
		t.Helper()
		for _, raw := range packets {
			if _, err := router.WriteToUDP(raw, net.UDPAddrFromAddrPort(local)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// The read for request 7 passes every other message and fails on its
	// own refusal.
	deliver(
		echo(slayers.SCMPTypeEchoReply, own, 6),   // an earlier request's reply
		echo(slayers.SCMPTypeEchoReply, own+1, 7), // another socket's reply
		echo(slayers.SCMPTypeEchoRequest, own, 7), // a request, not a reply
		refusal(3, own+1, 7),                      // another socket's request
		refusal(2, own, 6),                        // an earlier request
		refusal(testIfID, own, 7),
	)
	_, _, err = conn.ReadEchoReply(7)
	var lost *EchoLostError
	if !errors.As(err, &lost) {
		t.Fatalf("ReadEchoReply(7) = %v, want an EchoLostError", err)
	}
	if lost.Seq != 7 || !lost.Signal.IA.Equal(iaMid) || lost.Signal.IfID != testIfID {
		t.Errorf("lost request %d at %v/%d, want 7 at %v/%d",
			lost.Seq, lost.Signal.IA, lost.Signal.IfID, iaMid, testIfID)
	}

	// The read for request 8 returns its reply past a late refusal of 7.
	deliver(refusal(testIfID, own, 7), echo(slayers.SCMPTypeEchoReply, own, 8))
	reply, from, err := conn.ReadEchoReply(8)
	if err != nil {
		t.Fatalf("ReadEchoReply(8) = %v, want the reply", err)
	}
	if !reply.Reply || reply.Identifier != own || reply.Seq != 8 || string(reply.Payload) != "probe" {
		t.Errorf("reply = %+v, want the reply to %d/8", reply, own)
	}
	if !from.IA.Equal(iaMid) {
		t.Errorf("reply source = %v, want %v", from.IA, iaMid)
	}
}
