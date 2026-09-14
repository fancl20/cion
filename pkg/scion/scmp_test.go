package scion

import (
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
		Links:        map[uint16]addr.IA{1: addr.MustIAFrom(20, 0xff0000000002)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck

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
