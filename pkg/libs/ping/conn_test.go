package ping

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/scion"
)

// testHost is the package's own loopback host, which no other package's
// tests bind.
var testHost = netip.MustParseAddr("127.0.0.134")

var (
	iaA = addr.MustIAFrom(1, 0xff0000000001)
	iaB = addr.MustIAFrom(1, 0xff0000000002)
)

// newTestConn binds a SCION conn of ia on the test host whose packets go to
// internal, as to its node's router.
func newTestConn(t *testing.T, ia addr.IA, internal netip.AddrPort) *scion.Conn {
	t.Helper()
	conn, err := scion.NewConn(scion.ConnConfig{
		IA:           ia,
		Bind:         netip.AddrPortFrom(testHost, 0).String(),
		InternalAddr: internal.String(),
		MACKey:       make([]byte, 16),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// bound returns the conn's bound address.
func bound(conn *scion.Conn) netip.AddrPort {
	return conn.LocalAddr().(*scion.Addr).Addr
}

// TestConnSendsOverTheLink checks that a request sent over a link leaves as
// an echo request under the conn's own port and the sequence number.
func TestConnSendsOverTheLink(t *testing.T) {
	router := newTestConn(t, iaB, netip.AddrPortFrom(testHost, 9))
	c := NewConn(newTestConn(t, iaA, bound(router)))
	if err := c.SendOver(iaB, testHost, 1, 7); err != nil {
		t.Fatal(err)
	}
	if err := router.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	echo, from, err := router.ReadEchoFrom()
	if err != nil {
		t.Fatal(err)
	}
	if echo.Reply || echo.Identifier != c.conn.LocalPort() || echo.Seq != 7 || !from.IA.Equal(iaA) {
		t.Errorf("sent %+v from %v, want request 7 under port %d from %v",
			echo, from.IA, c.conn.LocalPort(), iaA)
	}
}

// TestConnReadsItsOwnReplies checks that the replies to the conn's own
// requests are delivered, past the replies to another socket's and the
// requests, and that the read returns nil once its context ends.
func TestConnReadsItsOwnReplies(t *testing.T) {
	conn := newTestConn(t, iaA, netip.AddrPortFrom(testHost, 9))
	peer := newTestConn(t, iaB, bound(conn))
	c := NewConn(conn)
	ctx, cancel := context.WithCancel(t.Context())
	returned := make(chan error, 1)
	go func() { returned <- c.ReadReplies(ctx) }()

	to := &scion.Addr{IA: iaA, Addr: bound(conn), IfID: 1}
	own := conn.LocalPort()
	for _, send := range []func() error{
		func() error { return peer.WriteEchoReplyTo(to, own, 7, nil) },
		func() error { return peer.WriteEchoReplyTo(to, own+1, 8, nil) },
		func() error { return peer.WriteEchoRequestTo(to, 9, nil) },
		func() error { return peer.WriteEchoReplyTo(to, own, 10, nil) },
	} {
		if err := send(); err != nil {
			t.Fatal(err)
		}
	}
	var got []uint16
	for range 2 {
		select {
		case r := <-c.Replies():
			got = append(got, r.Seq)
		case <-time.After(5 * time.Second):
			t.Fatalf("replies delivered %v, want 7 and 10", got)
		}
	}
	if diff := cmp.Diff([]uint16{7, 10}, got); diff != "" {
		t.Errorf("replies delivered (-want +got):\n%s", diff)
	}
	cancel()
	if err := <-returned; err != nil {
		t.Errorf("ReadReplies = %v, want nil once its context ended", err)
	}
}
