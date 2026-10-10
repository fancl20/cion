package services

import (
	"context"
	"net"
	"testing"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/scion"
)

// TestResponderReleasesOnCancel checks the responder's stop: once its
// context ends, Run returns nil with its socket closed and released, and
// the address binds again at once.
func TestResponderReleasesOnCancel(t *testing.T) {
	conn, err := scion.NewConn(scion.ConnConfig{
		IA:           addr.MustIAFrom(1, 0xff0000000110),
		Bind:         "127.0.0.1:0",
		InternalAddr: "127.0.0.1:9",
		MACKey:       make([]byte, 16),
	})
	if err != nil {
		t.Fatal(err)
	}
	bound := conn.LocalAddr().(*scion.Addr).Addr
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	go func() { returned <- (&responder{conn: conn}).Run(ctx) }()
	cancel()
	if err := <-returned; err != nil {
		t.Fatalf("Run = %v, want nil once its context ended", err)
	}
	rebound, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(bound))
	if err != nil {
		t.Fatalf("the responder's address did not bind again: %v", err)
	}
	_ = rebound.Close()
}
