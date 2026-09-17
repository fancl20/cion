package scion

import (
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
)

// TestConnZeroLinkStart checks the library's zero-link start (proposal
// 0008): a connection without a link table builds — a node may start before
// any link exists — and resolves no one-hop egress through a nil source.
func TestConnZeroLinkStart(t *testing.T) {
	conn, err := NewConn(ConnConfig{
		IA:           addr.MustIAFrom(20, 0xfd0000000001),
		Bind:         netip.MustParseAddrPort("127.0.0.1:0").String(),
		InternalAddr: netip.MustParseAddrPort("127.0.0.1:0").String(),
		MACKey:       []byte("0123456789abcdef"),
	})
	if err != nil {
		t.Fatalf("a zero-link conn failed to build: %v", err)
	}
	defer func() { _ = conn.Close() }()

	neighbor := addr.MustIAFrom(20, 0xfd0000000002)
	if _, err := conn.resolveLink(neighbor); err == nil {
		t.Error("a nil link source resolved an egress interface")
	}
}
