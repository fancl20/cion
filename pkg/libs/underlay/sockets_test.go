package underlay

import (
	"bytes"
	"net"
	"testing"
	"time"
)

const testTimeout = 2 * time.Second

// TestNewUDPConnWildcardFamily checks the kernel socket's family pairing:
// the remote hint names the family, and a wildcard listen host of the other
// family — the wildcard-bound link's recorded local address, whose port
// alone it names — binds the hint family's wildcard at the same port instead
// of failing the bind.
func TestNewUDPConnWildcardFamily(t *testing.T) {
	v4Peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = v4Peer.Close() }()
	c, err := Kernel.NewUDP(&net.UDPAddr{IP: net.IPv6zero},
		v4Peer.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		t.Fatalf("binding for the v4 remote from the v6 wildcard: %v", err)
	}
	defer func() { _ = c.Close() }()
	if local := c.LocalAddr(); local.IP.To4() == nil {
		t.Errorf("the socket's local address = %v, want the v4 wildcard", local)
	}
	out := []byte("v4 from the v6 wildcard")
	v4Addr := v4Peer.LocalAddr().(*net.UDPAddr)
	if _, err := c.WriteToUDP(out, v4Addr); err != nil {
		t.Fatalf("writing to the v4 remote: %v", err)
	}
	_ = v4Peer.SetReadDeadline(time.Now().Add(testTimeout))
	got := make([]byte, len(out))
	n, err := v4Peer.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], out) {
		t.Fatalf("received %q, want %q", got[:n], out)
	}

	v6Peer, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("the host declines the v6 loopback: %v", err)
	}
	defer func() { _ = v6Peer.Close() }()
	c6, err := Kernel.NewUDP(&net.UDPAddr{IP: net.IPv4zero},
		v6Peer.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		t.Fatalf("binding for the v6 remote from the v4 wildcard: %v", err)
	}
	defer func() { _ = c6.Close() }()
	if local := c6.LocalAddr(); local.IP.To4() != nil {
		t.Errorf("the socket's local address = %v, want the v6 wildcard", local)
	}
}
