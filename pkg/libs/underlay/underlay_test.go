package underlay

import (
	"net"
	"net/netip"
	"testing"
)

// TestResolveAddrPort checks the resolver's two rules: an IPv4 address in the
// v4-mapped IPv6 form resolves to plain IPv4, and an empty host, which names
// no address, is refused.
func TestResolveAddrPort(t *testing.T) {
	got, err := ResolveAddrPort("[::ffff:192.0.2.1]:30041")
	if err != nil {
		t.Fatalf("ResolveAddrPort: %v", err)
	}
	if want := netip.MustParseAddrPort("192.0.2.1:30041"); got != want {
		t.Errorf("ResolveAddrPort = %v, want %v", got, want)
	}
	if ap, err := ResolveAddrPort(":30041"); err == nil {
		t.Errorf("ResolveAddrPort(%q) = %v, want an error", ":30041", ap)
	}
}

// TestResolveAddrPortDefault checks the defaulting resolver: a form without
// a port names the default port — an IPv6 host bracketed on the way — and a
// form whose spelled port cannot parse fails as spelled.
func TestResolveAddrPortDefault(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want netip.AddrPort
	}{
		{"host with port", "192.0.2.1:30041", netip.MustParseAddrPort("192.0.2.1:30041")},
		{"bare IPv4 host", "192.0.2.1", netip.MustParseAddrPort("192.0.2.1:30044")},
		{"bare IPv6 host", "fd00::1", netip.MustParseAddrPort("[fd00::1]:30044")},
	}
	for _, tc := range cases {
		got, err := ResolveAddrPortDefault(tc.in, 30044)
		if err != nil {
			t.Errorf("%s: ResolveAddrPortDefault(%q): %v", tc.name, tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: ResolveAddrPortDefault(%q) = %v, want %v", tc.name, tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"192.0.2.1:99999"} {
		if ap, err := ResolveAddrPortDefault(bad, 30044); err == nil {
			t.Errorf("ResolveAddrPortDefault(%q) = %v, want an error", bad, ap)
		}
	}
}

// TestResolveLocalAddr checks the local resolver: an empty host resolves to
// any address on the port, and a v4-mapped address to the four-byte IPv4 form.
func TestResolveLocalAddr(t *testing.T) {
	wildcard, err := ResolveLocalAddr(":30041")
	if err != nil {
		t.Fatalf("ResolveLocalAddr(%q): %v", ":30041", err)
	}
	if wildcard.IP != nil || wildcard.Port != 30041 {
		t.Errorf("ResolveLocalAddr(%q) = %v, want any address on port 30041", ":30041", wildcard)
	}
	mapped, err := ResolveLocalAddr("[::ffff:192.0.2.1]:30041")
	if err != nil {
		t.Fatalf("ResolveLocalAddr: %v", err)
	}
	if len(mapped.IP) != net.IPv4len || !mapped.IP.Equal(net.IPv4(192, 0, 2, 1)) {
		t.Errorf("ResolveLocalAddr IP = %#v, want the four-byte 192.0.2.1", mapped.IP)
	}
}
