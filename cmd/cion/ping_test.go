package main

import (
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
)

func TestParsePingTarget(t *testing.T) {
	dst, host, err := parsePingTarget("20-ff00:0:2,192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if !dst.Equal(addr.MustIAFrom(20, 0xff0000000002)) {
		t.Errorf("ISD-AS = %v, want 20-ff00:0:2", dst)
	}
	if host != netip.MustParseAddr("192.0.2.10") {
		t.Errorf("host = %v, want 192.0.2.10", host)
	}

	for _, bad := range []string{
		"",
		"20-ff00:0:2",             // no host
		"20-ff00:0:2,",            // empty host
		"not-an-ia,192.0.2.10",    // bad ISD-AS
		"20-ff00:0:2,not-an-host", // bad host
	} {
		if _, _, err := parsePingTarget(bad); err == nil {
			t.Errorf("parsePingTarget(%q) succeeded, want error", bad)
		}
	}
}
