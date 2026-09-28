package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
)

// TestPingArgumentsParse checks the ping command's surface: the shared and
// local node arguments parse — the command assembles a local node — and the
// core's issuance arguments are unknown to it.
func TestPingArgumentsParse(t *testing.T) {
	cmd := newPingCommand()
	if err := cmd.Flags().Parse([]string{
		"--domain", "core.example.org",
		"--neighbor", "192.0.2.7:30045",
		"--state", "/var/lib/cion",
	}); err != nil {
		t.Fatalf("parsing the local surface: %v", err)
	}
	if err := cmd.Flags().Parse([]string{"--acme-email", "admin@example.org"}); err == nil {
		t.Error("--acme-email parsed under ping, want the unknown-flag refusal")
	} else if !strings.Contains(err.Error(), "acme-email") {
		t.Errorf("the refusal = %v, want it to name the flag", err)
	}
}

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
