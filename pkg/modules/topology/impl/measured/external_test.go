package measured

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// TestExternalHostPersistsAcrossRestart checks the learned external host's
// persistence: an observation persists on change, a later load returns it —
// a restart republishes it — and the latest observation wins. An address
// that echoes none observes nothing.
func TestExternalHostPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	h := &externalHost{path: externalHostPath(dir)}

	first := netip.MustParseAddr("203.0.113.7")
	if err := h.observe(first); err != nil {
		t.Fatal(err)
	}
	if got := h.host(); got != first {
		t.Errorf("learned host = %v, want %v", got, first)
	}
	loaded, err := loadExternalHost(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != first {
		t.Errorf("persisted host = %v, want %v", loaded, first)
	}

	// The latest observation wins and persists; an invalid one — a reply
	// that echoes no source — observes nothing.
	second := netip.MustParseAddr("198.51.100.9")
	if err := h.observe(second); err != nil {
		t.Fatal(err)
	}
	if err := h.observe(netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	loaded, err = loadExternalHost(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != second {
		t.Errorf("persisted host after the second observation = %v, want %v",
			loaded, second)
	}

	// A malformed persistence fails the load, not silently discards it.
	if err := os.WriteFile(filepath.Join(dir, ExternalHostFile),
		[]byte("not-an-address\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadExternalHost(dir); err == nil {
		t.Error("a malformed external-host file loaded")
	}
}

// TestDomainHostResolvesPublishedAddress checks the founding core's
// published host: its domain's first address of the control host's family —
// a published address the node's sockets do not bind is a misconfiguration —
// the control host itself the fallback when the name fails, and the answer
// memoized so the publication cadence outlives a name's resolution.
func TestDomainHostResolvesPublishedAddress(t *testing.T) {
	lookups := 0
	d := domainHost{
		domain:   "core.example.org",
		fallback: netip.MustParseAddr("10.0.0.7"),
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			lookups++
			return []netip.Addr{
				netip.MustParseAddr("2001:db8::1"), // the wrong family
				netip.MustParseAddr("192.0.2.20"),
				netip.MustParseAddr("198.51.100.3"),
			}, nil
		},
	}
	ctx := context.Background()
	if got := d.resolve(ctx); got != netip.MustParseAddr("192.0.2.20") {
		t.Errorf("resolved host = %v, want the family's first 192.0.2.20", got)
	}
	// The memo holds the answer for the window: the second publication
	// resolves nothing.
	if got := d.resolve(ctx); got != netip.MustParseAddr("192.0.2.20") {
		t.Errorf("memoized host = %v, want the held one", got)
	}
	if lookups != 1 {
		t.Errorf("resolutions = %d, want the memoized one", lookups)
	}

	// A name that fails falls back to the control host, memoized the same.
	d = domainHost{
		domain:   "core.example.org",
		fallback: netip.MustParseAddr("10.0.0.7"),
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("no such name")
		},
	}
	for range 2 {
		if got := d.resolve(ctx); got != netip.MustParseAddr("10.0.0.7") {
			t.Errorf("fallback host = %v, want the control host", got)
		}
	}

	// A name whose answers are all of the wrong family falls back too.
	d = domainHost{
		domain:   "core.example.org",
		fallback: netip.MustParseAddr("10.0.0.7"),
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
		},
	}
	if got := d.resolve(ctx); got != netip.MustParseAddr("10.0.0.7") {
		t.Errorf("wrong-family host = %v, want the control host's", got)
	}
}
