package measured

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/fancl20/cion/pkg/libs/underlay"
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

// TestDomainHostParsesTheLiteral checks the founding core's identity under
// an address: the literal is the host itself, parsed with no lookup, the
// identity being the address it publishes; a name leaves no literal, its
// host the lookup's.
func TestDomainHostParsesTheLiteral(t *testing.T) {
	lookups := 0
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		return nil, errors.New("no such name")
	}
	d := newDomainHost("2001:db8::1", netip.MustParseAddr("10.0.0.7"), lookup)
	if d.literal != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("literal = %v, want the identity's address", d.literal)
	}
	if lookups != 0 {
		t.Errorf("lookups = %d, want none for a value that cannot change", lookups)
	}
	if d := newDomainHost("core.example.org", netip.MustParseAddr("10.0.0.7"), lookup); d.literal.IsValid() {
		t.Errorf("a name's literal = %v, want none", d.literal)
	}
}

// TestDomainHostLooksUpPublishedAddress checks the founding core's lookup:
// its domain's first address of the bind host's family — a published address
// the node's sockets do not bind is a misconfiguration — and no answer from
// a failed lookup or one whose addresses are all of the wrong family.
func TestDomainHostLooksUpPublishedAddress(t *testing.T) {
	lookingUp := func(addrs []netip.Addr, err error) domainHost {
		return domainHost{
			domain: "core.example.org",
			bind:   netip.MustParseAddr("10.0.0.7"),
			lookup: func(context.Context, string, string) ([]netip.Addr, error) {
				return addrs, err
			},
		}
	}
	ctx := context.Background()
	d := lookingUp([]netip.Addr{
		netip.MustParseAddr("2001:db8::1"), // the wrong family
		netip.MustParseAddr("192.0.2.20"),
		netip.MustParseAddr("198.51.100.3"),
	}, nil)
	if got, ok := d.lookupAddr(ctx); !ok || got != netip.MustParseAddr("192.0.2.20") {
		t.Errorf("looked up %v (%v), want the family's first 192.0.2.20", got, ok)
	}
	failing := lookingUp(nil, errors.New("no such name"))
	if got, ok := failing.lookupAddr(ctx); ok {
		t.Errorf("a failed lookup answered %v", got)
	}
	wrongFamily := lookingUp([]netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil)
	if got, ok := wrongFamily.lookupAddr(ctx); ok {
		t.Errorf("a lookup of the wrong family answered %v", got)
	}
}

// TestHoldsTheNodesOwnHost checks the published host's check: a host a
// socket binds is the node's own; one the kernel refuses with EADDRNOTAVAIL
// is not — documentation space no interface holds stands for a
// NAT's — and any other refusal is an error.
func TestHoldsTheNodesOwnHost(t *testing.T) {
	if own, err := holds(underlay.Kernel, netip.MustParseAddr("127.0.0.1")); err != nil || !own {
		t.Errorf("holds(127.0.0.1) = %v, %v, want held", own, err)
	}
	if own, err := holds(underlay.Kernel, netip.MustParseAddr("192.0.2.1")); err != nil || own {
		t.Errorf("holds(192.0.2.1) = %v, %v, want not held", own, err)
	}
	refusing := underlay.Sockets{
		ListenUDP: func(*net.UDPAddr, netip.AddrPort) (underlay.UDPConn, error) {
			return nil, os.NewSyscallError("bind", syscall.EMFILE)
		},
	}
	if _, err := holds(refusing, netip.MustParseAddr("127.0.0.1")); !errors.Is(err, syscall.EMFILE) {
		t.Errorf("holds under another refusal = %v, want the refusal", err)
	}
}
