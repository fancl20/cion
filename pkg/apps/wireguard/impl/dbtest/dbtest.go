// Package dbtest holds the application directory store's contract tests,
// shared by every implementation the way the trust DB's are.
package dbtest

import (
	"context"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// TestDirectoryStore runs the contract every directory store keeps: entries
// round-trip beside host entries, a re-publish replaces, and the store reads
// back what it holds.
func TestDirectoryStore(t *testing.T, open func(t *testing.T) wireguard.DirectoryStore) {
	ctx := context.Background()
	store := open(t)
	t.Cleanup(func() { _ = store.Close() })

	entries := []wireguard.Entry{
		{
			IA:           mustIA(t, "20-ff00:0:1"),
			PublicKey:    mustKey(t, 0x01),
			Overlay:      mustPrefix(t, "100.64.1.0/24"),
			HostEndpoint: mustAddrPort(t, "198.51.100.10:51820"),
		},
		{
			IA:        mustIA(t, "20-ff00:0:2"),
			PublicKey: mustKey(t, 0x02),
			Overlay:   mustPrefix(t, "100.64.2.0/24"),
		},
	}
	for _, e := range entries {
		if err := store.Publish(ctx, e); err != nil {
			t.Fatalf("publishing %s: %v", e.IA, err)
		}
	}
	hosts := []wireguard.HostEntry{
		{
			PublicKey: mustKey(t, 0x81),
			Addr:      netip.MustParseAddr("100.64.1.4"),
			IA:        mustIA(t, "20-ff00:0:1"),
			Note:      "telegram operator",
		},
		{
			PublicKey: mustKey(t, 0x82),
			Addr:      netip.MustParseAddr("100.64.2.5"),
			IA:        mustIA(t, "20-ff00:0:2"),
		},
	}
	for _, h := range hosts {
		if err := store.PublishHost(ctx, h); err != nil {
			t.Fatalf("publishing the host %s: %v", h.PublicKey, err)
		}
	}
	want := wireguard.Directory{Nodes: entries, Hosts: hosts}
	got, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got,
		cmpopts.EquateComparable(netip.Addr{}, netip.Prefix{}, netip.AddrPort{},
			wireguard.PublicKey{})); diff != "" {

		t.Errorf("list mismatch (-want +got):\n%s", diff)
	}

	// A re-publish replaces the publisher's entry and no one else's.
	updated := entries[0]
	updated.Overlay = mustPrefix(t, "100.64.9.0/24")
	if err := store.Publish(ctx, updated); err != nil {
		t.Fatalf("re-publishing %s: %v", updated.IA, err)
	}
	// A host's re-registration replaces its own record and no one else's.
	reRegistered := hosts[0]
	reRegistered.Note = "telegram invitation"
	if err := store.PublishHost(ctx, reRegistered); err != nil {
		t.Fatalf("re-publishing the host %s: %v", reRegistered.PublicKey, err)
	}
	got, err = store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Nodes) != 2 || len(got.Hosts) != 2 {
		t.Fatalf("re-publish grew the directory to %d entries and %d hosts",
			len(got.Nodes), len(got.Hosts))
	}
	for _, e := range got.Nodes {
		if e.IA.Equal(entries[0].IA) && e.Overlay.String() != "100.64.9.0/24" {
			t.Errorf("re-publish left the old subnet %s", e.Overlay)
		}
	}
	for _, h := range got.Hosts {
		if h.PublicKey == hosts[0].PublicKey && h.Note != "telegram invitation" {
			t.Errorf("re-registration left the old note %q", h.Note)
		}
	}
}

func mustIA(t *testing.T, s string) addr.IA {
	t.Helper()
	ia, err := addr.ParseIA(s)
	if err != nil {
		t.Fatal(err)
	}
	return ia
}

func mustKey(t *testing.T, fill byte) wireguard.PublicKey {
	t.Helper()
	var key wireguard.PublicKey
	for i := range key {
		key[i] = fill
	}
	return key
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return prefix
}

func mustAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}
