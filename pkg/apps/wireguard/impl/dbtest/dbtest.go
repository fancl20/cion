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
// round-trip, a re-publish replaces, and the store reads back what it holds.
func TestDirectoryStore(t *testing.T, open func(t *testing.T) wireguard.DirectoryStore) {
	ctx := context.Background()
	store := open(t)
	t.Cleanup(func() { _ = store.Close() })

	entries := []wireguard.Entry{
		{
			IA:        mustIA(t, "20-ff00:0:1"),
			PublicKey: mustKey(t, 0x01),
			Overlay:   mustPrefix(t, "10.64.1.0/24"),
		},
		{
			IA:        mustIA(t, "20-ff00:0:2"),
			PublicKey: mustKey(t, 0x02),
			Overlay:   mustPrefix(t, "10.64.2.0/24"),
		},
	}
	for _, e := range entries {
		if err := store.Publish(ctx, e); err != nil {
			t.Fatalf("publishing %s: %v", e.IA, err)
		}
	}
	got, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(entries, got, cmpopts.EquateComparable(netip.Addr{}, netip.Prefix{}, wireguard.PublicKey{})); diff != "" {
		t.Errorf("list mismatch (-want +got):\n%s", diff)
	}

	// A re-publish replaces the publisher's entry and no one else's.
	updated := entries[0]
	updated.Overlay = mustPrefix(t, "10.64.9.0/24")
	if err := store.Publish(ctx, updated); err != nil {
		t.Fatalf("re-publishing %s: %v", updated.IA, err)
	}
	got, err = store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("re-publish grew the directory to %d entries", len(got))
	}
	for _, e := range got {
		if e.IA.Equal(entries[0].IA) && e.Overlay.String() != "10.64.9.0/24" {
			t.Errorf("re-publish left the old subnet %s", e.Overlay)
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
