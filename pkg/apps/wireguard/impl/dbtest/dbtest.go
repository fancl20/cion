// Package dbtest holds the application directory store's contract tests,
// shared by every implementation the way the trust DB's are.
package dbtest

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// MemStore is the in-memory directory-store double the suites share: publish
// assigns slices the store's way, host entries record keyed by their public
// key, and Seed records a node entry verbatim — the fixture form that names
// its own slice.
type MemStore struct {
	mtx   sync.Mutex
	nodes []wireguard.Entry
	hosts []wireguard.HostEntry
}

// Publish records the entry, keyed by its ISD-AS, assigning its slice the
// store's way.
func (s *MemStore) Publish(_ context.Context, entry wireguard.Entry) (wireguard.Entry, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	overlay, err := wireguard.AssignSlice(entry.IA, s.nodes)
	if err != nil {
		return wireguard.Entry{}, err
	}
	entry.Overlay = overlay
	for i := range s.nodes {
		if s.nodes[i].IA.Equal(entry.IA) {
			s.nodes[i] = entry
			return entry, nil
		}
	}
	s.nodes = append(s.nodes, entry)
	return entry, nil
}

// Seed records a node entry verbatim, no assignment run.
func (s *MemStore) Seed(entry wireguard.Entry) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	for i := range s.nodes {
		if s.nodes[i].IA.Equal(entry.IA) {
			s.nodes[i] = entry
			return
		}
	}
	s.nodes = append(s.nodes, entry)
}

// PublishHost records the host entry, keyed by its public key.
func (s *MemStore) PublishHost(_ context.Context, entry wireguard.HostEntry) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	for i := range s.hosts {
		if s.hosts[i].PublicKey == entry.PublicKey {
			s.hosts[i] = entry
			return nil
		}
	}
	s.hosts = append(s.hosts, entry)
	return nil
}

// List returns a snapshot of everything recorded.
func (s *MemStore) List(context.Context) (wireguard.Directory, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return wireguard.Directory{
		Nodes: append([]wireguard.Entry(nil), s.nodes...),
		Hosts: append([]wireguard.HostEntry(nil), s.hosts...),
	}, nil
}

// Close retires nothing; the double holds no resource.
func (s *MemStore) Close() error { return nil }

// MustKey returns the public key whose every byte is fill — the suites'
// stand-in for a real one.
func MustKey(fill byte) wireguard.PublicKey {
	var key wireguard.PublicKey
	for i := range key {
		key[i] = fill
	}
	return key
}

// TestDirectoryStore runs the contract every directory store keeps: the
// store assigns each publisher the first free /24 of the tailnet range by
// address order — unique across publishers, stable per ISD-AS across
// re-publications, the claimed overlay ignored — beside host entries that
// round-trip and a re-registration that replaces.
func TestDirectoryStore(t *testing.T, open func(t *testing.T) wireguard.DirectoryStore) {
	ctx := context.Background()
	store := open(t)
	t.Cleanup(func() { _ = store.Close() })

	// The claims carry overlays the assignment must ignore; the answers
	// place each publisher's slice in address order instead.
	entries := []wireguard.Entry{
		{
			IA:           mustIA(t, "20-ff00:0:1"),
			PublicKey:    MustKey(0x01),
			Overlay:      mustPrefix(t, "100.64.200.0/24"),
			HostEndpoint: mustAddrPort(t, "198.51.100.10:51820"),
		},
		{
			IA:        mustIA(t, "20-ff00:0:2"),
			PublicKey: MustKey(0x02),
			Overlay:   mustPrefix(t, "100.64.200.0/24"),
		},
	}
	assigned := []wireguard.Entry{entries[0], entries[1]}
	assigned[0].Overlay = mustPrefix(t, "100.64.0.0/24")
	assigned[1].Overlay = mustPrefix(t, "100.64.1.0/24")
	for _, e := range entries {
		recorded, err := store.Publish(ctx, e)
		if err != nil {
			t.Fatalf("publishing %s: %v", e.IA, err)
		}
		if recorded.Overlay != assigned[0].Overlay && recorded.Overlay != assigned[1].Overlay {
			t.Errorf("publishing %s answered %s, want one of %s, %s",
				e.IA, recorded.Overlay, assigned[0].Overlay, assigned[1].Overlay)
		}
	}
	hosts := []wireguard.HostEntry{
		{
			PublicKey:  MustKey(0x81),
			MachineKey: MustKey(0x91),
			Addr:       netip.MustParseAddr("100.64.0.4"),
			IA:         mustIA(t, "20-ff00:0:1"),
			Note:       "telegram operator",
		},
		{
			PublicKey:  MustKey(0x82),
			MachineKey: MustKey(0x92),
			Addr:       netip.MustParseAddr("100.64.1.5"),
			IA:         mustIA(t, "20-ff00:0:2"),
		},
	}
	for _, h := range hosts {
		if err := store.PublishHost(ctx, h); err != nil {
			t.Fatalf("publishing the host %s: %v", h.PublicKey, err)
		}
	}
	want := wireguard.Directory{Nodes: assigned, Hosts: hosts}
	got, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got,
		cmpopts.EquateComparable(netip.Addr{}, netip.Prefix{}, netip.AddrPort{},
			wireguard.PublicKey{})); diff != "" {
		t.Errorf("list mismatch (-want +got):\n%s", diff)
	}

	// A re-publish replaces the publisher's key and endpoint, keeps its
	// slice — stable per ISD-AS — and ignores whatever overlay it claims;
	// no one else's entry moves.
	updated := entries[0]
	updated.PublicKey = MustKey(0x03)
	updated.Overlay = mustPrefix(t, "100.64.9.0/24")
	updated.HostEndpoint = mustAddrPort(t, "198.51.100.11:51820")
	recorded, err := store.Publish(ctx, updated)
	if err != nil {
		t.Fatalf("re-publishing %s: %v", updated.IA, err)
	}
	if recorded.Overlay != assigned[0].Overlay {
		t.Errorf("re-publishing %s answered the claimed %s, want the held %s",
			updated.IA, recorded.Overlay, assigned[0].Overlay)
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
		switch {
		case e.IA.Equal(entries[0].IA):
			if e.Overlay != assigned[0].Overlay {
				t.Errorf("re-publish moved the slice to %s", e.Overlay)
			}
			if e.PublicKey != updated.PublicKey ||
				e.HostEndpoint != updated.HostEndpoint {
				t.Errorf("re-publish left the entry %+v, want the key and endpoint replaced", e)
			}
		case e.IA.Equal(entries[1].IA):
			if e.Overlay != assigned[1].Overlay || e.PublicKey != entries[1].PublicKey {
				t.Errorf("re-publishing %s moved its neighbor: %+v", entries[0].IA, e)
			}
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
