// Package providertest implements the shared contract tests for topology
// source implementations, the databases' impl/dbtest pattern: an
// implementation has at least one test that runs this suite.
package providertest

import (
	"context"
	"testing"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/topology"
)

// Suite describes one implementation's run of the contract tests.
type Suite struct {
	// New builds the provider as a founding core, carrying the seed facts
	// of its own — a --neighbor for the measured provider, a link-set
	// entry for the file one.
	New func(t *testing.T) topology.Provider
	// Store is the fresh store the provider is wired to and seeds.
	Store links.DB
}

// draw is a first start's provisional draw: a private-range ISD-AS.
var draw = addr.MustIAFrom(20, 0xfd0000000071)

// Run tests one implementation of the topology.Provider contract as the
// suite can build it: a founding core, wired to the store, its standing
// episodes asserted — the draw returning unchanged, seeding idempotent
// before the first generation.
func Run(t *testing.T, s Suite) {
	ctx := context.Background()
	t.Run("contract: the founding core's draw returns unchanged", func(t *testing.T) {
		p := s.New(t)
		ia, err := p.CompleteIdentity(ctx, draw)
		if err != nil {
			t.Fatalf("completing the core's identity: %v", err)
		}
		if ia != draw {
			t.Errorf("the core's completed identity = %v, want the draw %v",
				ia, draw)
		}
	})
	t.Run("contract: seeding is idempotent", func(t *testing.T) {
		p := s.New(t)
		p.Wire(topology.Pieces{Store: s.Store})
		if err := p.Seed(ctx); err != nil {
			t.Fatalf("the first seed: %v", err)
		}
		first := snapshot(t, s.Store)
		if len(first) == 0 {
			t.Fatal("the first seed landed no entry")
		}
		if err := p.Seed(ctx); err != nil {
			t.Fatalf("the second seed: %v", err)
		}
		second := snapshot(t, s.Store)
		if len(first) != len(second) {
			t.Fatalf("entries after the second seed = %d, want the %d of the first",
				len(second), len(first))
		}
		for i := range first {
			if first[i] != second[i] {
				t.Errorf("entry %d changed on the second seed: %v, want %v",
					i, second[i], first[i])
			}
		}
	})
}

// snapshot reads the store's entries as the comparable facts of each.
func snapshot(t *testing.T, store links.DB) []links.Link {
	t.Helper()
	entries, err := store.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := make([]links.Link, 0, len(entries))
	for _, l := range entries {
		out = append(out, links.Link{
			NeighborIA: l.NeighborIA,
			IfID:       l.IfID,
			Local:      l.Local,
			Remote:     l.Remote,
			State:      l.State,
		})
	}
	return out
}
