package services

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/fancl20/cion/pkg/modules/membership"
)

// TestAppEnvironmentFollowsFoundingTier checks the applications' core flag
// derives from the resolved role, not the core argument: the joining core
// spells the core flag beside its neighbor, yet its applications run as a
// local node's.
func TestAppEnvironmentFollowsFoundingTier(t *testing.T) {
	neighbor := []string{"192.0.2.7:30043"}
	for _, tc := range []struct {
		name      string
		core      bool
		neighbors []string
		want      bool
	}{
		{"the founding core", true, nil, true},
		{"a joining core", true, neighbor, false},
		{"a local node", false, neighbor, false},
	} {
		cfg := nodeConfig()
		cfg.Core, cfg.Neighbors = tc.core, tc.neighbors
		rc, err := cfg.resolve()
		if err != nil {
			t.Fatalf("resolving %s: %v", tc.name, err)
		}
		n := &node{cfg: rc, members: rc.newMembership(membership.Env{})}
		if got := n.appEnvironment().Core; got != tc.want {
			t.Errorf("%s's environment Core = %v, want %v (role %v)",
				tc.name, got, tc.want, rc.role)
		}
	}
}

// TestAppEnvironmentCarriesTheResolvers checks the applications'
// environment carries the resolvers the run arguments name, resolved in
// their order.
func TestAppEnvironmentCarriesTheResolvers(t *testing.T) {
	cfg := nodeConfig()
	cfg.Resolvers = []string{"9.9.9.9", "2620:fe::fe"}
	rc, err := cfg.resolve()
	if err != nil {
		t.Fatal(err)
	}
	n := &node{cfg: rc, members: rc.newMembership(membership.Env{})}
	want := []netip.Addr{netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("2620:fe::fe")}
	if got := n.appEnvironment().Resolvers; !slices.Equal(got, want) {
		t.Errorf("the environment's resolvers = %v, want %v", got, want)
	}
}
