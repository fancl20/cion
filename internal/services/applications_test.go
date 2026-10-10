package services

import (
	"testing"
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
		n := &node{cfg: rc}
		if got := n.appEnvironment().Core; got != tc.want {
			t.Errorf("%s's environment Core = %v, want %v (role %v)",
				tc.name, got, tc.want, rc.role)
		}
	}
}
