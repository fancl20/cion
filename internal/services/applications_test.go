package services

import (
	"testing"

	"github.com/fancl20/cion/pkg/trust"
)

// TestAppEnvironmentFollowsFoundingTier checks the applications' core flag
// derives from the node's tier, not its core argument: the joining core
// spells the core flag beside its neighbor, yet its applications run as a
// local node's.
func TestAppEnvironmentFollowsFoundingTier(t *testing.T) {
	neighbor := []string{"192.0.2.7:30043"}
	for _, tc := range []struct {
		name   string
		cfg    NodeConfig
		asType trust.ASType
		want   bool
	}{
		{"the founding core", NodeConfig{Core: true}, trust.ASTypeCore, true},
		{"a joining core", NodeConfig{Core: true, Neighbors: neighbor}, trust.ASTypeAuthoritative, false},
		{"a local node", NodeConfig{Neighbors: neighbor}, trust.ASTypeNormal, false},
	} {
		n := &node{cfg: tc.cfg, ident: identity{asType: tc.asType}}
		if got := n.appEnvironment().Core; got != tc.want {
			t.Errorf("%s's environment Core = %v, want %v", tc.name, got, tc.want)
		}
	}
}
