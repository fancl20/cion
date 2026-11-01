package none_test

import (
	"path/filepath"
	"testing"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/trust/trusttest"
	"github.com/fancl20/cion/pkg/modules/membership"
	"github.com/fancl20/cion/pkg/modules/membership/impl/membershiptest"
	"github.com/fancl20/cion/pkg/modules/membership/impl/none"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
)

// openDB opens a fresh trust database, closed when the test ends.
func openDB(t *testing.T) trustdb.DB {
	t.Helper()
	db, err := bbolt.New(filepath.Join(t.TempDir(), "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestContract runs the membership contract suite against the none method.
func TestContract(t *testing.T) {
	membershiptest.Run(t, func(env membership.Env) membership.Method { return none.New(env) }, openDB)
}

// TestAdmitsEveryChain checks the none method's one decision: a chain no
// founder certifies — another core's, for a name the founder never admitted
// — is admitted at every boundary and kept; nothing is presented beside the
// node's own chain, which is kept too; and the listing gives no membership
// an expiry.
func TestAdmitsEveryChain(t *testing.T) {
	f := trusttest.NewFounder(t, openDB(t), addr.MustIAFrom(20, 0xff0000000001))
	other := trusttest.NewFounder(t, openDB(t), addr.MustIAFrom(20, 0xff0000000002))
	unadmitted := addr.MustIAFrom(20, 0xff0000000099)
	_, chain := other.Enroll(t, unadmitted)

	env := membershiptest.Env(f.DB, addr.MustIAFrom(20, 0xff0000000011), false)
	m := none.New(env)
	for name, b := range map[string]membership.Boundary{
		"handshake": membership.BoundaryHandshake,
		"renewal":   membership.BoundaryRenewal,
	} {
		if err := m.Admit(t.Context(), membership.Facts{Boundary: b, Chain: chain}); err != nil {
			t.Errorf("%s: refused another core's chain: %v", name, err)
		}
	}
	if held := env.Store.Get(unadmitted); held == nil || !held[0].Equal(chain[0]) {
		t.Error("the admitted chain is not kept as its membership")
	}
	_, own := f.Enroll(t, env.IA)
	presented, err := m.Present(t.Context(), own)
	if err != nil || len(presented) != 0 {
		t.Errorf("presented %d certificates beside the chain (err %v), want none", len(presented), err)
	}
	if held := env.Store.Get(env.IA); held == nil || !held[0].Equal(own[0]) {
		t.Error("the node's own chain is not kept as its membership once presented")
	}
	list, err := m.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || !list[0].IA.Equal(env.IA) || !list[1].IA.Equal(unadmitted) ||
		!list[0].Expires.IsZero() || !list[1].Expires.IsZero() {

		t.Errorf("listing %v, want the node's own and the admitted chain's memberships, "+
			"neither with an expiry", list)
	}
}
