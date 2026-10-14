package trust_test

import (
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/trust/trusttest"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
)

var (
	coreIATest = addr.MustIAFrom(20, 0xff0000000001)
	nodeIATest = addr.MustIAFrom(20, 0xff0000000002)
	// askSource is the source address a submission arrives from in the
	// decision's admission episodes.
	askSource = netip.MustParseAddrPort("198.51.100.7:41234")
)

// newFounder returns the founder of coreIATest's ISD over a fresh trust
// database.
func newFounder(t *testing.T) *trusttest.Founder {
	t.Helper()
	return trusttest.NewFounder(t, openTrustDB(t, t.TempDir()), coreIATest)
}

// openTrustDB opens the trust database in dir, closed when the test ends.
func openTrustDB(t *testing.T, dir string) trustdb.DB {
	t.Helper()
	db, err := bbolt.New(filepath.Join(dir, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
