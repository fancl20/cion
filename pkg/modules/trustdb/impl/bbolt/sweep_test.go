package bbolt

import (
	"context"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"go.etcd.io/bbolt"

	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/dbtest"
)

// newSweepDB opens a throwaway database and inserts the given chains.
func newSweepDB(t *testing.T, chains ...[]*x509.Certificate) *bboltDB {
	t.Helper()
	db, err := New(filepath.Join(t.TempDir(), "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, chain := range chains {
		if _, err := db.InsertChain(context.Background(), chain); err != nil {
			t.Fatal(err)
		}
	}
	return db.(*bboltDB)
}

// TestDeleteExpiredChainsAbortsOnMalformed checks the sweep's two-pass shape:
// a malformed entry aborts the sweep having deleted nothing — bern's two
// chains, collected before the cursor reaches the corrupted geneva entry,
// stay in the store.
func TestDeleteExpiredChainsAbortsOnMalformed(t *testing.T) {
	bern1 := dbtest.ChainFixture(t, "bern", 1)
	bern3 := dbtest.ChainFixture(t, "bern", 3)
	geneva1 := dbtest.ChainFixture(t, "geneva", 1)
	b := newSweepDB(t, bern1, bern3, geneva1)

	// Corrupt geneva's stored chain; the name sorts after bern's, so the
	// read pass collects bern's expired entries before it meets the garbage.
	if err := b.db.Update(func(tx *bbolt.Tx) error {
		subb := tx.Bucket([]byte("chains")).Bucket([]byte("1-ff00:0:120"))
		k, _ := subb.Cursor().First()
		return subb.Put(k, []byte("garbage"))
	}); err != nil {
		t.Fatal(err)
	}

	// Every fixture chain expired long before 2021; the sweep aborts on the
	// malformed entry and reports nothing deleted.
	n, err := b.DeleteExpiredChains(context.Background(), time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC))
	if err == nil {
		t.Error("DeleteExpiredChains succeeded on a malformed entry, want error")
	}
	if n != 0 {
		t.Errorf("DeleteExpiredChains = %d, want 0 on abort", n)
	}
	chains, err := b.Chains(context.Background(), trustdb.ChainQuery{
		IA: addr.MustParseIA("1-ff00:0:110"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 2 {
		t.Errorf("chains after the aborted sweep = %d, want 2 (nothing deleted)", len(chains))
	}
}

// TestDeleteExpiredChainsLeavesNoShell checks that an emptied ISD-AS
// sub-bucket is deleted with its last chain: the chains bucket holds no
// sub-bucket the sweep has emptied.
func TestDeleteExpiredChainsLeavesNoShell(t *testing.T) {
	bern1 := dbtest.ChainFixture(t, "bern", 1)
	geneva1 := dbtest.ChainFixture(t, "geneva", 1)
	b := newSweepDB(t, bern1, geneva1)

	n, err := b.DeleteExpiredChains(context.Background(), time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("DeleteExpiredChains = %d, want 2", n)
	}
	if err := b.db.View(func(tx *bbolt.Tx) error {
		if k, _ := tx.Bucket([]byte("chains")).Cursor().First(); k != nil {
			t.Errorf("chains bucket holds sub-bucket %q after the sweep emptied it", k)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
