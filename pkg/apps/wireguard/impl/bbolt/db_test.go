package bbolt

import (
	"path/filepath"
	"testing"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/apps/wireguard/impl/dbtest"
)

func TestDirectoryStoreContract(t *testing.T) {
	dbtest.TestDirectoryStore(t, func(t *testing.T) wireguard.DirectoryStore {
		store, err := New(filepath.Join(t.TempDir(), "directory.db"), nil)
		if err != nil {
			t.Fatal(err)
		}
		return store
	})
}
