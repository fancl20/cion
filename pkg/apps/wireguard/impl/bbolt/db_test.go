package bbolt

import (
	"context"
	"encoding/hex"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"go.etcd.io/bbolt"

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

// TestDirectoryStoreIgnoresRetiredFields checks the store's leniency toward
// the older stored shape: a stored entry carrying the retired port and
// underlay fields decodes with them ignored, and a re-publish replaces it
// with the new shape.
func TestDirectoryStoreIgnoresRetiredFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	store, err := New(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	db := store.(*directoryDB).db
	key := mustKey()
	// An entry in the older stored shape: gatewayPort and underlay beside
	// the fields that remain.
	old := `{"publicKey":"` + hex.EncodeToString(key[:]) + `",` +
		`"gatewayPort":51820,"underlay":"192.0.2.1","overlay":"100.64.1.0/24"}`
	if err := db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(entriesBucket).Put([]byte("20-ff00:0:1"), []byte(old))
	}); err != nil {
		t.Fatal(err)
	}

	entries, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries.Nodes) != 1 {
		t.Fatalf("list served %d entries, want 1", len(entries.Nodes))
	}
	want := wireguard.Entry{
		IA:        mustIA(),
		PublicKey: key,
		Overlay:   mustPrefix(),
	}
	if entries.Nodes[0] != want {
		t.Errorf("decoded entry = %+v, want %+v", entries.Nodes[0], want)
	}

	// A re-publish replaces the old-shape entry wholesale — and keeps the
	// slice the older state held, an ISD-AS that already holds one keeping
	// it.
	if _, err := store.Publish(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	entries, err = store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries.Nodes) != 1 || entries.Nodes[0] != want {
		t.Errorf("re-published entry = %+v, want %+v", entries.Nodes[0], want)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func mustIA() addr.IA {
	return addr.MustIAFrom(20, 0xff0000000001)
}

func mustKey() wireguard.PublicKey {
	var key wireguard.PublicKey
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func mustPrefix() netip.Prefix {
	return netip.MustParsePrefix("100.64.1.0/24")
}
