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
// a stored entry carrying port and underlay fields the struct does not
// name: they decode ignored, and a re-publish replaces the entry wholesale.
func TestDirectoryStoreIgnoresRetiredFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	store, err := New(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	db := store.(*directoryDB).db
	key := dbtest.MustKey(0x01)
	// An entry carrying gatewayPort and underlay beside the fields that
	// remain.
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

	// A re-publish replaces the stored entry wholesale — and keeps the
	// slice it held, an ISD-AS that already holds one keeping it.
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

// TestDirectoryStoreHostWithoutMachineKey checks the store's leniency toward
// a stored host entry carrying no machine key: it decodes with none — the
// coordination application binds the machine claim at the first presentation
// — and the bound record round-trips.
func TestDirectoryStoreHostWithoutMachineKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	store, err := New(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	db := store.(*directoryDB).db
	key := dbtest.MustKey(0x01)
	// A host entry carrying no machine key beside the fields that remain.
	old := `{"addr":"100.64.1.2","ia":"20-ff00:0:1","note":"telegram operator"}`
	if err := db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(hostsBucket).Put([]byte(key.String()), []byte(old))
	}); err != nil {
		t.Fatal(err)
	}

	directory, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Hosts) != 1 {
		t.Fatalf("list served %d hosts, want 1", len(directory.Hosts))
	}
	if directory.Hosts[0].MachineKey != (wireguard.PublicKey{}) {
		t.Errorf("decoded machine key = %s, want none", directory.Hosts[0].MachineKey)
	}

	// The presentation's binding lands, and the record round-trips.
	bound := directory.Hosts[0]
	bound.MachineKey = dbtest.MustKey(0x71)
	if err := store.PublishHost(context.Background(), bound); err != nil {
		t.Fatal(err)
	}
	directory, err = store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Hosts) != 1 || directory.Hosts[0] != bound {
		t.Errorf("re-published host = %+v, want %+v", directory.Hosts[0], bound)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func mustIA() addr.IA {
	return addr.MustIAFrom(20, 0xff0000000001)
}

func mustPrefix() netip.Prefix {
	return netip.MustParsePrefix("100.64.1.0/24")
}
