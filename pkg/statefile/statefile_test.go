package statefile

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

// TestWriteCreatesAndReplaces checks a write's shape: the file created with
// mode 0600 in parents created with mode 0700, and a second write replacing
// the content whole.
func TestWriteCreatesAndReplaces(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a", "b", "file")
	if err := Write(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b")} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Errorf("%s: mode %v, want a directory with mode 0700", dir, info.Mode())
		}
	}
	if err := Write(path, []byte("second, longer")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "second, longer" {
		t.Errorf("content = %q, want the second write's", raw)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode())
	}
	if _, err := os.Lstat(path + ".tmp"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the temporary file outlived the writes: %v", err)
	}
}

// TestWriteIsWholeToAReader checks the replacement a reader racing a stream
// of writes sees: one of the two contents, whole, on every read. The reader
// reads until the writer finishes.
func TestWriteIsWholeToAReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	contents := [][]byte{bytes.Repeat([]byte("a"), 16), bytes.Repeat([]byte("b"), 64<<10)}
	if err := Write(path, contents[0]); err != nil {
		t.Fatal(err)
	}
	writer := make(chan error, 1)
	go func() {
		for i := range 200 {
			if err := Write(path, contents[i%2]); err != nil {
				writer <- err
				return
			}
		}
		writer <- nil
	}()
	var reads, torn int
	for running := true; running; {
		select {
		case err := <-writer:
			if err != nil {
				t.Fatal(err)
			}
			running = false
		default:
		}
		raw, err := os.ReadFile(path)
		reads++
		if err != nil || (!bytes.Equal(raw, contents[0]) && !bytes.Equal(raw, contents[1])) {
			torn++
		}
	}
	if torn > 0 {
		t.Errorf("%d of %d reads saw neither content whole", torn, reads)
	}
}

// TestWriteFailureLeavesPath checks a failed write: a directory standing at
// the temporary name fails it before the rename and leaves the old content,
// and a directory standing at the path fails the rename and leaves no
// temporary file.
func TestWriteFailureLeavesPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := Write(path, []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("new")); err == nil {
		t.Error("the write through a directory at the temporary name succeeded")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "old" {
		t.Errorf("content = %q after the failed write, want the old one", raw)
	}

	occupied := filepath.Join(dir, "occupied")
	if err := os.Mkdir(occupied, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Write(occupied, []byte("new")); err == nil {
		t.Error("the rename over a directory succeeded")
	}
	if _, err := os.Lstat(occupied + ".tmp"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the failed rename left its temporary file: %v", err)
	}
}

// TestLoadOrCreate checks the load-or-create: a missing file is created once
// with what create returned, a present one decoded without calling create,
// and a decode error names the path.
func TestLoadOrCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "value")
	created := 0
	create := func() (string, []byte, error) {
		created++
		return "fresh", []byte("fresh\n"), nil
	}
	decode := func(raw []byte) (string, error) {
		return strings.TrimSpace(string(raw)), nil
	}
	for range 2 {
		v, err := LoadOrCreate(path, decode, create)
		if err != nil {
			t.Fatal(err)
		}
		if v != "fresh" {
			t.Errorf("value = %q, want the created one", v)
		}
	}
	if created != 1 {
		t.Errorf("create ran %d times, want once", created)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "fresh\n" {
		t.Errorf("file = %q, want the created bytes", raw)
	}

	bad := errors.New("bad content")
	_, err = LoadOrCreate(path, func([]byte) (string, error) { return "", bad }, create)
	if !errors.Is(err, bad) || !strings.Contains(err.Error(), path) {
		t.Errorf("decode error = %v, want %v naming %s", err, bad, path)
	}
	if created != 1 {
		t.Errorf("create ran on a present file")
	}
}

// TestRemove checks that Remove removes the file and accepts a missing one.
func TestRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := Write(path, []byte("content")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the file outlived its removal: %v", err)
	}
}

// TestOpenBoltCreatesTheMissingBuckets opens a fresh database with two buckets
// and reopens it with a third: the file has mode 0600, all three buckets
// exist, and the first keeps what was written to it before the reopen.
func TestOpenBoltCreatesTheMissingBuckets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	db, err := OpenBolt(path, nil, "a", "b")
	if err != nil {
		t.Fatalf("opening a fresh database: %v", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte("a")).Put([]byte("key"), []byte("value"))
	}); err != nil {
		t.Fatalf("writing to bucket a: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing the database: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode())
	}

	db, err = OpenBolt(path, nil, "a", "b", "c")
	if err != nil {
		t.Fatalf("reopening with a third bucket: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var missing []string
	var value []byte
	if err := db.View(func(tx *bbolt.Tx) error {
		for _, name := range []string{"a", "b", "c"} {
			if tx.Bucket([]byte(name)) == nil {
				missing = append(missing, name)
			}
		}
		if a := tx.Bucket([]byte("a")); a != nil {
			value = bytes.Clone(a.Get([]byte("key")))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(missing) > 0 {
		t.Errorf("buckets %v missing after the reopen", missing)
	}
	if string(value) != "value" {
		t.Errorf("bucket a holds %q after the reopen, want %q", value, "value")
	}
}

// TestOpenBoltReleasesTheFileWhenSetupFails opens an existing database
// read-only, which holds the file's shared lock and refuses the bucket setup's
// write, and then takes the exclusive lock a fresh open needs: the failed
// OpenBolt must have closed the database.
func TestOpenBoltReleasesTheFileWhenSetupFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	db, err := OpenBolt(path, nil, "a")
	if err != nil {
		t.Fatalf("creating the database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing the database: %v", err)
	}
	if _, err := OpenBolt(path, &bbolt.Options{ReadOnly: true}, "a"); err == nil {
		t.Fatal("OpenBolt set the buckets up through a read-only open")
	}
	again, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("reopening after the failed OpenBolt: %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatalf("closing the reopened database: %v", err)
	}
}
