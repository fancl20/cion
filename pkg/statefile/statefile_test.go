package statefile

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
