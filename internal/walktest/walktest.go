// Package walktest reads the module's tree for the roofs' walk tests: the
// directories, sources, and packages beneath a roof, and the module's package
// graph as go list reports it. Each roof's tests hold its own rules.
package walktest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Module is the module's import path.
const Module = "github.com/fancl20/cion"

// Package is one package of the module's graph: its import path, its
// production imports, and its tests' imports.
type Package struct {
	ImportPath   string
	Imports      []string
	TestImports  []string
	XTestImports []string
}

// Root returns the module's root directory, two levels above this package.
func Root(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locating the walktest package")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// Dir returns the directory at a slash-separated path below the module's
// root, such as "pkg/core".
func Dir(t *testing.T, rel string) string {
	t.Helper()
	return filepath.Join(Root(t), filepath.FromSlash(rel))
}

// Graph reads the module's package graph: every package with its imports.
func Graph(t *testing.T) map[string]*Package {
	t.Helper()
	cmd := exec.Command("go", "list", "-json", "./...")
	cmd.Dir = Root(t)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v: %s", err, stderr.String())
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	pkgs := make(map[string]*Package)
	for dec.More() {
		var p Package
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decoding go list: %v", err)
		}
		pkgs[p.ImportPath] = &p
	}
	return pkgs
}

// ChildDirs lists a directory's subdirectories, testdata aside. A directory
// that does not exist has none.
func ChildDirs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && e.Name() != "testdata" {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

// HasPackage reports whether the directory holds Go source.
func HasPackage(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") {
			return true
		}
	}
	return false
}

// Sources lists the production Go files directly in a directory, its tests
// aside.
func Sources(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			out = append(out, filepath.Join(dir, name))
		}
	}
	return out
}

// PackagesUnder lists the import paths of the packages beneath a directory,
// the directory itself aside.
func PackagesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var pkgs []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() || path == dir {
			return nil
		}
		if d.Name() == "testdata" {
			return filepath.SkipDir
		}
		if HasPackage(path) {
			pkgs = append(pkgs, ImportPath(t, path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return pkgs
}

// ImportPath returns a directory's import path.
func ImportPath(t *testing.T, dir string) string {
	t.Helper()
	rel, err := filepath.Rel(Root(t), dir)
	if err != nil {
		t.Fatal(err)
	}
	return Module + "/" + filepath.ToSlash(rel)
}
