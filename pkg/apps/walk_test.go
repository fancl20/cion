package apps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fancl20/cion/internal/walktest"
)

// The import graph's bounds: the module's root, and this roof's own
// place in it.
const (
	moduleRoot = walktest.Module
	roofPath   = moduleRoot + "/pkg/apps"
	// nonresident is the one child of the roof that is no resident: the
	// ping application, the ping command's own client — the application a
	// process runs beside a node, not an application a node runs.
	nonresident = "ping"
)

// TestWalk asserts the roof's shape: every child of the roof is a
// resident with an entry in the table, or the ping application, the
// command's own client; every entry has its package beneath the roof.
// The walk reads the tree at run time, so a change elsewhere in the roof
// can be served from go test's cache; the repo's -count discipline
// (AGENTS.md) is what defeats it.
func TestWalk(t *testing.T) {
	names := make(map[string]bool, len(Table))
	for _, e := range Table {
		names[e.Name] = true
	}
	for _, problem := range walkRoof(t, walktest.Dir(t, "pkg/apps"), names) {
		t.Error(problem)
	}
}

// walkRoof reads one roof's shape against the table's names, reporting
// every assertion the tree breaks: a package without an entry, an entry
// without its package.
func walkRoof(t *testing.T, roof string, entries map[string]bool) []string {
	var problems []string
	for _, c := range walktest.ChildDirs(t, roof) {
		name := filepath.Base(c)
		if name == nonresident || !walktest.HasPackage(c) {
			continue
		}
		if !entries[name] {
			problems = append(problems, name+": sits beneath the roof "+
				"with no entry in the table")
		}
	}
	for name := range entries {
		if !walktest.HasPackage(filepath.Join(roof, name)) {
			problems = append(problems, name+": holds an entry with no "+
				"package beneath the roof")
		}
	}
	return problems
}

// TestWalkFixtures proves the walk's assertions can fail: trees built to
// break each one — a package without an entry, an entry without its
// package — are each reported, so the walk cannot silently pass on
// nothing.
func TestWalkFixtures(t *testing.T) {
	write := func(t *testing.T, files map[string]string) string {
		t.Helper()
		root := t.TempDir()
		for name, body := range files {
			path := filepath.Join(root, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return root
	}
	cases := []struct {
		name     string
		files    map[string]string
		entries  map[string]bool
		problems []string
	}{
		{
			name: "a roof in good shape",
			files: map[string]string{
				"wireguard/app.go":    "package wireguard",
				"coordination/app.go": "package coordination",
			},
			entries: map[string]bool{"wireguard": true, "coordination": true},
		},
		{
			name:  "a package without an entry",
			files: map[string]string{"middlebox/app.go": "package middlebox"},
			entries: map[string]bool{
				"wireguard": true, "coordination": true,
			},
			problems: []string{"middlebox: sits beneath the roof"},
		},
		{
			name: "an entry without its package",
			files: map[string]string{
				"wireguard/app.go": "package wireguard",
			},
			entries: map[string]bool{
				"wireguard": true, "socks": true,
			},
			problems: []string{"socks: holds an entry"},
		},
		{
			name: "the ping application exempt by name",
			files: map[string]string{
				"wireguard/app.go": "package wireguard",
				"ping/pinger.go":   "package ping",
			},
			entries: map[string]bool{"wireguard": true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := walkRoof(t, write(t, tc.files), tc.entries)
			if tc.problems == nil {
				for _, p := range got {
					t.Errorf("unexpected problem: %s", p)
				}
				return
			}
			for _, want := range tc.problems {
				found := false
				for _, p := range got {
					found = found || strings.Contains(p, want)
				}
				if !found {
					t.Errorf("no problem mentions %q; got %v", want, got)
				}
			}
		})
	}
}

// TestImportRule asserts the one-way direction: no application package's
// production sources import anything above the roof — not the assembly,
// not the harness, not the commands, not the roof's own root.
func TestImportRule(t *testing.T) {
	listing := walktest.Graph(t)
	for _, path := range walktest.PackagesUnder(t, walktest.Dir(t, "pkg/apps")) {
		for _, problem := range importProblems(path, listing) {
			t.Error(problem)
		}
	}
}

// importProblems reports every above-the-roof production import of one
// application package.
func importProblems(path string, listing map[string]*walktest.Package) []string {
	p := listing[path]
	if p == nil {
		return []string{path + " is not in the module's package graph"}
	}
	var problems []string
	for _, imp := range p.Imports {
		if aboveRoof(imp) {
			problems = append(problems, path+" imports "+imp+" in "+
				"production: an application package imports the core and "+
				"the libraries, never anything above the roof")
		}
	}
	return problems
}

// aboveRoof reports whether an import path stands above the roof.
func aboveRoof(imp string) bool {
	if imp == roofPath {
		return true
	}
	return strings.HasPrefix(imp, moduleRoot+"/internal/") ||
		strings.HasPrefix(imp, moduleRoot+"/cmd/")
}

// TestImportRuleFixtures proves the import rule can fail: fabricated
// production imports from above the roof are each reported, and the
// imports beneath the roof pass.
func TestImportRuleFixtures(t *testing.T) {
	listing := map[string]*walktest.Package{
		roofPath + "/wireguard": {Imports: []string{
			roofPath,
			moduleRoot + "/pkg/core/controlplane",
		}},
		roofPath + "/socks": {Imports: []string{
			moduleRoot + "/internal/services",
		}},
		roofPath + "/coordination": {Imports: []string{
			roofPath + "/wireguard",
		}},
	}
	want := []struct {
		path string
		imp  string
	}{
		{roofPath + "/wireguard", roofPath},
		{roofPath + "/socks", moduleRoot + "/internal/services"},
	}
	for _, w := range want {
		problems := importProblems(w.path, listing)
		if len(problems) != 1 || !strings.Contains(problems[0], w.imp) {
			t.Errorf("importProblems(%s) = %v, want exactly %s flagged",
				w.path, problems, w.imp)
		}
	}
	if problems := importProblems(roofPath+"/coordination", listing); len(problems) != 0 {
		t.Errorf("a sibling's import flagged: %v", problems)
	}
}
