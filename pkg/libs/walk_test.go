// Package libs is the shared libraries' roof: code core and applications
// share, with no loops of its own and no policy, one package each beneath the
// roof. This package is the check that asserts their imports, run with the
// tests. The roof's root holds nothing else.
package libs

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/fancl20/cion/internal/walktest"
)

// TestWalk asserts that the roof's root holds the check alone.
func TestWalk(t *testing.T) {
	for _, f := range walktest.Sources(t, walktest.Dir(t, "pkg/libs")) {
		t.Errorf("the roof's root holds %s beside the check; the check is "+
			"the one package it holds", filepath.Base(f))
	}
}

// TestImportRule asserts the libraries' imports: inside the module, a
// library's production sources import libraries and module contracts only.
func TestImportRule(t *testing.T) {
	graph := walktest.Graph(t)
	for _, path := range walktest.PackagesUnder(t, walktest.Dir(t, "pkg/libs")) {
		for _, p := range importProblems(path, graph) {
			t.Error(p)
		}
	}
}

// importProblems reports every production import of one library that stands
// outside the libraries and the module contracts.
func importProblems(path string, graph map[string]*walktest.Package) []string {
	p := graph[path]
	if p == nil {
		return []string{path + " is not in the module's package graph"}
	}
	var problems []string
	for _, imp := range p.Imports {
		if !allowed(imp) {
			problems = append(problems, path+" imports "+imp+" in production: "+
				"a library imports libraries and module contracts only")
		}
	}
	return problems
}

// allowed reports whether a library may import the path: anything outside the
// module, a library, or a module's contract root.
func allowed(imp string) bool {
	rel, ok := strings.CutPrefix(imp, walktest.Module+"/")
	if !ok {
		return true
	}
	parts := strings.Split(rel, "/")
	if len(parts) < 3 || parts[0] != "pkg" {
		return false
	}
	return parts[1] == "libs" || (parts[1] == "modules" && len(parts) == 3)
}

// TestImportRuleFixtures proves the import rule can fail: fabricated
// production imports of a core package, an application, a module
// implementation, and the assembly are each reported, while a library, a
// module contract, a third-party package, and a test's import pass.
func TestImportRuleFixtures(t *testing.T) {
	const m = walktest.Module
	path := m + "/pkg/libs/scion"
	graph := map[string]*walktest.Package{
		path: {
			Imports: []string{
				m + "/pkg/core/dataplane",
				m + "/pkg/apps/wireguard",
				m + "/pkg/modules/pathdb/impl/bbolt",
				m + "/internal/services",
				m + "/pkg/libs/segment",
				m + "/pkg/modules/pathdb",
				"github.com/scionproto/scion/pkg/addr",
			},
			TestImports: []string{m + "/pkg/core/dataplane"},
		},
	}
	got := importProblems(path, graph)
	for _, want := range []string{
		"/pkg/core/dataplane ", "/pkg/apps/wireguard ", "/pkg/modules/pathdb/impl/bbolt ", "/internal/services ",
	} {
		found := false
		for _, p := range got {
			found = found || strings.Contains(p, want)
		}
		if !found {
			t.Errorf("no problem names %q; got %v", strings.TrimSpace(want), got)
		}
	}
	if len(got) != 4 {
		t.Errorf("problems = %v, want exactly the four forbidden imports", got)
	}
}
