// Package core is the node core's roof: the engines every node runs, core AS
// or not, one package each beneath the roof — the data plane, the control
// plane, the trust engine, and the bootstrap channel. This package is the
// check that asserts it: a walk of the roof and an import rule, both run with
// the tests. The roof's root holds nothing else.
package core

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fancl20/cion/internal/walktest"
)

// members are the core's packages. The core is frozen at this enumeration: a
// package beneath the roof that is not one of them fails the walk.
var members = []string{"controlplane", "dataplane", "trust", "webpki"}

// TestWalk asserts the roof's shape: its root holds the check alone, and its
// children are the core's members, each a package. The walk reads the tree at
// run time, so a change elsewhere in the roof can be served from go test's
// cache; the repo's -count discipline (AGENTS.md) is what defeats it.
func TestWalk(t *testing.T) {
	for _, p := range walkRoof(t, walktest.Dir(t, "pkg/core")) {
		t.Error(p)
	}
}

// walkRoof reads the roof's shape against the members, reporting every
// assertion the tree breaks.
func walkRoof(t *testing.T, roof string) []string {
	var problems []string
	for _, f := range walktest.Sources(t, roof) {
		problems = append(problems, "the roof's root holds "+filepath.Base(f)+
			" beside the check; the check is the one package it holds")
	}
	for _, c := range walktest.ChildDirs(t, roof) {
		if name := filepath.Base(c); !slices.Contains(members, name) {
			problems = append(problems, name+": sits beneath the roof and "+
				"is no member of the core")
		}
	}
	for _, m := range members {
		if !walktest.HasPackage(filepath.Join(roof, m)) {
			problems = append(problems, m+": a member of the core with no "+
				"package beneath the roof")
		}
	}
	return problems
}

// TestWalkFixtures proves the walk's assertions can fail: trees built to
// break each one — a fifth child, a production source at the root, a missing
// member — are each reported, so the walk cannot silently pass on nothing.
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
	roof := func(extra map[string]string, without string) map[string]string {
		files := map[string]string{"walk_test.go": "package core"}
		for _, m := range members {
			if m != without {
				files[m+"/"+m+".go"] = "package " + m
			}
		}
		maps.Copy(files, extra)
		return files
	}
	cases := []struct {
		name    string
		files   map[string]string
		problem string
	}{
		{name: "a roof in good shape", files: roof(nil, "")},
		{
			name:    "a fifth child",
			files:   roof(map[string]string{"policy/policy.go": "package policy"}, ""),
			problem: "policy: sits beneath the roof",
		},
		{
			name:    "a production source at the root",
			files:   roof(map[string]string{"core.go": "package core"}, ""),
			problem: "the roof's root holds core.go",
		},
		{
			name:    "a missing member",
			files:   roof(nil, "webpki"),
			problem: "webpki: a member of the core with no package",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := walkRoof(t, write(t, tc.files))
			if tc.problem == "" {
				for _, p := range got {
					t.Errorf("unexpected problem: %s", p)
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], tc.problem) {
				t.Errorf("problems = %v, want exactly one mentioning %q", got, tc.problem)
			}
		})
	}
}

// TestImportRule asserts the core's imports: no core package's production
// sources import an application, a module implementation, the assembly and
// the harness beneath internal/, or the commands.
func TestImportRule(t *testing.T) {
	graph := walktest.Graph(t)
	for _, path := range walktest.PackagesUnder(t, walktest.Dir(t, "pkg/core")) {
		for _, p := range importProblems(path, graph) {
			t.Error(p)
		}
	}
}

// importProblems reports every forbidden production import of one core
// package.
func importProblems(path string, graph map[string]*walktest.Package) []string {
	p := graph[path]
	if p == nil {
		return []string{path + " is not in the module's package graph"}
	}
	var problems []string
	for _, imp := range p.Imports {
		if forbidden(imp) {
			problems = append(problems, path+" imports "+imp+" in production: "+
				"a core package imports libraries, module contracts, and core "+
				"packages, never an application, a module implementation, "+
				"internal/, or cmd/")
		}
	}
	return problems
}

// forbidden reports whether a core package may not import the path.
func forbidden(imp string) bool {
	rel, ok := strings.CutPrefix(imp, walktest.Module+"/")
	if !ok {
		return false
	}
	parts := strings.Split(rel, "/")
	switch {
	case parts[0] == "internal", parts[0] == "cmd":
		return true
	case len(parts) >= 2 && parts[0] == "pkg" && parts[1] == "apps":
		return true
	default:
		return len(parts) >= 4 && parts[0] == "pkg" && parts[1] == "modules" &&
			parts[3] == "impl"
	}
}

// TestImportRuleFixtures proves the import rule can fail: fabricated
// production imports of an application, a module implementation, the
// assembly, and the commands are each reported, while a library, a module
// contract, a core package, a third-party package, and a test's import pass.
func TestImportRuleFixtures(t *testing.T) {
	const m = walktest.Module
	path := m + "/pkg/core/controlplane"
	graph := map[string]*walktest.Package{
		path: {
			Imports: []string{
				m + "/pkg/apps/wireguard",
				m + "/pkg/modules/links/impl/bbolt",
				m + "/internal/services",
				m + "/cmd/cion",
				m + "/pkg/libs/scion",
				m + "/pkg/modules/links",
				m + "/pkg/core/trust",
				"github.com/scionproto/scion/pkg/addr",
			},
			TestImports: []string{m + "/internal/walktest"},
		},
	}
	got := importProblems(path, graph)
	for _, want := range []string{
		"/pkg/apps/wireguard ", "/pkg/modules/links/impl/bbolt ", "/internal/services ", "/cmd/cion ",
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
