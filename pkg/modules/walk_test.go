// Package modules is the node's pluggable surface (ADR-0013): every seam
// the tree names, filed as a module — the contract at the module's root,
// the implementations one package each beneath, a shared contract suite
// every implementation runs, and the kind (storage, policy, or source)
// declared in the module's own document. This package is the check that
// asserts it: a walk of the roof and an import rule, both run with the
// tests, so what held by review alone becomes the tree's own assertion.
// The roof's root holds nothing else.
package modules

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// kinds are the seam species a module may declare; the kind fixes the
// selection its implementations stand under.
var kinds = map[string]bool{"storage": true, "policy": true, "source": true}

// implAllowlist is the set of packages that may import an implementation
// package in production: the assemblies alone — the node's composition
// root and the integration harness. Everything else reaches a seam through
// its module root, and tests import what they test.
var implAllowlist = map[string]bool{
	"github.com/fancl20/cion/internal/services":    true,
	"github.com/fancl20/cion/internal/testnetwork": true,
}

// TestWalk asserts the roof's shape: every child of the roof is a module;
// every module's root package declares its kind; nothing sits beneath a
// root but implementation packages and the module's contract suite; and
// every implementation runs the suite. The checks read the tree at run
// time, so a change elsewhere in the roof can be served from go test's
// cache; the repo's -count discipline (AGENTS.md) is what defeats it.
func TestWalk(t *testing.T) {
	roof := roofDir(t)
	listing := goList(t, repoRoot(t))

	// The roof's root holds the check alone.
	entries, err := os.ReadDir(roof)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") &&
			!strings.HasSuffix(e.Name(), "_test.go") {
			t.Errorf("the roof's root holds %s beside the check; the "+
				"check is the one package it holds", e.Name())
		}
	}

	var problems []string
	for _, m := range childDirs(t, roof) {
		problems = append(problems, walkModule(t, m, listing)...)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// walkModule reads one module's shape and its suite rule, reporting every
// assertion the module breaks.
func walkModule(t *testing.T, mod string, listing map[string]*listPkg) []string {
	name := filepath.Base(mod)
	var problems []string

	// The kind, declared in the module's own document.
	kind, ok := declaredKind(mod)
	if !ok {
		problems = append(problems, name+": the root package declares no "+
			"kind (a line \"Kind: storage|policy|source\" in the package document)")
	} else if !kinds[kind] {
		problems = append(problems, name+": declares the unknown kind "+kind)
	}

	// Nothing beneath the root but impl/, the implementations' place.
	for _, c := range childDirs(t, mod) {
		if filepath.Base(c) == "impl" {
			continue
		}
		problems = append(problems, name+": "+c+" sits beneath the module "+
			"root outside impl/, the implementations' place")
	}

	// impl/ holds one package per implementation and the module's contract
	// suite, nothing deeper.
	var impls, suites []string
	for _, c := range childDirs(t, implDir(t, mod)) {
		base := filepath.Base(c)
		if !hasPackage(c) {
			problems = append(problems, name+": "+c+" is no package")
			continue
		}
		for _, deeper := range childDirs(t, c) {
			problems = append(problems, name+": "+deeper+" nests a package "+
				"beneath "+base+"; one package per implementation")
		}
		if strings.HasSuffix(base, "test") {
			suites = append(suites, importPath(t, c))
			continue
		}
		impls = append(impls, importPath(t, c))
	}

	// Every implementation runs the suite — a check the package graph
	// feeds; the fixture trees carry none.
	if listing == nil {
		return problems
	}
	if len(impls) > 0 && len(suites) == 0 {
		problems = append(problems, name+": holds implementations but no "+
			"contract suite (a package under impl/ whose name ends in test)")
	}
	for _, impl := range impls {
		p := listing[impl]
		if p == nil {
			problems = append(problems, name+": "+impl+" is not in the "+
				"module's package graph")
			continue
		}
		runs := append(append([]string{}, p.TestImports...), p.XTestImports...)
		runsSuite := false
		for _, suite := range suites {
			runsSuite = runsSuite || contains(runs, suite)
		}
		if !runsSuite {
			problems = append(problems, name+": "+impl+" runs no contract "+
				"suite; its tests must import one of "+strings.Join(suites, ", "))
		}
	}
	return problems
}

// TestImportRule asserts that implementation packages are imported by the
// assemblies and the tests alone — composition-root exclusivity as a
// mechanical fact.
func TestImportRule(t *testing.T) {
	roof := roofDir(t)
	listing := goList(t, repoRoot(t))

	for _, m := range childDirs(t, roof) {
		for _, c := range childDirs(t, implDir(t, m)) {
			if strings.HasSuffix(filepath.Base(c), "test") {
				continue // the suite, shared test machinery
			}
			for _, p := range importProblems(importPath(t, c), listing) {
				t.Error(p)
			}
		}
	}
}

// importProblems reports every production importer of one implementation
// package that stands outside the assemblies.
func importProblems(impl string, listing map[string]*listPkg) []string {
	var problems []string
	for path, p := range listing {
		if !contains(p.Imports, impl) {
			continue // tests import through TestImports; production here
		}
		if implAllowlist[path] {
			continue
		}
		problems = append(problems, impl+" is imported in production by "+
			path+"; only the assemblies and the tests may import an "+
			"implementation")
	}
	return problems
}

// TestWalkFixtures proves the walk's assertions can fail: trees built to
// break each one — a module whose kind line is missing, a stray package
// beneath a root, an implementation outside impl/, an unknown kind — are
// each reported, so the walk cannot silently pass on nothing.
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
	rootPkg := func(kind string) string {
		doc := "// Package m is a module of the fixtures.\npackage m\n"
		if kind != "" {
			doc = "// Package m is a module of the fixtures.\n//\n// Kind: " +
				kind + " — the fixture's.\npackage m\n"
		}
		return doc
	}
	good := map[string]string{
		"m/m.go":                  rootPkg("storage"),
		"m/impl/bbolt/bbolt.go":   "package bbolt",
		"m/impl/dbtest/dbtest.go": "package dbtest",
	}
	cases := []struct {
		name     string
		files    map[string]string
		problems []string
	}{
		{
			name:  "a module in good shape",
			files: good,
		},
		{
			name: "a module whose kind line is missing",
			files: map[string]string{
				"m/m.go":                  rootPkg(""),
				"m/impl/bbolt/bbolt.go":   "package bbolt",
				"m/impl/dbtest/dbtest.go": "package dbtest",
			},
			problems: []string{"m: the root package declares no kind"},
		},
		{
			name: "a module of an unknown kind",
			files: map[string]string{
				"m/m.go":                  rootPkg("magic"),
				"m/impl/bbolt/bbolt.go":   "package bbolt",
				"m/impl/dbtest/dbtest.go": "package dbtest",
			},
			problems: []string{"m: declares the unknown kind magic"},
		},
		{
			name: "a stray package beneath a root",
			files: func() map[string]string {
				f := map[string]string{}
				for k, v := range good {
					f[k] = v
				}
				f["m/util/util.go"] = "package util"
				return f
			}(),
			problems: []string{"outside impl/"},
		},
		{
			name: "an implementation outside the implementations' place",
			files: func() map[string]string {
				f := map[string]string{}
				for k, v := range good {
					f[k] = v
				}
				f["m/impl/bbolt/inner/inner.go"] = "package inner"
				return f
			}(),
			problems: []string{"nests a package"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := write(t, tc.files)
			got := walkModule(t, filepath.Join(root, "m"), nil)
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

// TestImportRuleFixtures proves the import rule can fail: a fabricated
// production import from outside the allowlist is reported, the assemblies
// alone pass.
func TestImportRuleFixtures(t *testing.T) {
	const impl = "github.com/fancl20/cion/pkg/modules/m/impl/bbolt"
	listing := map[string]*listPkg{
		"github.com/fancl20/cion/internal/services": {Imports: []string{impl}},
		"github.com/fancl20/cion/pkg/controlplane":  {Imports: []string{impl}},
	}
	problems := importProblems(impl, listing)
	if len(problems) != 1 || !strings.Contains(problems[0],
		"github.com/fancl20/cion/pkg/controlplane") {

		t.Errorf("problems = %v, want exactly the control plane's import "+
			"flagged", problems)
	}
}

// declaredKind reads a module root's package document for its kind line.
func declaredKind(mod string) (string, bool) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(mod)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(mod, e.Name()), nil,
			parser.PackageClauseOnly|parser.ParseComments)
		if err != nil || f.Doc == nil {
			continue
		}
		for _, line := range strings.Split(f.Doc.Text(), "\n") {
			line = strings.TrimSpace(line)
			if rest, ok := strings.CutPrefix(line, "Kind:"); ok {
				words := strings.Fields(rest)
				if len(words) > 0 {
					return words[0], true
				}
			}
		}
	}
	return "", false
}

// hasPackage reports whether the directory holds Go source.
func hasPackage(dir string) bool {
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

// childDirs lists a directory's subdirectories, testdata aside.
func childDirs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
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

// implDir is the module's implementations' place; a module without one
// holds a directory that does not exist, which childDirs reads as empty.
func implDir(t *testing.T, mod string) string {
	t.Helper()
	return filepath.Join(mod, "impl")
}

// listPkg is the slice of go list -json an implementation rule reads.
type listPkg struct {
	ImportPath   string
	Imports      []string
	TestImports  []string
	XTestImports []string
}

// goList reads the module's package graph: every package with its
// production imports and its tests' imports.
func goList(t *testing.T, dir string) map[string]*listPkg {
	t.Helper()
	out := runGo(t, dir, "list", "-json", "./...")
	dec := json.NewDecoder(bytes.NewReader(out))
	pkgs := make(map[string]*listPkg)
	for dec.More() {
		var p listPkg
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decoding go list: %v", err)
		}
		pkgs[p.ImportPath] = &p
	}
	return pkgs
}

// runGo runs go with the given arguments in dir, failing the test on error
// and returning the standard output.
func runGo(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return out
}

// roofDir is this package's directory: the roof itself.
func roofDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locating this file")
	}
	return filepath.Dir(file)
}

// repoRoot is the module's root, two levels above the roof.
func repoRoot(t *testing.T) string {
	t.Helper()
	return filepath.Clean(filepath.Join(roofDir(t), "..", ".."))
}

// importPath derives a directory's import path from the repo layout.
func importPath(t *testing.T, dir string) string {
	t.Helper()
	rel, err := filepath.Rel(repoRoot(t), dir)
	if err != nil {
		t.Fatal(err)
	}
	return "github.com/fancl20/cion/" + filepath.ToSlash(rel)
}

// contains reports whether the list holds the string.
func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
