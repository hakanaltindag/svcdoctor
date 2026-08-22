package vocabulary

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// This package exists so that four strings have one spelling. A test that only
// checked the constants' values would miss the failure mode entirely: the risk
// is not that a value here is wrong, it is that a second copy appears somewhere
// else and the two drift.

// TestTheValuesAreTheReportContract pins the strings themselves.
//
// They moved here from internal/probe/dns, internal/probe/tcp and
// internal/probe/tls, and the move was ownership only. A changed value here is a
// changed report contract and breaks every consumer matching on it, so it is
// asserted literally rather than derived.
func TestTheValuesAreTheReportContract(t *testing.T) {
	for _, c := range []struct {
		got  domain.Step
		want string
	}{
		{StepTargetRequested, "target.requested"},
		{StepDNSLookup, "dns.lookup"},
		{StepTCPConnect, "tcp.connect"},
		{StepTLSHandshake, "tls.handshake"},
	} {
		if string(c.got) != c.want {
			t.Errorf("step = %q, want %q", c.got, c.want)
		}
		if !c.got.Valid() {
			t.Errorf("%q is not a valid step name", c.got)
		}
	}
}

// TestEachCanonicalStringHasExactlyOneOwner is the reason the package exists.
//
// Every production file in the repository is scanned for the four literals. They
// may appear here and nowhere else: a second literal copy is the bug this package
// was created to make impossible, and it would be invisible until a rename split
// one contract into two.
//
// Test files are excluded deliberately. A test asserting that a step is spelled
// "dns.lookup" is exactly the kind of literal that should exist.
func TestEachCanonicalStringHasExactlyOneOwner(t *testing.T) {
	owned := map[string]bool{
		"target.requested": true,
		"dns.lookup":       true,
		"tcp.connect":      true,
		"tls.handshake":    true,
	}

	root := repoRoot(t)
	found := map[string][]string{}

	walkProductionFiles(t, root, func(path string, file *ast.File) {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil || !owned[value] {
				return true
			}
			found[value] = append(found[value], rel)
			return true
		})
	})

	for value := range owned {
		files := found[value]
		switch {
		case len(files) == 0:
			t.Errorf("%q appears in no production file; the scan is not seeing this "+
				"package and every other assertion here is vacuous", value)
		case len(files) > 1 || !strings.HasPrefix(files[0], filepath.Join("internal", "vocabulary")):
			t.Errorf("%q appears in %v; it must appear only in internal/vocabulary, "+
				"because a second copy is a contract that can drift", value, files)
		}
	}
}

// TestTheProbesAliasRatherThanRedeclare checks the other half of the move.
//
// An alias keeps every existing caller working and keeps one spelling. A
// redeclared constant with the same value would compile, pass every test, and
// silently restore the duplication this package removed — which is why the
// literal scan above is the real guard and this is its readable companion.
func TestTheProbesAliasRatherThanRedeclare(t *testing.T) {
	root := repoRoot(t)

	for _, c := range []struct{ file, name, want string }{
		{filepath.Join("internal", "probe", "dns", "lookup.go"), "StepLookup", "StepDNSLookup"},
		{filepath.Join("internal", "probe", "tcp", "connect.go"), "StepConnect", "StepTCPConnect"},
		{filepath.Join("internal", "probe", "tls", "handshake.go"), "StepHandshake", "StepTLSHandshake"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, c.file), nil,
			parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", c.file, err)
		}

		if !aliasesVocabulary(file, c.name, c.want) {
			t.Errorf("%s does not declare %s as an alias of vocabulary.%s",
				c.file, c.name, c.want)
		}
	}
}

func aliasesVocabulary(file *ast.File, name, want string) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || spec.Names[0].Name != name || len(spec.Values) != 1 {
			return true
		}
		sel, ok := spec.Values[0].(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if ok && pkg.Name == "vocabulary" && sel.Sel.Name == want {
			found = true
		}
		return true
	})
	return found
}

// TestThisPackageHasNoBehaviour keeps the leaf a leaf.
//
// A vocabulary that grows a function grows a reason to import it from somewhere
// it does not belong, and then a reason to add a second one. The rule is easier
// to hold than to recover.
func TestThisPackageHasNoBehaviour(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "internal", "vocabulary")

	entries, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("globbing: %v", err)
	}

	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				t.Errorf("%s declares func %s; this package holds names and no behaviour",
					filepath.Base(path), fn.Name.Name)
			}
		}
		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if path != "github.com/hakanaltindag/svcdoctor/internal/domain" {
				t.Errorf("%s imports %s; this package imports internal/domain and nothing else",
					filepath.Base(path), path)
			}
		}
	}
}

// TestNoGenericTransportFindingCodeExists is the companion of
// internal/diagnosis/transport's phase guard, and it lives here because that
// package is denied the file-system access a module-wide scan needs.
//
// A generic transport finding could be smuggled in by declaring its code
// somewhere else and wiring a rule up later. Every finding code that exists is
// service-namespaced by contract, so a bare DNS_, TCP_, TLS_ or TARGET_ code
// anywhere in production is precisely what ADR 0042 does not authorize.
//
// FailureClass values share those prefixes and are legitimate — they say what
// evidence observed. Only a FindingCode is a claim, so the scan is limited to
// declarations of that type.
func TestNoGenericTransportFindingCodeExists(t *testing.T) {
	prefixes := []string{"DNS_", "TCP_", "TLS_", "TARGET_"}
	root := repoRoot(t)
	scanned := 0

	walkProductionFiles(t, root, func(path string, file *ast.File) {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok || !declaresFindingCode(spec) {
				return true
			}
			scanned++
			for _, value := range spec.Values {
				lit, ok := value.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				code, uErr := strconv.Unquote(lit.Value)
				if uErr != nil {
					continue
				}
				for _, prefix := range prefixes {
					if strings.HasPrefix(code, prefix) {
						t.Errorf("%s declares finding code %s; generic transport "+
							"diagnosis is Phase 4.9a", rel, code)
					}
				}
			}
			return true
		})
	})

	// The control. A scan that recognized no declaration would pass on any
	// repository, including one full of the codes it is meant to reject.
	if scanned == 0 {
		t.Error("no FindingCode declaration was recognized; the scan is vacuous")
	}
}

// declaresFindingCode reports whether a value spec declares a domain.FindingCode.
func declaresFindingCode(spec *ast.ValueSpec) bool {
	if sel, ok := spec.Type.(*ast.SelectorExpr); ok {
		return sel.Sel.Name == "FindingCode"
	}
	ident, ok := spec.Type.(*ast.Ident)
	return ok && ident.Name == "FindingCode"
}

// repoRoot walks up from the package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolving working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("module root not found")
		}
		dir = parent
	}
}

// walkProductionFiles visits every non-test Go file in the module.
func walkProductionFiles(t *testing.T, root string, visit func(path string, file *ast.File)) {
	t.Helper()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		visit(path, file)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
}
