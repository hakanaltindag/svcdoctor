package terminal

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The renderer's structural boundaries, asserted against its own source.
//
// depguard already denies this package the application, the adapters, the
// probes, diagnosis, security, redaction, the platform, `net` and `os`. What a
// linter cannot express is the rule ADR 0019 states about identifiers: an
// EvidenceID is a machine key, and *reading* one to decide what a node means
// substitutes a naming convention for the edges the producers actually wrote.
//
// It matters here more than almost anywhere. The Kafka tree separates bootstrap
// paths from advertised ones, and the advertised sweep's identifiers happen to
// contain the word "advertised" — so a substring test would work, on today's
// graphs, until an identifier scheme changed and a discovered broker silently
// became a bootstrap path. `internal/app` carries the same guard for the same
// reason.

// productionFiles returns this package's non-test Go sources.
func productionFiles(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Clean(name))
	}
	if len(out) == 0 {
		t.Fatal("no production files found; this test proves nothing")
	}
	return out
}

func parseFile(t *testing.T, name string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return file
}

// TestTheRendererNeverParsesAnEvidenceIdentifier is the ADR 0019 guard.
//
// It looks for a string operation applied to something that came from an
// evidence identifier: the shape `strings.Contains(string(node.ID()), …)`, a
// slice of one, a split, a prefix test. Reading an identifier to *print* it
// would be a different question — and is separately forbidden, because
// identifiers are the JSON's surface, not a person's.
func TestTheRendererNeverParsesAnEvidenceIdentifier(t *testing.T) {
	for _, name := range productionFiles(t) {
		file := parseFile(t, name)

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || (pkg.Name != "strings" && pkg.Name != "strconv" && pkg.Name != "regexp") {
				return true
			}
			for _, arg := range call.Args {
				if mentionsIdentifier(arg) {
					t.Errorf("%s: %s.%s is applied to an evidence identifier; "+
						"the graph's edges are the structure, not the identifier text",
						name, pkg.Name, selector.Sel.Name)
				}
			}
			return true
		})
	}
}

// mentionsIdentifier reports whether an expression reaches an evidence
// identifier.
func mentionsIdentifier(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case "ID", "EvidenceRefs":
			found = true
		}
		return true
	})
	return found
}

// TestTheRendererPrintsNoEvidenceIdentifier keeps the machine key in the JSON.
//
// A column of `kafka.broker_advertised/kafka.internal:9093/198.51.100.10/2/…` in
// a terminal is noise that pushes the diagnosis off the screen, and a reader who
// needs the exact nodes has the canonical artifact where the references are
// machine-usable.
func TestTheRendererPrintsNoEvidenceIdentifier(t *testing.T) {
	for _, name := range productionFiles(t) {
		file := parseFile(t, name)

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || pkg.Name != "fmt" {
				return true
			}
			for _, arg := range call.Args {
				if mentionsIdentifier(arg) {
					t.Errorf("%s: fmt.%s formats an evidence identifier into the output",
						name, selector.Sel.Name)
				}
			}
			return true
		})
	}
}
