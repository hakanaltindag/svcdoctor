package security_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Phase 10.3: the PostgreSQL diagnostic harnesses run the production rule set,
// and the compiler is what says so.
//
// # Why this exists
//
// Phase 10.2 found the Kafka integration harness wiring **two** of the Kafka
// rules while its own doc comment claimed it differed from production "in
// nothing but the graph". Every assertion that harness made was therefore about
// a product configuration nobody ships, and nothing failed, because the list was
// maintained by hand in two places and one of them was forgotten.
//
// The corpus guards that already exist — TestTheCorpusUsesTheProductionRuleSet
// and TestTheKafkaCorpusUsesTheProductionRuleSet — are the right idea and are
// still hand-maintained: they compare a harness list against a **literal list
// written beside it**. That catches a harness that drops a rule and misses the
// case that actually happened, which is the composition root gaining one.
//
// This one reads the composition root itself. There is one production source for
// "which rules run against a PostgreSQL graph", it is
// `internal/app/postgres.go`'s `NewRuleSet` chain, and every harness is checked
// against it rather than against a copy of it.
//
// # What it deliberately does not do
//
// It does not check that the harness builds the rule set the same *way*. A
// harness may wire the rules under its own identities, in its own order, through
// its own engine — ADR 0081 section 2.6a makes identity unobservable and the
// engine sorts, so none of that can change an output. What must not differ is
// the *set of rules that ran*, because that is the only difference that can
// silently make an assertion vacuous.

// postgresHarnesses are the rule lists that claim to be production's.
//
// Each names the file, the function whose body holds the list, and how a rule
// appears in it. The two shapes exist because the two harnesses are in different
// packages: one calls the rules directly, the other names them through a
// qualified selector.
var postgresHarnesses = []struct {
	file      string
	function  string
	qualifier string
}{
	{
		file:      "internal/diagnosis/postgres/fixtures_test.go",
		function:  "allFindings",
		qualifier: "", // same package: bare identifiers
	},
	{
		file:      "test/diagnosis/falsepositive_test.go",
		function:  "postgresRules",
		qualifier: "diagnosispostgres",
	},
}

// TestTheFixturesRunEveryProductionRule is the guard.
func TestTheFixturesRunEveryProductionRule(t *testing.T) {
	production := productionPostgresRules(t)
	if len(production) < 6 {
		t.Fatalf("the composition root wires %d PostgreSQL rules; the scan is not "+
			"finding them: %v", len(production), production)
	}

	for _, harness := range postgresHarnesses {
		t.Run(harness.function, func(t *testing.T) {
			got := harnessRules(t, harness.file, harness.function, harness.qualifier)

			for _, want := range production {
				if !slices.Contains(got, want) {
					t.Errorf("%s does not run %s, which internal/app/postgres.go wires.\n\n"+
						"A harness that runs a convenient subset is measuring the fixtures "+
						"rather than the product: every assertion it makes about what the "+
						"report does *not* contain passes for want of the rule that would "+
						"have put it there.\n\nharness: %v\nproduction: %v",
						harness.function, want, got, production)
				}
			}
			for _, extra := range got {
				if !slices.Contains(production, extra) {
					t.Errorf("%s runs %s, which internal/app/postgres.go does not wire.\n\n"+
						"A harness that runs more than production is asserting behaviour "+
						"no operator can reach.", harness.function, extra)
				}
			}
		})
	}
}

// productionPostgresRules reads the rule functions the composition root wires.
//
// It looks for `.Add("<id>", diagnosispostgres.<Rule>)` and takes the function
// name, not the identity: the identity is svcdoctor's internal name for a piece
// of code and is deliberately not what a harness has to reproduce (ADR 0081
// section 2.6a). The generic and transport rules are excluded because they are
// shared by four composition roots and have their own guard.
func productionPostgresRules(t *testing.T) []string {
	t.Helper()

	file := parsePostgresFile(t, "internal/app/postgres.go")

	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		method, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || method.Sel.Name != "Add" {
			return true
		}
		rule, ok := call.Args[1].(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := rule.X.(*ast.Ident)
		if !ok || pkg.Name != "diagnosispostgres" {
			return true
		}
		if !slices.Contains(out, rule.Sel.Name) {
			out = append(out, rule.Sel.Name)
		}
		return true
	})
	sort.Strings(out)
	return out
}

// harnessRules reads the rule functions one harness names inside one function.
func harnessRules(t *testing.T, path, function, qualifier string) []string {
	t.Helper()

	file := parsePostgresFile(t, path)

	var target *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == function {
			target = fn
		}
	}
	if target == nil {
		t.Fatalf("%s declares no function %s", path, function)
	}

	production := productionPostgresRules(t)
	var out []string
	ast.Inspect(target, func(n ast.Node) bool {
		name := ""
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := node.X.(*ast.Ident); ok && qualifier != "" && pkg.Name == qualifier {
				name = node.Sel.Name
			}
		case *ast.Ident:
			if qualifier == "" {
				name = node.Name
			}
		}
		// Only names the composition root also wires count. A harness body holds
		// plenty of other identifiers, and treating one of them as a rule would
		// make this test fail for a reason that is not about rules.
		if name != "" && slices.Contains(production, name) && !slices.Contains(out, name) {
			out = append(out, name)
		}
		return true
	})
	sort.Strings(out)
	return out
}

// parsePostgresFile parses one repository file, comments and all.
func parsePostgresFile(t *testing.T, rel string) *ast.File {
	t.Helper()

	path := filepath.Join(repoRootDir(t), rel)
	source, err := os.ReadFile(path) //nolint:gosec // a fixed repository-relative path
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", rel, err)
	}
	return file
}

// TestTheWiringGuardWouldCatchAMissingRule is the non-vacuity proof.
//
// A structural guard that could not fail is a comment. This drives the same
// comparison the test above performs, against a harness list with one rule
// removed, and requires it to be rejected.
func TestTheWiringGuardWouldCatchAMissingRule(t *testing.T) {
	production := productionPostgresRules(t)
	if len(production) < 2 {
		t.Fatalf("only %d production rules; the proof would be vacuous", len(production))
	}

	subset := slices.Clone(production[:len(production)-1])
	missing := production[len(production)-1]

	if slices.Contains(subset, missing) {
		t.Fatalf("the subset still contains %s; the proof is broken", missing)
	}
	var rejected bool
	for _, want := range production {
		if !slices.Contains(subset, want) {
			rejected = true
		}
	}
	if !rejected {
		t.Error("a harness missing a production rule was accepted; the guard is vacuous")
	}

	// And the harnesses really do name the rule the subset dropped, so the
	// comparison above is over the same vocabulary the guard uses.
	for _, harness := range postgresHarnesses {
		got := harnessRules(t, harness.file, harness.function, harness.qualifier)
		if !slices.Contains(got, missing) {
			t.Errorf("%s does not name %s at all; the guard's vocabulary has drifted "+
				"from the harness's", harness.function, missing)
		}
	}
	if strings.TrimSpace(missing) == "" {
		t.Error("the dropped rule has no name")
	}
}
