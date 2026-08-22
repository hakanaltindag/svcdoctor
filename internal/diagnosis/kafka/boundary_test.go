package kafka

import (
	"go/ast"
	gobuild "go/build"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Boundary tests: the properties depguard also enforces, restated where a reader
// of this package will see them, plus the ones depguard cannot express.
//
// The duplication is deliberate. depguard fails CI; these fail the package's own
// test run, next to the code that must keep them.

// productionFiles returns this package's non-test sources.
//
// It asks go/build rather than reading the directory, because depguard denies
// this package the os import — including in tests, which is correct: a purity
// boundary with a hole for test files is a purity boundary that will grow one in
// production.
func productionFiles(t *testing.T) []string {
	t.Helper()

	pkg, err := gobuild.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("describing the package: %v", err)
	}
	if len(pkg.GoFiles) == 0 {
		t.Fatal("no production sources found")
	}
	return pkg.GoFiles
}

// parse reads one production source. Comments are deliberately not requested, so
// nothing below can match the prose that explains why the code does not do a
// thing.
func parse(t *testing.T, name string) *ast.File {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return file
}

// TestTheRuleImportsOnlyDomainAndTheKafkaVocabulary pins the dependency
// direction the whole phase turned on.
//
// diagnosis must not import the adapter, so the three shared constants moved to
// a leaf vocabulary package rather than the boundary being weakened to reach
// them (ADR 0034 section 19). Anything else appearing here would be a layer this
// package has no business touching.
func TestTheRuleImportsOnlyDomainAndTheKafkaVocabulary(t *testing.T) {
	allowed := map[string]bool{
		"github.com/hakanaltindag/svcdoctor/internal/domain":        true,
		"github.com/hakanaltindag/svcdoctor/internal/service/kafka": true,
	}

	for _, name := range productionFiles(t) {
		for _, imported := range parse(t, name).Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if !strings.Contains(path, "/") || !strings.Contains(path, ".") {
				continue // standard library
			}
			if !allowed[path] {
				t.Errorf("%s imports %s; diagnosis reads a frozen graph and nothing else", name, path)
			}
		}
	}
}

// TestTheRulePerformsNoIO restates the purity contract against the standard
// library packages that would break it.
func TestTheRulePerformsNoIO(t *testing.T) {
	forbidden := map[string]string{
		"net":           "diagnosis must not perform network I/O",
		"net/http":      "diagnosis must not perform network I/O",
		"crypto/tls":    "diagnosis must not perform TLS operations",
		"os":            "diagnosis must not read files, the environment or process state",
		"os/exec":       "diagnosis must not run commands",
		"math/rand":     "diagnosis must be deterministic",
		"math/rand/v2":  "diagnosis must be deterministic",
		"context":       "a rule has nothing to cancel; evaluation is in-memory and bounded",
		"time":          "a rule reads recorded timestamps; it must not consult the clock",
		"database/sql":  "diagnosis performs no I/O",
		"encoding/json": "serializing a report is the report's job, not a rule's",
	}

	for _, name := range productionFiles(t) {
		for _, imported := range parse(t, name).Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if why, banned := forbidden[path]; banned {
				t.Errorf("%s imports %s: %s", name, path, why)
			}
		}
	}
}

// TestTheRuleHasTheUnchangedContractShape proves no argument was added.
//
// A context, a ServiceID, a Vantage or a Report on this signature would each be
// a contract change to diagnosis.Rule, and none was needed: the graph carries
// everything the policy asks for.
func TestTheRuleHasTheUnchangedContractShape(t *testing.T) {
	var rule diagnosis.Rule = AdvertisedEndpointUnreachable

	signature := reflect.TypeOf(rule)
	if signature.NumIn() != 1 {
		t.Fatalf("the rule takes %d arguments, want 1", signature.NumIn())
	}
	if got, want := signature.In(0), reflect.TypeOf(domain.Graph{}); got != want {
		t.Errorf("argument = %s, want %s", got, want)
	}
	if signature.NumOut() != 1 {
		t.Fatalf("the rule returns %d values, want 1", signature.NumOut())
	}
	if got, want := signature.Out(0), reflect.TypeOf([]domain.Finding{}); got != want {
		t.Errorf("result = %s, want %s", got, want)
	}
}

// TestTheRuleDoesNotMutateTheGraph.
//
// Graph hands out copies of its edge slices and holds unexported fields, so the
// property is structural. This states it anyway, because "diagnosis consumes
// frozen evidence" is the contract most quietly broken by a helper that decided
// to normalize something in place.
func TestTheRuleDoesNotMutateTheGraph(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	unreachable(b, exchange, 2, "broker-2.internal:9093", "broker-2.internal", "10.20.0.2")
	graph := b.freeze()

	before := make([]string, 0, graph.Len())
	for _, node := range graph.Nodes() {
		before = append(before, node.String())
	}
	length := graph.Len()

	AdvertisedEndpointUnreachable(graph)

	if graph.Len() != length {
		t.Errorf("graph length changed from %d to %d", length, graph.Len())
	}
	after := make([]string, 0, graph.Len())
	for _, node := range graph.Nodes() {
		after = append(after, node.String())
	}
	for i := range before {
		if i < len(after) && before[i] != after[i] {
			t.Errorf("node %d changed: %q -> %q", i, before[i], after[i])
		}
	}
}

// TestNoIdentifierOrScopeIsParsed is the anchoring guarantee, checked against
// the source rather than against behaviour.
//
// Ownership comes from graph edges. An identifier is opaque (ADR 0019 has no
// decoder), a sweep scope must never be parsed for meaning (ADR 0032 section 5),
// and reading either for provenance is what keeps Origin deferred. A rule that
// started splitting strings would be inventing the fact it must not invent.
//
// The check runs over the AST, so it sees what the code names and not what the
// comments discuss — both files below argue about provenance at length and must
// not fail for saying so.
func TestNoIdentifierOrScopeIsParsed(t *testing.T) {
	forbidden := map[string]string{
		"strings.Split":      "an evidence identifier is opaque and has no decoder",
		"strings.SplitN":     "an evidence identifier is opaque and has no decoder",
		"strings.Cut":        "an evidence identifier is opaque and has no decoder",
		"strings.HasPrefix":  "graph edges say what a node derives from; a prefix does not",
		"strings.TrimPrefix": "graph edges say what a node derives from; a prefix does not",
		"strings.Contains":   "ownership is structural, never a substring match",
		"strings.Index":      "ownership is structural, never a substring match",
		"SweepScope":         "a scope labels an execution and must never be read for meaning",
		"Origin":             "provenance is not inferred, and no code path may need it",
	}

	for _, name := range productionFiles(t) {
		names := namesUsedIn(t, name)
		for pattern, why := range forbidden {
			if names[pattern] {
				t.Errorf("%s uses %s: %s", name, pattern, why)
			}
		}
	}
}

// namesUsedIn returns every identifier and qualified selector the file names.
func namesUsedIn(t *testing.T, name string) map[string]bool {
	t.Helper()

	out := map[string]bool{}
	ast.Inspect(parse(t, name), func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if qualifier, ok := node.X.(*ast.Ident); ok {
				out[qualifier.Name+"."+node.Sel.Name] = true
			}
			out[node.Sel.Name] = true
		case *ast.Ident:
			out[node.Name] = true
		}
		return true
	})
	return out
}

// TestTheScanSeesTheCode is the control for the test above: a scan that matched
// nothing because it parsed nothing would pass silently.
func TestTheScanSeesTheCode(t *testing.T) {
	names := namesUsedIn(t, "advertisedendpoint.go")
	for _, want := range []string{"AdvertisedEndpointUnreachable", "g.Nodes", "domain.Finding"} {
		if !names[want] {
			t.Errorf("the AST scan did not see %q; the boundary scan would be vacuous", want)
		}
	}
	if names["provenance"] {
		t.Error("the AST scan is reading comments")
	}
}
