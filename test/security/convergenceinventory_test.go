package security_test

import (
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Phase 10.2A: the convergence inventory, kept honest by the compiler rather
// than by a document.
//
// # What this exists to prevent
//
// Two rules that can reach one finding code about one subject are *candidates*
// for convergence, and whether the merged result is honest depends on facts no
// reviewer can hold in their head across four services and thirty rules. Phase
// 10.2A inventoried every such pair mechanically and found exactly one, and the
// inventory is only worth having if it cannot silently grow.
//
// So the audit is a test. It parses every diagnosis package, attributes every
// finding code to the rules that can construct it — following intra-package
// calls and the package-level claim tables the services keep them in — and fails
// when a code is reachable from more than one rule and is not written down
// below with the reason it is safe.
//
// # What it deliberately does not do
//
// It cannot see a *single* rule producing two findings with one identity, which
// is how all three Phase 10.2A defects actually arose. Static analysis cannot
// answer that: it depends on how many evidence nodes a run produces. The safety
// net for that case is not this test — it is the merge preconditions themselves
// (ADR 0081 section 2.2b), which turn "two claims one identity" into two
// findings rather than into one invented one. This test guards the other half:
// that a *new* cross-rule pair arrives with a decision rather than by accident.
//
// The list below is therefore an inventory and not a permission slip.

// diagnosisPackages are the packages that hold rules.
var diagnosisPackages = []string{
	"internal/diagnosis",
	"internal/diagnosis/transport",
	"internal/diagnosis/kafka",
	"internal/diagnosis/postgres",
	"internal/diagnosis/redis",
	"internal/diagnosis/rabbitmq",
}

// knownConvergentCodes is every finding code reachable from more than one rule,
// with why publishing one finding for it is honest.
//
// A code appearing here has been reasoned about. A code appearing in the scan
// and not here fails the test, which is the point.
var knownConvergentCodes = map[string]string{
	"POSTGRES_CONNECTION_NOT_PERMITTED": "" +
		"postgres/startup anchors it at L4 and postgres/authentication at L5, deliberately " +
		"(internal/diagnosis/postgres/shared.go). Layer is a merge precondition, so the two " +
		"never converge and each is filed where its rule observed it. Phase 10.1B found this " +
		"one by measuring what a tie-break did to it.",
}

// TestTheConvergenceInventoryIsComplete is the audit, run as a test.
func TestTheConvergenceInventoryIsComplete(t *testing.T) {
	found := map[string][]string{}
	attributed := 0
	declared := 0

	for _, pkg := range diagnosisPackages {
		codes, rules, byCode := attributeCodesToRules(t, pkg)
		declared += len(codes)

		seen := map[string]bool{}
		for code, owners := range byCode {
			seen[code] = true
			if len(owners) > 1 {
				sort.Strings(owners)
				found[code] = owners
			}
		}
		attributed += len(seen)

		// Non-vacuity, per package: every declared code must be attributed to at
		// least one rule. A scan that attributed nothing would report no
		// convergence for the best possible reason and the worst possible one.
		for _, code := range codes {
			if !seen[code] {
				t.Errorf("%s declares %s and no rule in it can construct one; either the "+
					"code is dead or this scan cannot see how it is produced, and both "+
					"make the inventory below meaningless", pkg, code)
			}
		}
		if len(rules) == 0 {
			t.Errorf("%s holds no rule at all; the scan is looking in the wrong place", pkg)
		}
		t.Logf("%-32s %2d rules, %2d codes", pkg, len(rules), len(codes))
	}

	if declared == 0 || attributed == 0 {
		t.Fatal("the scan found no codes at all; every assertion here would be vacuous")
	}
	t.Logf("attributed %d of %d declared finding codes", attributed, declared)

	for code, owners := range found {
		if _, known := knownConvergentCodes[code]; !known {
			t.Errorf("%s is reachable from %v.\n\n"+
				"Two rules that can reach one code about one subject are convergence "+
				"candidates. Merging is safe only when they agree about every field a "+
				"merged finding *takes* rather than reconciles — code, subject, layer, "+
				"discriminator, summary and detail (ADR 0081 sections 2.2a and 2.2b) — "+
				"and when they do not, the report carries both findings.\n\n"+
				"Neither outcome is wrong, and both need a decision. Add the code to "+
				"knownConvergentCodes with the reason, or give the two rules distinct "+
				"codes.", code, owners)
		}
	}
	for code := range knownConvergentCodes {
		if _, still := found[code]; !still {
			t.Errorf("%s is listed as convergent and is no longer reachable from two "+
				"rules; delete the entry so the list keeps meaning something", code)
		}
	}
}

// attributeCodesToRules parses one package and maps each finding code to the
// rules that can construct it.
//
// It follows intra-package calls from each exported rule entry point, and treats
// a package-level var as a node in that graph — which is how the service claim
// tables (`protocolClaims`, the RabbitMQ and Redis equivalents) get attributed
// to the rule that reads them. Without that the scan silently under-reports:
// the first version of it attributed 5 of Kafka's 15 codes and confidently
// found no convergence anywhere.
func attributeCodesToRules(t *testing.T, pkg string) (codes, rules []string, byCode map[string][]string) {
	t.Helper()

	files := productionGoFiles(t, pkg)

	constants := map[string]string{}
	for _, path := range files {
		ast.Inspect(parseFile(t, path), func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok || vs.Type == nil {
				return true
			}
			if sel, ok := vs.Type.(*ast.SelectorExpr); !ok || sel.Sel.Name != "FindingCode" {
				return true
			}
			for i, name := range vs.Names {
				if i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok {
						constants[name.Name] = strings.Trim(lit.Value, `"`)
					}
				}
			}
			return true
		})
	}
	for _, lit := range constants {
		codes = append(codes, lit)
	}
	sort.Strings(codes)

	refs := map[string]map[string]bool{} // node -> identifiers it names
	owns := map[string]map[string]bool{} // node -> codes it names directly
	collect := func(node ast.Node, name string) {
		if refs[name] == nil {
			refs[name] = map[string]bool{}
			owns[name] = map[string]bool{}
		}
		ast.Inspect(node, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if lit, ok := constants[x.Name]; ok {
					owns[name][lit] = true
				}
				refs[name][x.Name] = true
			case *ast.SelectorExpr:
				refs[name]["(m)"+x.Sel.Name] = true
			}
			return true
		})
	}

	for _, path := range files {
		for _, d := range parseFile(t, path).Decls {
			switch decl := d.(type) {
			case *ast.GenDecl:
				if decl.Tok != token.VAR {
					continue
				}
				for _, spec := range decl.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, name := range vs.Names {
						collect(vs, name.Name)
					}
				}
			case *ast.FuncDecl:
				name := decl.Name.Name
				if decl.Recv != nil {
					name = "(m)" + name
				}
				collect(decl, name)
				if decl.Recv == nil && ast.IsExported(decl.Name.Name) &&
					decl.Type.Params != nil && len(decl.Type.Params.List) == 1 &&
					strings.Contains(typeName(decl.Type.Params.List[0].Type), "RuleContext") {
					rules = append(rules, decl.Name.Name)
				}
			}
		}
	}
	sort.Strings(rules)

	byCode = map[string][]string{}
	for _, rule := range rules {
		for code := range reachableCodes(rule, refs, owns) {
			byCode[code] = append(byCode[code], rule)
		}
	}
	return codes, rules, byCode
}

// productionGoFiles lists one package's non-test sources, in a stable order.
//
// It enumerates and parses file by file rather than calling parser.ParseDir,
// which Go 1.25 deprecated because it ignores build tags. No diagnosis package
// carries one — diagnosis is pure and platform-independent by construction — so
// the distinction does not arise here, and reusing the repository's existing
// parseFile keeps one parser configuration across every AST guard.
func productionGoFiles(t *testing.T, pkg string) []string {
	t.Helper()

	dir := filepath.Join(repositoryRoot(t), pkg)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	if len(out) == 0 {
		t.Fatalf("no production file was found in %s; the scan would be vacuous", pkg)
	}
	sort.Strings(out)
	return out
}

// reachableCodes walks the reference graph from one rule.
func reachableCodes(start string, refs, owns map[string]map[string]bool) map[string]bool {
	out := map[string]bool{}
	seen := map[string]bool{}

	var walk func(string)
	walk = func(node string) {
		if seen[node] {
			return
		}
		seen[node] = true
		for code := range owns[node] {
			out[code] = true
		}
		for next := range refs[node] {
			if _, known := refs[next]; known {
				walk(next)
			}
		}
	}
	walk(start)
	return out
}

// The parameter type is rendered by typeName in diagnosticcore_test.go, which
// already does exactly this for the RuleContext field-set assertion.

// TestTheInventoryScanCanFindConvergence is the non-vacuity proof.
//
// A scan that attributed no code to two rules would pass the inventory above for
// the wrong reason and look identical to one that passes correctly. This
// requires the scan to find the one pair that really exists.
func TestTheInventoryScanCanFindConvergence(t *testing.T) {
	_, _, byCode := attributeCodesToRules(t, "internal/diagnosis/postgres")

	owners := byCode["POSTGRES_CONNECTION_NOT_PERMITTED"]
	sort.Strings(owners)
	if !slices.Equal(owners, []string{"Authentication", "Startup"}) {
		t.Fatalf("the scan attributed POSTGRES_CONNECTION_NOT_PERMITTED to %v, want both "+
			"postgres rules; if it cannot see this pair it can see none of them", owners)
	}
}

// TestTheInventoryScanSeesThroughAClaimTable is the second non-vacuity proof,
// and it guards the exact blind spot the first version of this scan had.
//
// Kafka keeps eleven of its codes in a package-level map keyed by (step, state,
// failure class). A scan that only walked function bodies attributed one of the
// eleven and reported the package clean.
func TestTheInventoryScanSeesThroughAClaimTable(t *testing.T) {
	codes, rules, byCode := attributeCodesToRules(t, "internal/diagnosis/kafka")

	if len(codes) != 15 {
		t.Errorf("the Kafka package declares %d codes, want 15", len(codes))
	}
	if len(rules) != 5 {
		t.Errorf("the Kafka package exports %d rules, want 5", len(rules))
	}
	owners := byCode["KAFKA_METADATA_NOT_COMPLETED"]
	if !slices.Equal(owners, []string{"Protocol"}) {
		t.Fatalf("KAFKA_METADATA_NOT_COMPLETED is attributed to %v, want [Protocol]; it "+
			"is only reachable through the package-level claim table, so this failing "+
			"means the scan cannot see a table at all", owners)
	}
}
