package security

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Phase 10.4B architecture guards, ADR 0086.
//
// Three of these assert an **absence**, which is unusual and deliberate. An
// absence is exactly what gets filled in by accident: the phase's whole
// discipline is that next-evidence plumbing landed and a hypothesis-grouping
// engine did not, and nothing but a failing build keeps those two apart six
// months from now.
//
// They parse Go rather than grep it. A grep for "IndistinguishableSets" is
// defeated by naming the function something else; a scan for a function whose
// signature groups findings is not.

// repoRoot walks up to the module root so the guards can address packages by
// their repository-relative path.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found above the working directory")
	return ""
}

// productionFiles parses every non-test Go file under dir, recursively.
func productionFiles(t *testing.T, root, dir string) map[string]*ast.File {
	t.Helper()
	out := map[string]*ast.File{}
	fset := token.NewFileSet()
	base := filepath.Join(root, dir)
	err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			return perr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		out[rel] = f
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	if len(out) == 0 {
		t.Fatalf("no production files found under %s; the guard would pass vacuously", dir)
	}
	return out
}

// TestExactlyOneAdviceProjectionPathExists is the anti-drift guard for the
// conversion this phase introduced.
//
// Before Phase 10.4B there were two projections, one copied into each service
// package that had classified advice, and **both dropped four of the five
// fields**. That is not a hypothetical failure mode; it is the defect the phase
// was opened to fix. Two independent mappings can drift apart, and the only
// robust answer is that there is one.
//
// The guard is structural: exactly one production function may construct a
// classified recommendation, and it must be the method on Advice.
func TestExactlyOneAdviceProjectionPathExists(t *testing.T) {
	root := repoRoot(t)

	var sites []string
	for _, dir := range []string{"internal"} {
		for path, file := range productionFiles(t, root, dir) {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "NewClassifiedRecommendation" {
					return true
				}
				sites = append(sites, path)
				return true
			})
			// The unqualified call inside internal/domain itself.
			if strings.HasPrefix(path, filepath.Join("internal", "domain")) {
				ast.Inspect(file, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					if id, ok := call.Fun.(*ast.Ident); ok &&
						id.Name == "NewClassifiedRecommendation" {
						sites = append(sites, path)
					}
					return true
				})
			}
		}
	}

	// Two legitimate sites: the projection itself, and redaction rebuilding a
	// value it was given. Redaction is not a second *mapping* — it reproduces a
	// classification it did not choose — but it does call the constructor, and
	// naming it here is more honest than special-casing it away.
	want := map[string]string{
		filepath.Join("internal", "diagnosis", "advice.go"): "Advice.Recommendation, " +
			"the one projection",
		filepath.Join("internal", "security", "redaction", "redact.go"): "rebuilding a " +
			"recommendation it was handed, preserving the classification it did not choose",
	}
	seen := map[string]bool{}
	for _, site := range sites {
		if _, allowed := want[site]; !allowed {
			t.Errorf("%s constructs a classified recommendation.\n\n"+
				"There is exactly one projection from advice to a report "+
				"recommendation, Advice.Recommendation. A second one is how the "+
				"four fields got dropped twice before Phase 10.4B (ADR 0086).", site)
		}
		seen[site] = true
	}
	for site, why := range want {
		if !seen[site] {
			t.Errorf("%s no longer constructs a classified recommendation (%s); "+
				"if the path moved, move this guard with it", site, why)
		}
	}
}

// TestNoServiceLocalAdviceProjectionHelperExists is NBE-044's sibling: the two
// deleted helpers must not come back.
func TestNoServiceLocalAdviceProjectionHelperExists(t *testing.T) {
	root := repoRoot(t)
	// No file is exempt, including advice.go. The generic package is not a safe
	// place for a lossy helper either — a mutation planted one there and the
	// first cut of this guard skipped the file it was hiding in.
	for path, file := range productionFiles(t, root, filepath.Join("internal", "diagnosis")) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			name := fn.Name.Name
			if strings.Contains(strings.ToLower(name), "projectadvice") {
				t.Errorf("%s declares %s.\n\n"+
					"Phase 10.4B deleted the two service-local projection helpers "+
					"because both silently dropped four of advice's five fields. "+
					"Use diagnosis.Recommend.", path, name)
			}
		}
	}
}

// TestNoHypothesisGroupingEngineExists is NBE-044, and it is the constraint
// ADR 0086 section 2.11 makes binding on this phase.
//
// Phase 10.4A measured that **no pair of competing hypotheses exists anywhere in
// the tree**, so a grouping engine would be a primitive manufacturing its own
// producer — the inversion ADR 0054 refuses. The identity mechanism is deferred
// to Phase 10.4C, which opens only when a service phase produces a real pair.
//
// This asserts an absence, so it is written to survive a rename: it looks for
// the *shape* — a production function that takes findings and returns groups of
// them — as well as for the names that were considered.
func TestNoHypothesisGroupingEngineExists(t *testing.T) {
	root := repoRoot(t)

	forbiddenNames := []string{
		"indistinguishableset", "hypothesisset", "hypothesisgroup", "groupbydiscriminator",
		"discriminatorid", "discriminatorkey", "discriminatoridentity",
	}

	for path, file := range productionFiles(t, root, "internal") {
		ast.Inspect(file, func(n ast.Node) bool {
			var name string
			switch decl := n.(type) {
			case *ast.FuncDecl:
				name = decl.Name.Name
			case *ast.TypeSpec:
				name = decl.Name.Name
			case *ast.Field:
				for _, id := range decl.Names {
					lower := strings.ToLower(id.Name)
					for _, bad := range forbiddenNames {
						if strings.Contains(lower, bad) {
							t.Errorf("%s declares a field %q; Phase 10.4C owns the "+
								"identity mechanism (ADR 0086 section 2.2a)", path, id.Name)
						}
					}
				}
				return true
			default:
				return true
			}
			lower := strings.ToLower(name)
			for _, bad := range forbiddenNames {
				if strings.Contains(lower, bad) {
					t.Errorf("%s declares %q.\n\n"+
						"No hypothesis-grouping engine and no discriminator identity "+
						"may exist before a real competing pair does (ADR 0086 "+
						"sections 2.2a, 2.3 and 2.11; NBE-044).", path, name)
				}
			}
			return true
		})
	}
}

// TestTheDiscriminatorIsNotAGroupingKey is the other half of the deferral.
//
// ADR 0086 section 2.2a withdrew byte-equal discriminator prose as a runtime
// identity, because Finding.Discriminator is human-facing text and a prose
// grouping key lets a wording-only edit change diagnostic behaviour — the
// coupling Phase 10.2A spent a phase removing.
//
// Convergence compares discriminators, which is allowed and is different in
// kind: there it is a **precondition that refuses to merge**, so prose drift
// yields two findings that each state what their rule stated. What may not
// appear is a discriminator used as a map key, which is what grouping looks
// like.
func TestTheDiscriminatorIsNotAGroupingKey(t *testing.T) {
	root := repoRoot(t)
	for path, file := range productionFiles(t, root, "internal") {
		ast.Inspect(file, func(n ast.Node) bool {
			mt, ok := n.(*ast.MapType)
			if !ok {
				return true
			}
			if strings.Contains(strings.ToLower(exprString(mt.Key)), "discriminator") {
				t.Errorf("%s keys a map on a discriminator.\n\n"+
					"A discriminator is prose. Using it as an identity makes a "+
					"wording edit a behaviour change (ADR 0086 section 2.2a).", path)
			}
			return true
		})
	}
}

// exprString renders an expression's identifier text well enough for a name
// check, without pulling in a printer.
func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.StarExpr:
		return exprString(v.X)
	default:
		return ""
	}
}
