package transport

import (
	"go/ast"
	gobuild "go/build"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Architecture guards for the first generic transport rules.
//
// This package is the one place a rule could stop being anchored: it is the only
// diagnosis package whose subject is not a service fact, so it is the only one
// where "just scan the graph for failed transport nodes" is even expressible. The
// guards below exist because that shortcut is easy, plausible, and wrong — it is
// the unanchored rule ADR 0017 declined, and it cannot tell an operator's target
// from a broker the cluster advertised.
//
// The file that used to live here asserted this package was empty. It has been
// replaced rather than deleted: the phase it guarded is over, and what it
// protected — that no claim arrives without a record deciding what it may say —
// is now protected by the allow-list in internal/vocabulary.

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

func parse(t *testing.T, name string) *ast.File {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return file
}

// namesUsedIn returns every identifier and qualified selector a file names.
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

// TestDiagnosisImportsOnlyTheEvidenceModel pins the layer boundary.
//
// depguard already denies the probe, adapter, render, platform and security
// imports repository-wide. This adds what depguard cannot express: that a rule
// which consumes a frozen graph needs nothing beyond the graph, the names on it,
// and the rule contract it satisfies — and that the composition root is above
// this package rather than beside it.
//
// # Why internal/diagnosis is on the list from Phase 10.1a
//
// ADR 0080 section 2.1 widened diagnosis.Rule from a graph to a RuleContext, so
// a rule package must name the type it accepts. ADR 0080 section 2.6 draws the
// direction that makes that safe: a rule package imports the engine, the engine
// imports no subpackage of its own, and a cycle is therefore impossible rather
// than merely avoided. The allowlist is what keeps the second half honest — an
// import of a *sibling* rule package would fail here, which is the coupling that
// would let one service's reasoning depend on another's.
func TestDiagnosisImportsOnlyTheEvidenceModel(t *testing.T) {
	allowed := map[string]bool{
		"github.com/hakanaltindag/svcdoctor/internal/diagnosis":  true,
		"github.com/hakanaltindag/svcdoctor/internal/domain":     true,
		"github.com/hakanaltindag/svcdoctor/internal/vocabulary": true,
	}

	for _, name := range productionFiles(t) {
		for _, imported := range parse(t, name).Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if !allowed[path] {
				t.Errorf("%s imports %s; a rule reads a frozen graph and needs nothing else",
					name, path)
			}
		}
	}
}

// TestNoIdentifierOrScopeIsParsedAndNoProvenanceIsNamed is the anchoring
// guarantee, checked against the source rather than against behaviour.
//
// Ownership comes from graph edges. An identifier is opaque (ADR 0019 defines no
// decoder), a sweep scope must never be read for meaning (ADR 0032 section 5),
// and `Origin` is the per-node provenance ADR 0042 section 10 showed is not
// needed here and REPORT_SCHEMA.md still defers. A rule that started splitting
// strings would be inventing the fact it must not invent.
//
// The scan runs over the AST, so it sees what the code names and not what the
// comments discuss — every file here argues about provenance at length and must
// not fail for saying so.
func TestNoIdentifierOrScopeIsParsedAndNoProvenanceIsNamed(t *testing.T) {
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
		"Provenance":         "the graph records derivation, never provenance",
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

// TestOwnershipIsNeverRootnessOrDescendants pins the two shortcuts that would
// silently break the boundary.
//
// `Parents` is how a rule would ask "is this node a root?", which is provenance
// read off graph shape. A recursive walk is how it would reach every descendant,
// which would swallow the Kafka advertised sweep sitting transitively below a
// bootstrap target.
//
// Neither is needed: the walk descends by direct child from a node it already
// knows the meaning of.
func TestOwnershipIsNeverRootnessOrDescendants(t *testing.T) {
	for _, name := range productionFiles(t) {
		names := namesUsedIn(t, name)
		if names["Parents"] {
			t.Errorf("%s calls Parents; asking what a node hangs from is asking for "+
				"provenance, and ownership descends from an anchor instead", name)
		}
		if names["BlockedBy"] {
			t.Errorf("%s calls BlockedBy; a blocked step is never a cause "+
				"(docs/FINDINGS.md section 11)", name)
		}

		// A recursive helper is the shape a descendant walk takes. Every
		// traversal here is a bounded descent written as nested loops.
		for _, decl := range parse(t, name).Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == fn.Name.Name {
					t.Errorf("%s: %s calls itself; requested-target ownership is a "+
						"bounded descent, never a descendant walk", name, fn.Name.Name)
				}
				return true
			})
		}
	}
}

// TestNoServiceKnowledgeExists pins service neutrality.
//
// These rules must work unchanged for Redis, RabbitMQ and MySQL. A service name
// in a predicate would make that false and would be the central conditional
// dispatch docs/ARCHITECTURE.md section 8 exists to prevent.
func TestNoServiceKnowledgeExists(t *testing.T) {
	forbidden := []string{"postgres", "kafka", "redis", "rabbitmq", "mysql", "elasticsearch"}

	for _, name := range productionFiles(t) {
		src := parse(t, name)

		ast.Inspect(src, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			lowered := strings.ToLower(ident.Name)
			for _, service := range forbidden {
				if strings.Contains(lowered, service) {
					t.Errorf("%s names %s; these rules are service-neutral", name, ident.Name)
				}
			}
			return true
		})

		// A service-shaped string constant is the other way the knowledge
		// arrives — a step name like "postgres.ssl_request" compared directly.
		ast.Inspect(src, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			lowered := strings.ToLower(lit.Value)
			for _, service := range forbidden {
				if strings.Contains(lowered, service) {
					t.Errorf("%s contains the literal %s; these rules are service-neutral",
						name, lit.Value)
				}
			}
			return true
		})
	}
}

// TestNoUnproducedTLSClassIsReferenced pins what ADR 0043 section 14's ban
// became once its reopen condition was met.
//
// That section banned every TLS reference here, because generic TLS had no
// producer and a claim for evidence that cannot occur is policy nobody can test.
// **ADR 0053 satisfied the reopen condition** — Kafka bootstrap composition
// produces a `tls.handshake` under a requested `tcp.connect` — so the six classes
// internal/probe/tls actually emits are now authorized, and tls.go maps them.
//
// The ban survives for the part that never had a producer. Three declared classes
// are emitted by nothing, verified against internal/probe/tls/handshake.go rather
// than assumed, and mapping one would authorize a claim for evidence no run can
// produce. Each would arrive here looking like a natural completion of the table.
//
// Comments may discuss them — tlsClaims explains at length why they are absent —
// so the scan reads code only.
func TestNoUnproducedTLSClassIsReferenced(t *testing.T) {
	for _, name := range productionFiles(t) {
		names := namesUsedIn(t, name)
		for _, banned := range []string{
			"FailureTLSVersionMismatch",
			"FailureTLSClientCertificateRequired",
			"FailureTLSClientCertificateRejected",
			// PostgreSQL's in-band negotiation is a different owner's node, and
			// naming it here would be the start of a service switch.
			"StepSSLRequest",
		} {
			if names[banned] {
				t.Errorf("%s names %s; it has no production producer, so no claim "+
					"may be authorized for it (ADR 0053 section 9)", name, banned)
			}
		}
	}
}

// TestExactlyEightFindingCodesAreDeclared pins the vocabulary of this package.
//
// The module-wide allow-list in internal/vocabulary checks that no *unauthorized*
// generic code exists anywhere. This checks the other direction locally: that
// this package declares eight and not nine, so a code added here has to be added
// to both places and cannot slip in as a local constant.
//
// Three from ADR 0043 and five from ADR 0053. The five are what the six produced
// TLS FailureClasses map to, with the two certificate-validity classes sharing
// one code.
func TestExactlyEightFindingCodesAreDeclared(t *testing.T) {
	declared := map[string]bool{}

	for _, name := range productionFiles(t) {
		ast.Inspect(parse(t, name), func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			sel, ok := spec.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "FindingCode" {
				return true
			}
			for _, value := range spec.Values {
				if lit, ok := value.(*ast.BasicLit); ok {
					declared[strings.Trim(lit.Value, `"`)] = true
				}
			}
			return true
		})
	}

	want := map[string]bool{
		string(CodeNameNotResolved):          true,
		string(CodeResolutionFailed):         true,
		string(CodeConnectionNotEstablished): true,

		string(CodeTLSEndpointDoesNotSpeakTLS): true,
		string(CodeTLSIdentityMismatch):        true,
		string(CodeTLSChainNotTrusted):         true,
		string(CodeTLSCertificateNotValidNow):  true,
		string(CodeTLSHandshakeNotCompleted):   true,
	}
	if len(declared) != len(want) {
		t.Errorf("declared %v, want exactly %v", declared, want)
	}
	for code := range want {
		if !declared[code] {
			t.Errorf("%s is not declared in this package", code)
		}
	}
}

// TestNoIOAndNoInit restates what a pure rule is not.
func TestNoIOAndNoInit(t *testing.T) {
	for _, name := range productionFiles(t) {
		src := parse(t, name)

		for _, decl := range src.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "init" {
				t.Errorf("%s declares init(); a rule set is wired explicitly, never as a "+
					"side effect", name)
			}
		}

		// SQL-shaped literals, on the same reasoning internal/app uses: the
		// layer most likely to add a health query is the one that must not.
		ast.Inspect(src, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			for _, fragment := range []string{"SELECT ", "INSERT ", "UPDATE ", "DELETE "} {
				if strings.Contains(lit.Value, fragment) {
					t.Errorf("%s contains a SQL-shaped literal %s", name, lit.Value)
				}
			}
			return true
		})
	}
}

// TestTheScanSeesTheCode is the control for every scan above.
//
// A scan that matched nothing because it parsed nothing would pass silently, and
// so would every guard resting on it.
func TestTheScanSeesTheCode(t *testing.T) {
	for _, c := range []struct {
		file string
		want []string
	}{
		{"tcp.go", []string{"TCP", "evaluateTCP", "collectSweeps", "domain.Finding"}},
		{"sweep.go", []string{"collectSweep", "g.Nodes", "g.Children", "g.Node"}},
		{"dns.go", []string{"DNS", "evaluateDNS", "domain.FindingCode"}},
	} {
		names := namesUsedIn(t, c.file)
		for _, want := range c.want {
			if !names[want] {
				t.Errorf("the AST scan of %s did not see %q; every boundary scan "+
					"resting on it would be vacuous", c.file, want)
			}
		}
		if names["unreachable"] {
			t.Errorf("the AST scan of %s is reading comments", c.file)
		}
	}
}

// TestTheRuleContractIsUnchanged pins that both rules satisfy diagnosis.Rule.
//
// It used to add that this package proved it without importing the engine, on
// the grounds that reaching back for the engine's type would be circular in
// spirit. Phase 10.1a settled that the other way: ADR 0080 section 2.1 widened
// the contract to a RuleContext, so a rule must name the type it accepts, and
// ADR 0080 section 2.6 draws the direction explicitly — a rule package imports
// the engine, the engine imports no subpackage of its own, and the cycle is
// impossible rather than avoided.
func TestTheRuleContractIsUnchanged(t *testing.T) {
	var rules []diagnosis.Rule
	rules = append(rules, DNS, TCP)

	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	for _, rule := range rules {
		if got := rule(rctx(domain.Graph{})); got != nil {
			t.Errorf("a rule returned %v for the zero graph, want nil", got)
		}
	}
}
