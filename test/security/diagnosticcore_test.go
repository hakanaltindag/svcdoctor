package security_test

import (
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
)

// Phase 10.1a: the structural guards over the generic diagnostic core.
//
// The reasoning layer is where "generic" quietly stops being true. A service
// name reaching internal/diagnosis would not break a test anywhere else — the
// findings would be right, the reports would be right — and the next service
// would arrive to find the engine already knows what a broker is.
//
// Every guard here has a matching non-vacuity proof, because a structural test
// that scans an empty list passes forever and looks exactly like one that passes
// correctly.

// genericDiagnosisPackage is the one package these guards are about.
//
// Its subpackages are service rule packages by design and are excluded: it is
// their job to know a service.
const genericDiagnosisPackage = "internal/diagnosis"

// serviceWords are the names the generic core must not know.
//
// The list is products and their vocabularies rather than a general word list.
// The goal is architectural ownership, not text censorship.
var serviceWords = []string{
	"kafka", "postgres", "postgresql", "redis", "valkey", "rabbitmq", "lavinmq",
	"redpanda", "amqp", "resp", "sqlstate", "sasl", "scram",
}

// genericDiagnosisFiles returns the production files of internal/diagnosis
// itself, excluding its service subpackages.
func genericDiagnosisFiles(t *testing.T) []string {
	t.Helper()

	root := filepath.Join(repositoryRoot(t), genericDiagnosisPackage)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading %s: %v", root, err)
	}

	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(root, name))
	}
	if len(out) == 0 {
		t.Fatalf("no production file was found in %s; every guard below would pass vacuously",
			genericDiagnosisPackage)
	}
	slices.Sort(out)
	return out
}

// TestDIAG019TheGenericCoreNamesNoService is ADR 0080 section 2.3 and DIAG-019.
//
// # What it reads, and what it deliberately does not
//
// It reads the AST: identifiers, qualified selectors, string and character
// literals, and imports. It does **not** read comments, and that exclusion is
// intentional rather than a shortcut. This package's own doc.go argues at length
// about why a rule anchored at a service fact behaves differently from an
// unanchored one, and naming the services in that argument is what makes it
// legible. A guard that failed on it would be enforcing silence about the
// architecture rather than the architecture.
//
// The goal is ownership: no service name in a type, a function, a constant, a
// string the code compares against, or an import.
func TestDIAG019TheGenericCoreNamesNoService(t *testing.T) {
	for _, path := range genericDiagnosisFiles(t) {
		file := parseFile(t, path)

		for _, imported := range file.Imports {
			importPath := strings.Trim(imported.Path.Value, `"`)
			for _, word := range serviceWords {
				if strings.Contains(strings.ToLower(importPath), word) {
					t.Errorf("%s imports %s; the generic engine holds concepts, and a "+
						"service's vocabulary is the service's (ADR 0080 section 2.3)",
						relative(t, path), importPath)
				}
			}
		}

		ast.Inspect(file, func(node ast.Node) bool {
			var found, kind string
			switch n := node.(type) {
			case *ast.Ident:
				found, kind = n.Name, "identifier"
			case *ast.BasicLit:
				if n.Kind != token.STRING && n.Kind != token.CHAR {
					return true
				}
				found, kind = strings.Trim(n.Value, "\"`'"), "literal"
			default:
				return true
			}

			lowered := strings.ToLower(found)
			for _, word := range serviceWords {
				if strings.Contains(lowered, word) {
					t.Errorf("%s names %q in a %s; a service name in the generic core is "+
						"the `if service == \"...\"` tree ADR 0009 exists to prevent",
						relative(t, path), found, kind)
				}
			}
			return true
		})
	}
}

// TestDIAG019TheServiceNameGuardCanFail is the non-vacuity proof for the guard
// above.
//
// It runs the same scan over a service rule package, where a service name is
// expected, and requires it to find one. A scan that found nothing anywhere
// would pass the guard above for the wrong reason.
func TestDIAG019TheServiceNameGuardCanFail(t *testing.T) {
	root := filepath.Join(repositoryRoot(t), genericDiagnosisPackage, "kafka")

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading %s: %v", root, err)
	}

	hits := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		ast.Inspect(parseFile(t, filepath.Join(root, name)), func(node ast.Node) bool {
			ident, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			for _, word := range serviceWords {
				if strings.Contains(strings.ToLower(ident.Name), word) {
					hits++
				}
			}
			return true
		})
	}

	if hits == 0 {
		t.Fatal("the same scan found no service name in a service rule package, so " +
			"TestDIAG019TheGenericCoreNamesNoService proves nothing")
	}
	t.Logf("the scan found %d service-named identifiers where they belong", hits)
}

// TestDIAG023AddingAServiceEditsNoGenericFile is DIAG-023, asserted the only way
// it can be: by showing the generic core imports nothing that would have to grow.
//
// ADR 0080 section 2.7 makes "no generic file is edited" step zero for a
// contributor adding a service. What makes it true is that the generic core
// imports only the evidence model — so there is no catalogue of codes, no
// registry file, and no dispatch table for a service to be added to.
func TestDIAG023AddingAServiceEditsNoGenericFile(t *testing.T) {
	allowed := map[string]bool{
		"github.com/hakanaltindag/svcdoctor/internal/domain": true,
	}

	found := 0
	for _, path := range genericDiagnosisFiles(t) {
		for _, imported := range parseFile(t, path).Imports {
			importPath := strings.Trim(imported.Path.Value, `"`)
			if !strings.Contains(importPath, ".") {
				continue // standard library
			}
			found++
			if !allowed[importPath] {
				t.Errorf("%s imports %s; the generic engine reads a frozen graph and "+
					"needs nothing else (ADR 0080 section 2.6)", relative(t, path), importPath)
			}
		}
	}
	if found == 0 {
		t.Fatal("no repository import was found at all; this guard would pass vacuously")
	}
}

// TestDIAG009TheGenericCorePerformsNoIOAndReadsNoSecret is DIAG-009 and DIAG-018,
// restated in the package rather than in .golangci.yml.
//
// depguard already denies most of this repository-wide, and the two enforcements
// are deliberately independent: a lint configuration is a file somebody can edit
// in the same commit as the violation, and a test is not.
//
// # Why time.Now is checked here rather than by forbidigo
//
// ADR 0080 section 2.2 specifies a forbidigo pattern for time.Now, on the
// grounds that banning the whole `time` package would ban durations too.
// forbidigo's forbid list is global in golangci-lint v2, so scoping it to this
// directory means granting an exclusion to every *other* directory — an
// enumeration a new top-level package escapes silently.
//
// The prohibition is implemented; the mechanism is an AST scan, which is scoped
// exactly and is the technique this repository already uses for the SASL core.
// The ADR's requirement is met and its suggested mechanism is not, which is
// recorded in docs/validation/PHASE101A_DIAGNOSTIC_CORE_VALIDATION.md.
func TestDIAG009TheGenericCorePerformsNoIOAndReadsNoSecret(t *testing.T) {
	// nolint:gosec // G101 is a false positive here: the map's *keys* are import
	// paths, one of which ends in "/secret" because that is the name of the
	// package a rule must not reach. There is no credential in this file.
	forbiddenImports := map[string]string{
		"net":           "diagnosis must not perform network I/O",
		"net/http":      "diagnosis must not perform network I/O",
		"crypto/tls":    "diagnosis must not perform TLS operations",
		"os":            "diagnosis must not read files, the environment or process state",
		"os/exec":       "diagnosis must not run commands",
		"io/ioutil":     "diagnosis must not read files",
		"math/rand":     "diagnosis must be deterministic",
		"math/rand/v2":  "diagnosis must be deterministic",
		"crypto/rand":   "diagnosis must be deterministic",
		"context":       "a rule has nothing to cancel; evaluation is in-memory and bounded",
		"database/sql":  "diagnosis performs no I/O",
		"encoding/json": "serializing a report is the report's job, not a rule's",
		"github.com/hakanaltindag/svcdoctor/internal/security":     "a secret has no role in a frozen graph and no path into one",
		"github.com/hakanaltindag/svcdoctor/internal/probe":        "diagnosis consumes normalized evidence, never a collector",
		"github.com/hakanaltindag/svcdoctor/internal/adapter":      "diagnosis knows no protocol",
		"github.com/hakanaltindag/svcdoctor/internal/render":       "producing findings and explaining them are different jobs",
		"github.com/hakanaltindag/svcdoctor/internal/platform":     "diagnosis reads no environment",
		"github.com/hakanaltindag/svcdoctor/internal/app":          "the composition root is above diagnosis, not beside it",
		"github.com/hakanaltindag/svcdoctor/internal/cli":          "a rule is called by the application, and does not reach back",
		"github.com/hakanaltindag/svcdoctor/internal/fleet/run":    "a rule reasons about one target",
		"github.com/hakanaltindag/svcdoctor/internal/fleet/secret": "the credential resolver is unreachable from reasoning",
	}

	// Calls that would make a rule's output depend on when it ran, or reach
	// state no frozen graph carries.
	forbiddenCalls := map[string]string{
		"time.Now":        "a rule reads recorded timestamps; a rule that reads the clock is a rule whose output depends on when it ran",
		"time.Since":      "the same, wearing a different name",
		"os.Getenv":       "diagnosis reads no environment",
		"os.ReadFile":     "diagnosis reads no files",
		"security.Reveal": "a rule cannot open a secret, and has none to open",
		"rand.Int":        "diagnosis must be deterministic",
		"rand.Intn":       "diagnosis must be deterministic",
		"exec.Command":    "diagnosis runs no commands",
		"net.Dial":        "diagnosis opens no sockets",
		"http.Get":        "diagnosis performs no network I/O",
	}

	scanned := 0
	for _, path := range genericDiagnosisFiles(t) {
		file := parseFile(t, path)
		scanned++

		for _, imported := range file.Imports {
			importPath := strings.Trim(imported.Path.Value, `"`)
			if why, banned := forbiddenImports[importPath]; banned {
				t.Errorf("%s imports %s: %s", relative(t, path), importPath, why)
			}
		}

		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if why, banned := forbiddenCalls[selectorName(call.Fun)]; banned {
				t.Errorf("%s calls %s: %s", relative(t, path), selectorName(call.Fun), why)
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("no file was scanned; this guard would pass vacuously")
	}
	t.Logf("scanned %d generic diagnosis files against %d forbidden imports and %d forbidden calls",
		scanned, len(forbiddenImports), len(forbiddenCalls))
}

// TestDIAG017RuleContextCarriesExactlyThreeFields is DIAG-017.
//
// ADR 0080 section 2.1 makes RuleContext's smallness the security model: a rule
// receives a frozen graph, a vantage and a boolean, and there is nothing there
// to dial, open or reveal. A fourth field is how that stops being true, and it
// would arrive looking harmless.
//
// The field set is asserted by name and by type, so widening it is a decision
// somebody has to make on purpose.
func TestDIAG017RuleContextCarriesExactlyThreeFields(t *testing.T) {
	want := map[string]string{
		"Graph":      "domain.Graph",
		"Vantage":    "domain.Vantage",
		"Incomplete": "bool",
	}

	got := map[string]string{}
	found := false
	for _, path := range genericDiagnosisFiles(t) {
		ast.Inspect(parseFile(t, path), func(node ast.Node) bool {
			spec, ok := node.(*ast.TypeSpec)
			if !ok || spec.Name.Name != "RuleContext" {
				return true
			}
			structType, ok := spec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("RuleContext is not a struct")
			}
			found = true
			for _, field := range structType.Fields.List {
				for _, name := range field.Names {
					got[name.Name] = typeName(field.Type)
				}
			}
			return false
		})
	}

	if !found {
		t.Fatal("RuleContext was not found; this guard would pass vacuously")
	}
	if len(got) != len(want) {
		t.Fatalf("RuleContext has %d fields %v, want exactly %v.\n\n"+
			"Its smallness is the security model (ADR 0080 sections 2.1 and 5). A "+
			"context.Context, a ServiceID, a credential, a clock or a configuration "+
			"handle on this struct is a rule that can do something a rule must not.",
			len(got), got, want)
	}
	for name, wantType := range want {
		if gotType, present := got[name]; !present || gotType != wantType {
			t.Errorf("RuleContext.%s is %q, want %q", name, gotType, wantType)
		}
	}
}

// TestDIAG041ProductionEvaluatesRatherThanDiagnoses pins the half of ADR 0083
// section 2.3 that a convenience method could quietly undo.
//
// Engine.Diagnose returns findings and drops the rule-failure list. That is
// right for a rule test, which has no run to mark incomplete, and wrong for
// production, where discarding it would turn a diagnostic defect into a silently
// shorter report with a clean exit code.
func TestDIAG041ProductionEvaluatesRatherThanDiagnoses(t *testing.T) {
	scanned := 0
	for _, pkg := range allProductionPackages(t) {
		if pkg == genericDiagnosisPackage {
			continue // Diagnose is defined there, in terms of Evaluate
		}
		for _, path := range productionFilesIn(t, pkg) {
			scanned++
			ast.Inspect(parseFile(t, path), func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "Diagnose" {
					return true
				}
				t.Errorf("%s calls Engine.Diagnose; production must call Evaluate, "+
					"because dropping the rule-failure list turns a diagnostic defect "+
					"into a silently shorter report (ADR 0083 section 2.3)", relative(t, path))
				return true
			})
		}
	}
	if scanned == 0 {
		t.Fatal("no production file was scanned; this guard would pass vacuously")
	}
}

// TestDIAG036EveryProducedRecommendationIsAlreadySafe runs the Phase 10.1a
// action validator over every recommendation the production rules construct.
//
// The validator is unwired: domain.Recommendation gains no field in this phase,
// so nothing enforces it yet. What this establishes is that adopting it in Phase
// 10.1b changes no existing string — the guard can be turned on without a single
// finding being reworded, which is what makes the adoption a wiring change
// rather than a content one.
func TestDIAG036EveryProducedRecommendationIsAlreadySafe(t *testing.T) {
	actions := producedRecommendationActions(t)
	if len(actions) == 0 {
		t.Fatal("no recommendation text was found at all; this guard would pass vacuously")
	}

	for action, where := range actions {
		if err := diagnosis.ValidateActionText(action); err != nil {
			t.Errorf("%s produces the recommendation %q, which the Phase 10.1a safety "+
				"validator refuses: %v.\n\n"+
				"Adopting ADR 0082 section 2.3 rule 3 in Phase 10.1b would require "+
				"rewording it, which makes that phase a content change rather than a "+
				"wiring one.", where, action, err)
		}
	}
	t.Logf("%d distinct recommendation strings are already safe under the "+
		"Phase 10.1a validator", len(actions))
}

// producedRecommendationActions collects the recommendation text every rule
// package declares.
//
// Every rule in the tree builds its recommendations from a `recommend<Name>`
// constant rather than from a literal at the call site, so the constants are the
// surface. They are frequently assembled by concatenation across several lines,
// which is why the parts are joined in source order rather than collected
// separately: half a sentence would be validated against a rule about how a
// sentence begins.
func producedRecommendationActions(t *testing.T) map[string]string {
	t.Helper()

	out := map[string]string{}
	for _, pkg := range allProductionPackages(t) {
		if !strings.HasPrefix(pkg, genericDiagnosisPackage) {
			continue
		}
		for _, path := range productionFilesIn(t, pkg) {
			ast.Inspect(parseFile(t, path), func(node ast.Node) bool {
				spec, ok := node.(*ast.ValueSpec)
				if !ok {
					return true
				}
				for i, name := range spec.Names {
					if !strings.HasPrefix(name.Name, "recommend") || i >= len(spec.Values) {
						continue
					}
					if text, ok := joinedStringLiteral(spec.Values[i]); ok {
						out[text] = relative(t, path) + " " + name.Name
					}
				}
				return true
			})
		}
	}
	return out
}

// joinedStringLiteral renders an expression built only from string literals and
// "+", and reports whether it was one.
//
// Anything else — a function call, a variable, a format string — is not a
// constant this guard can read, and returning false is the honest answer. No
// such recommendation exists today, and TestDIAG036EveryProducedRecommendationIsAlreadySafe
// fails if the whole collection comes back empty.
func joinedStringLiteral(expr ast.Expr) (string, bool) {
	switch node := expr.(type) {
	case *ast.BasicLit:
		if node.Kind != token.STRING {
			return "", false
		}
		text, err := strconv.Unquote(node.Value)
		if err != nil {
			return "", false
		}
		return text, true

	case *ast.BinaryExpr:
		if node.Op != token.ADD {
			return "", false
		}
		left, ok := joinedStringLiteral(node.X)
		if !ok {
			return "", false
		}
		right, ok := joinedStringLiteral(node.Y)
		if !ok {
			return "", false
		}
		return left + right, true

	case *ast.ParenExpr:
		return joinedStringLiteral(node.X)

	default:
		return "", false
	}
}

// typeName renders a field's type as source text, for the field-set assertion.
func typeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if pkg, ok := t.X.(*ast.Ident); ok {
			return pkg.Name + "." + t.Sel.Name
		}
		return t.Sel.Name
	case *ast.StarExpr:
		return "*" + typeName(t.X)
	default:
		return "<unrecognized>"
	}
}
