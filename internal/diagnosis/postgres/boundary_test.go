package postgres

import (
	"go/ast"
	gobuild "go/build"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
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

// TestTheRulesImportOnlyDomainAndThePostgreSQLVocabulary pins the dependency
// direction the phase turned on.
//
// diagnosis must not import the adapter, so the eight shared constants moved to
// a leaf vocabulary package rather than the boundary being weakened to reach
// them (ADR 0040 section 22). Anything else appearing here would be a layer this
// package has no business touching — the adapter and its wire package above all,
// because those hold protocol machinery, live connections and credentials.
func TestTheRulesImportOnlyDomainAndThePostgreSQLVocabulary(t *testing.T) {
	allowed := map[string]bool{
		"github.com/hakanaltindag/svcdoctor/internal/domain":           true,
		"github.com/hakanaltindag/svcdoctor/internal/service/postgres": true,
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

// TestTheRulesPerformNoIO restates the purity contract against the standard
// library packages that would break it.
func TestTheRulesPerformNoIO(t *testing.T) {
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
		"database/sql":  "diagnosis performs no I/O and executes no SQL",
		"encoding/json": "serializing a report is the report's job, not a rule's",
		"regexp":        "a rule reads typed evidence; it does not pattern-match prose",
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

// TestTheRulesReadOnlyTheAuthorizedAttributes pins the attribute surface.
//
// Four keys are authorized by ADR 0040 section 22, and a rule that started
// reading a fifth would be consuming evidence no record authorized it to read —
// the session parameters most of all, which is how a replica finding would
// arrive without a decision. The check is over the source rather than over
// behaviour, so it fails on the attempt rather than on a shape a test happened
// to cover.
func TestTheRulesReadOnlyTheAuthorizedAttributes(t *testing.T) {
	authorized := map[string]bool{
		"AttrSSLOffered":    true,
		"AttrAuthMethod":    true,
		"AttrSQLState":      true,
		"AttrErrorIsNative": true,
	}

	for _, name := range productionFiles(t) {
		ast.Inspect(parse(t, name), func(n ast.Node) bool {
			selector, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || pkg.Name != "servicepostgres" {
				return true
			}
			if strings.HasPrefix(selector.Sel.Name, "Attr") && !authorized[selector.Sel.Name] {
				t.Errorf("%s reads %s, which ADR 0040 section 22 does not authorize",
					name, selector.Sel.Name)
			}
			return true
		})
	}
}

// TestNoContractStringIsRespelled pins that step names and attribute keys come
// from the vocabulary package rather than from a literal.
//
// A re-spelled contract string is a rule that keeps compiling while it stops
// matching the evidence, which is the worst way for this to break: silently, and
// only against a real graph.
func TestNoContractStringIsRespelled(t *testing.T) {
	for _, name := range productionFiles(t) {
		ast.Inspect(parse(t, name), func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if strings.Contains(lit.Value, `"postgres.`) {
				t.Errorf("%s spells a contract string %s; take it from internal/service/postgres",
					name, lit.Value)
			}
			return true
		})
	}
}

// TestTheRulesSatisfyTheEngineContract is the compile-time proof that these are
// rules, without this package importing the engine to say so.
func TestTheRulesSatisfyTheEngineContract(t *testing.T) {
	engine := diagnosis.NewEngine(SSLRequest, Startup, Authentication, Session)

	if got := engine.RuleCount(); got != 4 {
		t.Fatalf("RuleCount = %d, want 4", got)
	}

	// And an empty graph produces nothing, which is the property a report of a
	// run that never reached PostgreSQL depends on.
	if findings := engine.Diagnose(domain.Graph{}); len(findings) != 0 {
		t.Errorf("an empty graph produced %v", codesOf(findings))
	}
}

// TestEveryAuthorizedCodeIsWellFormedAndNamespaced pins the public surface.
//
// Twelve codes, no thirteenth. The count is asserted so that adding one is a
// deliberate act rather than a drift, exactly as the FailureClass count guard
// works in internal/domain.
func TestEveryAuthorizedCodeIsWellFormedAndNamespaced(t *testing.T) {
	codes := []domain.FindingCode{
		CodeTLSDeclined,
		CodeStartupFailed,
		CodeConnectionNotPermitted,
		CodeCredentialsRejected,
		CodePeerVerificationFailed,
		CodeMechanismUnavailable,
		CodeUnsupportedBySvcdoctor,
		CodeCredentialWithheld,
		CodeAuthenticationFailed,
		CodeDatabaseNotFound,
		CodeDatabaseConnectDenied,
		CodeSessionEstablishmentFailed,
	}

	const want = 12
	if len(codes) != want {
		t.Fatalf("this package declares %d codes, want %d", len(codes), want)
	}

	seen := map[domain.FindingCode]bool{}
	for _, code := range codes {
		if !code.Valid() {
			t.Errorf("%q is not a valid finding code", code)
		}
		if code.Namespace() != "POSTGRES" {
			t.Errorf("%q has namespace %q, want POSTGRES", code, code.Namespace())
		}
		if seen[code] {
			t.Errorf("%q is declared twice", code)
		}
		seen[code] = true
	}
}

// TestTheVocabularyIsALeaf restates for this package's dependency that the
// constants it reads carry no behaviour with them.
func TestTheVocabularyIsALeaf(t *testing.T) {
	steps := []domain.Step{
		servicepostgres.StepSSLRequest,
		servicepostgres.StepStartup,
		servicepostgres.StepAuthentication,
		servicepostgres.StepSession,
	}
	for _, step := range steps {
		if !strings.HasPrefix(string(step), "postgres.") {
			t.Errorf("step %q is not namespaced", step)
		}
	}
}
