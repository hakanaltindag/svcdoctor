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

// TestTheRulesImportOnlyDomainAndTheVocabularyLeaves pins the dependency
// direction the phase turned on.
//
// diagnosis must not import the adapter, so the eight shared constants moved to
// a leaf vocabulary package rather than the boundary being weakened to reach
// them (ADR 0040 section 22). Anything else appearing here would be a layer this
// package has no business touching — the adapter and its wire package above all,
// because those hold protocol machinery, live connections and credentials.
//
// **internal/vocabulary joined the list in Phase 4.9d**, on exactly the same
// terms as the PostgreSQL leaf and for the same reason. ADR 0044 gives this
// package a `tls.handshake` node whose direct parent proves it, and naming that
// step requires the one canonical spelling of it. The generic leaf holds names
// and no behaviour, imports internal/domain and nothing else, and importing the
// probe that produces the step is what depguard forbids and what the leaf exists
// to make unnecessary.
//
// # Why internal/diagnosis is on the list from Phase 10.1a
//
// ADR 0080 section 2.1 widened diagnosis.Rule from a graph to a RuleContext, so
// a rule package must name the type it accepts. ADR 0080 section 2.6 draws the
// direction that makes that safe: a rule package imports the engine, the engine
// imports no subpackage of its own, and a cycle is therefore impossible rather
// than merely avoided. The allowlist keeps the sharper half honest — an import
// of a *sibling* rule package would still fail here, which is the coupling that
// would let one service's reasoning depend on another's.
func TestTheRulesImportOnlyDomainAndTheVocabularyLeaves(t *testing.T) {
	allowed := map[string]bool{
		"github.com/hakanaltindag/svcdoctor/internal/diagnosis":        true,
		"github.com/hakanaltindag/svcdoctor/internal/domain":           true,
		"github.com/hakanaltindag/svcdoctor/internal/service/postgres": true,
		"github.com/hakanaltindag/svcdoctor/internal/vocabulary":       true,
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
// rules.
//
// It used to add that this package proved it *without* importing the engine.
// Phase 10.1a ended that: ADR 0080 section 2.1 widened diagnosis.Rule from a
// graph to a RuleContext, and a rule package must now name the type it accepts.
// The direction is the one ADR 0080 section 2.6 draws — a service rule package
// imports the engine and never the reverse — so a cycle stays structurally
// impossible rather than merely avoided.
func TestTheRulesSatisfyTheEngineContract(t *testing.T) {
	var _ diagnosis.Rule = SSLRequest

	engine := testEngine(SSLRequest, Startup, Authentication, Session)

	if got := engine.RuleCount(); got != 4 {
		t.Fatalf("RuleCount = %d, want 4", got)
	}

	// And an empty graph produces nothing, which is the property a report of a
	// run that never reached PostgreSQL depends on.
	if findings := engine.Diagnose(rctx(domain.Graph{})); len(findings) != 0 {
		t.Errorf("an empty graph produced %v", codesOf(findings))
	}
}

// TestEveryAuthorizedCodeIsWellFormedAndNamespaced pins the public surface.
//
// Nineteen codes, no twentieth. The count is asserted so that adding one is a
// deliberate act rather than a drift, exactly as the FailureClass count guard
// works in internal/domain.
//
// It was twelve until Phase 4.9d, when ADR 0044 authorized five for the in-band
// handshake. Raising it is the deliberate act; a sixth TLS code would fail here
// and in internal/vocabulary's module-wide allow-list, which has to be edited
// too.
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
		CodeTLSUpgradeNotHonored,
		CodeTLSIdentityMismatch,
		CodeTLSChainNotTrusted,
		CodeTLSCertificateNotValidNow,
		CodeTLSHandshakeFailed,
		CodeCredentialNotConfigured,
		CodeSSLNegotiationFailed,
	}

	const want = 19
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

// --- guards for the in-band TLS rule (ADR 0044) --------------------------------

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

// TestTheTLSRuleInfersNoProvenance is the anchoring guarantee for the one rule
// here that reads a generic node.
//
// It owns a `tls.handshake` node by reading the parent edge the adapter recorded.
// That is a fact a producer stated; asking what a node is *about* by inspecting
// identifiers, scopes or ancestry would be the guess ADR 0034 section 4 forbids
// and the `Origin` that stays deferred.
//
// The scan reads the AST, so the file's comments — which discuss provenance at
// length — do not trip it.
func TestTheTLSRuleInfersNoProvenance(t *testing.T) {
	forbidden := map[string]string{
		"strings.Split":      "an evidence identifier is opaque and has no decoder",
		"strings.SplitN":     "an evidence identifier is opaque and has no decoder",
		"strings.Cut":        "an evidence identifier is opaque and has no decoder",
		"strings.HasPrefix":  "the parent edge says what caused a node; a prefix does not",
		"strings.TrimPrefix": "the parent edge says what caused a node; a prefix does not",
		"strings.Contains":   "ownership is structural, never a substring match",
		"strings.Index":      "ownership is structural, never a substring match",
		"SweepScope":         "a scope labels an execution and must never be read for meaning",
		"Origin":             "provenance is not inferred, and no code path may need it",
		"Provenance":         "the graph records derivation, never provenance",
	}

	names := namesUsedIn(t, "tls.go")
	for pattern, why := range forbidden {
		if names[pattern] {
			t.Errorf("tls.go uses %s: %s", pattern, why)
		}
	}
}

// TestTheTLSRuleWalksOneEdgeAndStops pins that ownership is direct parentage.
//
// A recursive helper is the shape an ancestor search takes, and an ancestor
// search is how this rule would start claiming handshakes several layers below a
// negotiation it never checked. `Children` is the other direction and this rule
// has no reason to look down at all.
func TestTheTLSRuleWalksOneEdgeAndStops(t *testing.T) {
	names := namesUsedIn(t, "tls.go")
	if names["Children"] {
		t.Error("tls.go calls Children; the rule reads its node and its one parent")
	}
	if names["BlockedBy"] {
		t.Error("tls.go calls BlockedBy; a blocked step is never a cause")
	}

	for _, decl := range parse(t, "tls.go").Decls {
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
				t.Errorf("%s calls itself; ownership is one edge, never a traversal",
					fn.Name.Name)
			}
			return true
		})
	}
}

// TestTheTLSRuleIsNotCoupledToAuthentication pins the separation ADR 0044
// section 12 requires.
//
// The rule reads two nodes and stops. Reaching into startup, authentication or
// session would let a TLS claim depend on what happened after it, and would put
// this rule in the path of ADR 0041's credential-attempt limit.
func TestTheTLSRuleIsNotCoupledToAuthentication(t *testing.T) {
	names := namesUsedIn(t, "tls.go")
	for _, banned := range []string{
		"StepStartup", "StepAuthentication", "StepSession",
		"AttrAuthMethod", "AttrSQLState", "Credential", "Reveal", "Secret",
	} {
		if names[banned] {
			t.Errorf("tls.go names %s; the TLS rule reads the handshake and its negotiation",
				banned)
		}
	}
}

// TestTheTLSRuleQuotesNoLibraryTextOrCertificateMaterial pins what may not reach
// a report.
//
// The TLS probe already discards the handshake error's text, for the reason the
// DNS probe gives about resolver errors: library prose can name hosts and paths
// in a form structural redaction cannot recognize. A rule that reconstructed any
// of it — or that inlined a certificate field — would reintroduce exactly that.
func TestTheTLSRuleQuotesNoLibraryTextOrCertificateMaterial(t *testing.T) {
	names := namesUsedIn(t, "tls.go")
	for _, banned := range []string{
		"Error", "Unwrap", "Certificate", "Subject", "Issuer", "DNSNames",
		"AttrPeerDNSNames", "AttrPeerNotAfter", "AttrServerName",
	} {
		// Subject is the domain accessor and is legitimate; the certificate
		// field of the same name is not reachable from here at all, because the
		// package cannot import crypto/x509.
		if banned == "Subject" {
			continue
		}
		if names[banned] {
			t.Errorf("tls.go names %s; certificate material stays on the evidence node "+
				"where redaction transforms it", banned)
		}
	}
}

// TestTheTLSMappingIsClosed pins that an unrecognized class produces nothing.
//
// A default branch folding anything unknown into the floor would hand a future
// producer a claim nobody reviewed, and would make the floor's own wording —
// "could not attribute" — a statement about a class that may be perfectly
// attributable.
func TestTheTLSMappingIsClosed(t *testing.T) {
	authorized := map[domain.FailureClass]bool{
		domain.FailureTLSPeerNotTLS:             true,
		domain.FailureTLSHostnameMismatch:       true,
		domain.FailureTLSUnknownAuthority:       true,
		domain.FailureTLSCertificateExpired:     true,
		domain.FailureTLSCertificateNotYetValid: true,
		domain.FailureTLSHandshakeFailure:       true,
	}

	if len(tlsClaims) != len(authorized) {
		t.Fatalf("the mapping holds %d classes, want %d", len(tlsClaims), len(authorized))
	}
	for class := range tlsClaims {
		if !authorized[class] {
			t.Errorf("%s is mapped but not authorized by ADR 0044", class)
		}
	}

	// Every declared class outside the authorized set must map to nothing,
	// including the three TLS classes no producer emits.
	for i := 0; ; i++ {
		class := domain.FailureClass(i)
		if !class.Valid() {
			break
		}
		if authorized[class] {
			continue
		}
		if _, mapped := tlsClaims[class]; mapped {
			t.Errorf("%s is mapped and must not be", class)
		}
	}
	for _, unproduced := range []domain.FailureClass{
		domain.FailureTLSVersionMismatch,
		domain.FailureTLSClientCertificateRequired,
		domain.FailureTLSClientCertificateRejected,
	} {
		if _, mapped := tlsClaims[unproduced]; mapped {
			t.Errorf("%s has no producer and must not be mapped", unproduced)
		}
	}
}

// TestNoCodeIsDeclaredOutsideTheAuthorizedSet closes the gap the count guard
// leaves.
//
// TestEveryAuthorizedCodeIsWellFormedAndNamespaced enumerates the codes by hand,
// so a constant declared and never added to that list is invisible to it — and
// an unused constant is exactly how a sixth code arrives, one refactor before
// something starts using it. This scans the declarations instead.
func TestNoCodeIsDeclaredOutsideTheAuthorizedSet(t *testing.T) {
	authorized := map[string]bool{
		"POSTGRES_TLS_DECLINED": true, "POSTGRES_STARTUP_FAILED": true,
		"POSTGRES_CONNECTION_NOT_PERMITTED": true, "POSTGRES_CREDENTIALS_REJECTED": true,
		"POSTGRES_PEER_VERIFICATION_FAILED":                true,
		"POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE":    true,
		"POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR": true,
		"POSTGRES_CREDENTIAL_WITHHELD":                     true,
		"POSTGRES_AUTHENTICATION_FAILED":                   true,
		"POSTGRES_DATABASE_NOT_FOUND":                      true,
		"POSTGRES_DATABASE_CONNECT_DENIED":                 true,
		"POSTGRES_SESSION_ESTABLISHMENT_FAILED":            true,
		"POSTGRES_TLS_UPGRADE_NOT_HONORED":                 true,
		"POSTGRES_TLS_IDENTITY_MISMATCH":                   true,
		"POSTGRES_TLS_CHAIN_NOT_TRUSTED":                   true,
		"POSTGRES_TLS_CERTIFICATE_NOT_VALID_NOW":           true,
		"POSTGRES_TLS_HANDSHAKE_FAILED":                    true,
		"POSTGRES_CREDENTIAL_NOT_CONFIGURED":               true,
		"POSTGRES_SSL_NEGOTIATION_FAILED":                  true,
	}

	found := 0
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
				lit, ok := value.(*ast.BasicLit)
				if !ok {
					continue
				}
				code := strings.Trim(lit.Value, `"`)
				found++
				if !authorized[code] {
					t.Errorf("%s declares %s, which no record authorizes", name, code)
				}
			}
			return true
		})
	}

	if found != len(authorized) {
		t.Errorf("scanned %d declarations, want %d; the scan or the set has drifted",
			found, len(authorized))
	}
}

// TestNoCodeMirrorsAFailureClass keeps the two vocabularies apart.
//
// FailureClass says what evidence observed; FindingCode says what diagnosis
// claims. A code spelled like a class — POSTGRES_TLS_PEER_NOT_TLS beside the
// class TLS_PEER_NOT_TLS — makes the claim vocabulary a namespaced copy of the
// evidence vocabulary, which is the mechanical mapping ADR 0044 section 5
// refused. It is checked on the suffix, because the namespace would otherwise
// hide the mirroring.
func TestNoCodeMirrorsAFailureClass(t *testing.T) {
	classes := map[string]bool{}
	for i := 0; ; i++ {
		class := domain.FailureClass(i)
		if !class.Valid() {
			break
		}
		classes[class.String()] = true
	}
	if len(classes) < 30 {
		t.Fatalf("only %d classes enumerated; the scan is vacuous", len(classes))
	}

	for _, code := range []domain.FindingCode{
		CodeTLSDeclined, CodeTLSUpgradeNotHonored, CodeTLSIdentityMismatch,
		CodeTLSChainNotTrusted, CodeTLSCertificateNotValidNow, CodeTLSHandshakeFailed,
		CodeStartupFailed, CodeCredentialsRejected, CodePeerVerificationFailed,
		CodeDatabaseNotFound, CodeSessionEstablishmentFailed,
		CodeCredentialNotConfigured, CodeSSLNegotiationFailed,
	} {
		suffix := strings.TrimPrefix(string(code), "POSTGRES_")
		if classes[suffix] {
			t.Errorf("%s mirrors the FailureClass %s; a claim must not be spelled like "+
				"an observation", code, suffix)
		}
	}
}

// TestNoRuleInfersAMissingCredentialFromAbsence pins the reason ADR 0046 put the
// fact in the producer.
//
// A rule that asked "is there no authentication child?" would claim a missing
// credential about a run cancelled at the same point, because those graphs are
// identical. The mechanical form of that mistake is a rule reading Children from
// a startup node, or counting nodes by step to find one that is not there.
//
// The rules read the node in front of them and its parent. Nothing walks down.
func TestNoRuleInfersAMissingCredentialFromAbsence(t *testing.T) {
	for _, name := range productionFiles(t) {
		names := namesUsedIn(t, name)
		if names["Children"] {
			t.Errorf("%s calls Children; a PostgreSQL rule anchors at a node and reads "+
				"upward, and absence is never evidence", name)
		}
	}
}

// TestTheMissingInputClassIsReadExactlyOnce pins that the new class has one
// consumer and no fallback.
//
// A second reader, or a default branch that folded unrecognized skip classes
// into this claim, would let a future producer's skip become "no credential was
// configured" with nobody deciding that.
func TestTheMissingInputClassIsReadExactlyOnce(t *testing.T) {
	count := 0
	for _, name := range productionFiles(t) {
		ast.Inspect(parse(t, name), func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "FailureExecRequiredInputMissing" {
				count++
			}
			return true
		})
	}
	if count != 1 {
		t.Errorf("the missing-input class is named %d times, want exactly 1", count)
	}
}
