package security

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
)

// The identity-bearing attribute contract, checked end to end.
//
// Phase 4.1 exists so that a future adapter can record a role and a database as
// evidence and still label the resulting report SHAREABLE_REDACTED without
// lying. Nothing here knows which service that will be: the canaries are shaped
// like PostgreSQL values because that is the caller the phase was built for, and
// the production packages under test contain no PostgreSQL code at all.
const (
	identityCanaryRole     = "payments_writer"
	identityCanaryDatabase = "payments_prod"
	identityCanaryTenant   = "acme-holdings"
	identityCanaryHost     = "db-canary.payments.internal"
	identityCanaryAddr     = "10.77.88.99"
	identityCanaryVantage  = "identity-runner-canary.local"

	// The password canary must never reach a report at all — not raw, and not
	// as a pseudonym. It is here to prove the secret boundary is untouched by a
	// phase that adds a new category of non-secret sensitive value.
	identityCanaryPassword = "svcdoctor-canary-password-4f21ab"
)

// identityReportFixture builds a local report carrying every category of value
// at once: two logical identities, a hostname, an address, an evidence
// identifier, and ordinary diagnostic facts that must survive.
//
// A credential is constructed alongside it and deliberately never recorded, so
// the test can assert that the password is absent because there is no path for
// it rather than because nobody looked.
func identityReportFixture(t *testing.T) domain.Report {
	t.Helper()

	// A real credential, held the way production holds one. It never reaches
	// the report: there is no AttrValue constructor that accepts a Secret.
	endpoint, err := security.NewEndpoint(identityCanaryHost, 5432)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(
		endpoint, identityCanaryRole, security.NewSecret(identityCanaryPassword))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	if credential.Identity() != identityCanaryRole {
		t.Fatalf("credential identity = %q, want %q", credential.Identity(), identityCanaryRole)
	}

	subject, err := domain.NewEndpointSubject(identityCanaryAddr + ":5432")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	step, err := domain.NewStep("probe.session")
	if err != nil {
		t.Fatalf("NewStep: %v", err)
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:      domain.EvidenceID("probe.session/" + identityCanaryHost + "/" + identityCanaryAddr),
		Subject: subject,
		Layer:   domain.LayerAuth,
		Step:    step,
		State:   domain.StatePass,
		Attributes: map[domain.AttributeKey]domain.AttrValue{
			// Declared identities: a principal and a named resource.
			"probe.role":     domain.IdentityAttr(identityCanaryRole),
			"probe.database": domain.IdentityAttr(identityCanaryDatabase),
			"probe.tenant":   domain.IdentityAttr(identityCanaryTenant),
			// A declared peer, in the category that already existed.
			"probe.peer": domain.HostAttr(identityCanaryHost),
			// Ordinary diagnostic facts, which must survive intact.
			"probe.protocol_version": domain.StringAttr("3.0"),
			"probe.status_code":      domain.StringAttr("28P01"),
			"probe.ready":            domain.BoolAttr(true),
			"probe.round_trip":       domain.DurationAttr(12 * time.Millisecond),
		},
		StartedAt: time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC),
		Duration:  12 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	builder := domain.NewGraphBuilder()
	if err := builder.AddEvidence(evidence); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	finding, err := domain.NewFinding(domain.FindingInput{
		Code:       domain.FindingCode("PROBE_SESSION_ESTABLISHED"),
		Kind:       domain.FindingKindConfirmed,
		Severity:   domain.SeverityInfo,
		Confidence: domain.ConfidenceHigh,
		Layer:      domain.LayerAuth,
		Subject:    subject,
		Summary: "the session for " + identityCanaryRole + " reached " +
			identityCanaryDatabase,
		Detail: "Role " + identityCanaryRole + " connected to database " +
			identityCanaryDatabase + " at " + identityCanaryHost + ".",
		EvidenceRefs: []domain.EvidenceID{evidence.ID()},
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	run, err := domain.NewRunMetadata("0.1.0", time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC),
		time.Second, "example")
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget(identityCanaryHost + ":5432")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage(identityCanaryVantage)
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	reportSecurity, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage, Graph: graph,
		Findings: []domain.Finding{finding}, Security: reportSecurity,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

func encodeReport(t *testing.T, r domain.Report) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(b)
}

// TestLocalReportContainsEveryIdentityCanary is the control.
//
// Without it the redaction assertions below would pass against a fixture that
// never carried the values in the first place.
func TestLocalReportContainsEveryIdentityCanary(t *testing.T) {
	encoded := encodeReport(t, identityReportFixture(t))

	for _, canary := range []string{
		identityCanaryRole, identityCanaryDatabase, identityCanaryTenant,
		identityCanaryHost, identityCanaryAddr, identityCanaryVantage,
	} {
		if !strings.Contains(encoded, canary) {
			t.Errorf("the local report does not contain %q, so redacting it proves nothing", canary)
		}
	}

	// The password is the exception, and it is absent from the *local* report
	// too. A secret has no path into evidence at all.
	if strings.Contains(encoded, identityCanaryPassword) {
		t.Fatal("the password canary reached a LOCAL_FULL report; the secret boundary is broken")
	}
}

// TestEveryCategoryIsRedactedIntoItsOwnNamespace is the phase's definition of
// done, in one assertion set.
//
// Roles and databases become identity-NNN, hosts stay host-NNN, addresses stay
// ip-NNN, evidence identifiers stay evidence-NNN, ordinary diagnostic facts
// survive, and the password appears nowhere in any form.
func TestEveryCategoryIsRedactedIntoItsOwnNamespace(t *testing.T) {
	local := identityReportFixture(t)
	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	encoded := encodeReport(t, shareable)

	if got := shareable.Security().OutputMode(); got != domain.OutputModeShareableRedacted {
		t.Fatalf("output mode = %s, want SHAREABLE_REDACTED", got)
	}

	// Nothing identifying survives, in any surface.
	for _, canary := range []string{
		identityCanaryRole, identityCanaryDatabase, identityCanaryTenant,
		identityCanaryHost, identityCanaryAddr, identityCanaryVantage,
		identityCanaryPassword,
	} {
		if strings.Contains(encoded, canary) {
			t.Errorf("%q survived into a report labelled SHAREABLE_REDACTED", canary)
		}
	}

	node := shareable.Graph().Nodes()[0]

	// Each declared identity is in the identity namespace, and they are distinct.
	seen := map[string]domain.AttributeKey{}
	for _, key := range []domain.AttributeKey{"probe.role", "probe.database", "probe.tenant"} {
		v, ok := node.Attribute(key)
		if !ok {
			t.Fatalf("attribute %s is missing", key)
		}
		id, ok := v.Identity()
		if !ok {
			t.Fatalf("attribute %s has kind %s, want identity", key, v.Kind())
		}
		if !strings.HasPrefix(id, "identity-") {
			t.Errorf("%s = %q, want an identity-NNN pseudonym", key, id)
		}
		if prev, dup := seen[id]; dup {
			t.Errorf("%s and %s both became %q", prev, key, id)
		}
		seen[id] = key
	}

	// The peer stays in the host namespace: a principal must never be numbered
	// as a machine, and a machine must never be numbered as a principal.
	peer, _ := node.Attribute("probe.peer")
	host, ok := peer.Host()
	if !ok {
		t.Fatalf("probe.peer has kind %s, want host", peer.Kind())
	}
	if !strings.HasPrefix(host, "host-") {
		t.Errorf("probe.peer = %q, want a host-NNN pseudonym", host)
	}

	// The subject keeps its address in the ip namespace, with the port intact.
	if ref := node.Subject().Ref(); !strings.HasPrefix(ref, "ip-") || !strings.HasSuffix(ref, ":5432") {
		t.Errorf("subject ref = %q, want ip-NNN:5432", ref)
	}
	// The evidence identifier keeps its own namespace.
	if id := node.ID().String(); !strings.HasPrefix(id, "evidence-") {
		t.Errorf("evidence id = %q, want evidence-NNN", id)
	}

	// Diagnostic facts survive, which is what makes a shareable report useful.
	for key, want := range map[domain.AttributeKey]string{
		"probe.protocol_version": "3.0",
		"probe.status_code":      "28P01",
		"probe.ready":            "true",
		"probe.round_trip":       "12ms",
	} {
		v, ok := node.Attribute(key)
		if !ok {
			t.Fatalf("attribute %s is missing", key)
		}
		if got := v.String(); got != want {
			t.Errorf("%s = %q, want %q: a diagnostic fact was destroyed", key, got, want)
		}
	}

	// Prose keeps the correlation and loses the identity.
	finding := shareable.Findings()[0]
	for name, text := range map[string]string{
		"summary": finding.Summary(),
		"detail":  finding.Detail(),
	} {
		if !strings.Contains(text, "identity-") {
			t.Errorf("finding %s lost the identity correlation: %q", name, text)
		}
		if !strings.Contains(text, "host-") && name == "detail" {
			t.Errorf("finding detail lost the host correlation: %q", text)
		}
	}

	counts := shareable.Security().Redactions()
	if counts.Identity != 3 {
		t.Errorf("identity count = %d, want 3 distinct identities", counts.Identity)
	}
	if counts.Hostname == 0 || counts.IPAddress == 0 || counts.EvidenceID == 0 || counts.Prose == 0 {
		t.Errorf("existing categories stopped counting: %+v", counts)
	}
}

// TestIdentityRedactionIsIdempotentEndToEnd keeps the documented contract true
// for a report that mixes every category.
func TestIdentityRedactionIsIdempotentEndToEnd(t *testing.T) {
	once, err := redaction.Redact(identityReportFixture(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	twice, err := redaction.Redact(once)
	if err != nil {
		t.Fatalf("second Redact: %v", err)
	}
	if got, want := encodeReport(t, twice), encodeReport(t, once); got != want {
		t.Errorf("Redact is not idempotent:\n got %s\nwant %s", got, want)
	}
}

// TestRedactionLeavesTheLocalReportIntact proves the caller still holds a usable
// local report afterwards, with the real identities in it.
func TestRedactionLeavesTheLocalReportIntact(t *testing.T) {
	local := identityReportFixture(t)
	before := encodeReport(t, local)

	if _, err := redaction.Redact(local); err != nil {
		t.Fatalf("Redact: %v", err)
	}

	after := encodeReport(t, local)
	if after != before {
		t.Errorf("the local report was mutated:\nbefore %s\n after %s", before, after)
	}
	if !strings.Contains(after, identityCanaryRole) {
		t.Error("the local report lost its identities")
	}
}

// TestIdentityRedactionIsDeterministic runs the whole pipeline repeatedly and
// requires byte-identical canonical output every time.
func TestIdentityRedactionIsDeterministic(t *testing.T) {
	want := ""
	for i := 0; i < 50; i++ {
		shareable, err := redaction.Redact(identityReportFixture(t))
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		got := encodeReport(t, shareable)
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("iteration %d differs:\n got %s\nwant %s", i, got, want)
		}
	}
}

// --- architecture ------------------------------------------------------------

// serviceWords are names a redactor must never branch on. Inferring sensitivity
// from an attribute key would rebuild the central registry of service keys the
// architecture refuses, and would silently miss any service not on the list.
var serviceWords = []string{
	"postgres", "postgresql", "kafka", "mysql", "mariadb",
	"rabbitmq", "vhost", "redis", "valkey", "elasticsearch", "opensearch",
}

// TestRedactionContainsNoServiceSpecificPolicy is the generality guard.
//
// It parses the production sources and inspects **string literals and
// identifiers only**, deliberately not comments. A comment naming PostgreSQL as
// the caller this was built for is useful documentation; a string literal or a
// function named after a service is policy, and policy is what must not be here.
//
// The check is over the AST rather than over raw text for exactly that reason: a
// grep would fail on the package documentation and would tempt somebody to
// delete an explanation to make a test pass.
func TestRedactionContainsNoServiceSpecificPolicy(t *testing.T) {
	dirs := []string{
		filepath.Join("..", "..", "internal", "security", "redaction"),
		filepath.Join("..", "..", "internal", "domain"),
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}

		inspected := 0
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)

			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}
			inspected++

			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.BasicLit:
					if node.Kind == token.STRING {
						reportServiceWord(t, path, fset, node.Pos(), node.Value, "string literal")
					}
				case *ast.Ident:
					reportServiceWord(t, path, fset, node.Pos(), node.Name, "identifier")
				}
				return true
			})
		}

		// Without this the test would pass vacuously if the directory moved.
		if inspected == 0 {
			t.Fatalf("no production Go files found in %s", dir)
		}
	}
}

func reportServiceWord(
	t *testing.T, path string, fset *token.FileSet, pos token.Pos, text, what string,
) {
	t.Helper()
	lower := strings.ToLower(text)
	for _, word := range serviceWords {
		if strings.Contains(lower, word) {
			t.Errorf("%s:%d: %s %q names the service %q; redaction and the domain model "+
				"must stay service-neutral. Sensitivity is declared by a producer through "+
				"an AttrKind, never inferred from a key name (ADR 0022, ADR 0037)",
				path, fset.Position(pos).Line, what, text, word)
		}
	}
}

// TestRedactionPerformsNoKeyNameInference is the behavioural half of the guard
// above: an attribute whose *key* reads exactly like a sensitive field is left
// alone unless its *value* was declared.
//
// If this ever starts failing, somebody added a key-name heuristic, and every
// service whose key spelling differs would be leaking silently.
func TestRedactionPerformsNoKeyNameInference(t *testing.T) {
	local := identityReportFixture(t)

	node := local.Graph().Nodes()[0]
	attrs := node.Attributes()
	// Keys that scream "sensitive", carrying undeclared ordinary strings.
	attrs["postgres.user"] = domain.StringAttr("undeclared_user_canary")
	attrs["postgres.database"] = domain.StringAttr("undeclared_db_canary")
	attrs["username"] = domain.StringAttr("undeclared_name_canary")

	rebuilt, err := domain.NewEvidence(domain.EvidenceInput{
		ID: node.ID(), Subject: node.Subject(), Layer: node.Layer(), Step: node.Step(),
		State: node.State(), Attributes: attrs,
		StartedAt: node.StartedAt(), Duration: node.Duration(),
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	builder := domain.NewGraphBuilder()
	if err := builder.AddEvidence(rebuilt); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	withKeys, err := domain.NewReport(domain.ReportInput{
		Run: local.Run(), Target: local.Target(), Vantage: local.Vantage(),
		Graph: graph, Security: local.Security(),
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}

	shareable, err := redaction.Redact(withKeys)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	encoded := encodeReport(t, shareable)

	for _, undeclared := range []string{
		"undeclared_user_canary", "undeclared_db_canary", "undeclared_name_canary",
	} {
		if !strings.Contains(encoded, undeclared) {
			t.Errorf("%q was redacted, so sensitivity is being inferred from a key name; "+
				"ADR 0022 rejected that and ADR 0037 kept the rejection", undeclared)
		}
	}
	// And the declared ones still go, in the same report.
	if strings.Contains(encoded, identityCanaryRole) {
		t.Error("a declared identity survived alongside the undeclared ones")
	}
}
