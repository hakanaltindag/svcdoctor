package security

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	diagnosispostgres "github.com/hakanaltindag/svcdoctor/internal/diagnosis/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// The security check for Phase 4.6b: the twelve PostgreSQL findings, taken
// through redaction.
//
// It lives here rather than beside the rules because depguard denies
// internal/diagnosis the internal/security import — correctly, and the boundary
// is not weakened to make a test convenient. The Kafka finding-redaction test is
// here for the same reason.
//
// PostgreSQL adds a carrier Kafka does not have: **identity attributes**. The
// role and the database are recorded through domain.IdentityAttr on the startup
// node, and a finding that named either in prose would put a tenant's role and
// dataset names into a shared report by a route that structural redaction of the
// graph would never see. The rules are written so that identity travels only on
// the subject and on the referenced evidence; this is what makes that a checked
// property rather than a claim.

const (
	// Canaries. They appear nowhere else in the repository, so finding one in a
	// shareable report is unambiguous.
	pgFindingCanaryHost     = "primary-db-9.corp-secret.internal"
	pgFindingCanaryIP       = "10.91.92.93"
	pgFindingCanaryRole     = "tenant-77-writer"
	pgFindingCanaryDatabase = "tenant-77-ledger"
)

// postgresFailureReport builds a graph in the shape Phases 4.3 through 4.5
// produce, diagnoses it, and assembles a local report.
//
// The session fails at a missing database, which is the case that exercises the
// most carriers at once: an identity-bearing role and database on the startup
// node, a SQLSTATE in a floor-adjacent detail, and three evidence references
// that must all survive remapping.
func postgresFailureReport(t *testing.T) domain.Report {
	t.Helper()

	builder := domain.NewGraphBuilder()
	at := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

	add := func(
		id, subject string, layer domain.Layer, step domain.Step,
		state domain.State, class domain.FailureClass, parent domain.EvidenceID,
		attributes map[domain.AttributeKey]domain.AttrValue,
	) domain.EvidenceID {
		t.Helper()
		ref, err := domain.NewEndpointSubject(subject)
		if err != nil {
			t.Fatalf("subject %q: %v", subject, err)
		}
		at = at.Add(time.Millisecond)
		evidence, err := domain.NewEvidence(domain.EvidenceInput{
			ID: domain.EvidenceID(id), Subject: ref, Layer: layer, Step: step,
			State: state, FailureClass: class, Attributes: attributes,
			StartedAt: at, Elapsed: domain.Measured(time.Millisecond),
		})
		if err != nil {
			t.Fatalf("evidence %q: %v", id, err)
		}
		if err := builder.AddEvidence(evidence); err != nil {
			t.Fatalf("adding %q: %v", id, err)
		}
		if parent != "" {
			if err := builder.AddParent(evidence.ID(), parent); err != nil {
				t.Fatalf("parent of %q: %v", id, err)
			}
		}
		return evidence.ID()
	}

	endpoint := pgFindingCanaryHost + ":5432"
	address := pgFindingCanaryIP + ":5432"

	lookup := add("dns.lookup/"+endpoint, endpoint, domain.LayerDNS, "dns.lookup",
		domain.StatePass, domain.FailureNone, "", nil)
	tcp := add("tcp.connect/"+endpoint+"/"+pgFindingCanaryIP, address,
		domain.LayerTCP, "tcp.connect", domain.StatePass, domain.FailureNone, lookup, nil)
	ssl := add("postgres.ssl_request/"+endpoint+"/"+pgFindingCanaryIP, address,
		domain.LayerTLS, servicepostgres.StepSSLRequest, domain.StatePass, domain.FailureNone, tcp,
		map[domain.AttributeKey]domain.AttrValue{
			servicepostgres.AttrSSLOffered: domain.BoolAttr(true),
		})
	startup := add("postgres.startup/"+endpoint+"/"+pgFindingCanaryIP, address,
		domain.LayerProtocol, servicepostgres.StepStartup, domain.StatePass, domain.FailureNone, ssl,
		map[domain.AttributeKey]domain.AttrValue{
			servicepostgres.AttrAuthMethod: domain.StringAttr("sasl"),
			// The two carriers this test exists for.
			"postgres.role":     domain.IdentityAttr(pgFindingCanaryRole),
			"postgres.database": domain.IdentityAttr(pgFindingCanaryDatabase),
		})
	auth := add("postgres.authentication/"+endpoint+"/"+pgFindingCanaryIP, address,
		domain.LayerAuth, servicepostgres.StepAuthentication, domain.StatePass, domain.FailureNone,
		startup, nil)
	add("postgres.session/"+endpoint+"/"+pgFindingCanaryIP, address,
		domain.LayerAuth, servicepostgres.StepSession, domain.StateFail,
		domain.FailureResourceNotFound, auth,
		map[domain.AttributeKey]domain.AttrValue{
			servicepostgres.AttrSQLState:      domain.StringAttr("3D000"),
			servicepostgres.AttrErrorIsNative: domain.BoolAttr(true),
		})

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}

	var findings []domain.Finding
	findings = append(findings, diagnosispostgres.SSLRequest(ruleContextFor(graph))...)
	findings = append(findings, diagnosispostgres.Startup(ruleContextFor(graph))...)
	findings = append(findings, diagnosispostgres.Authentication(ruleContextFor(graph))...)
	findings = append(findings, diagnosispostgres.Session(ruleContextFor(graph))...)
	if len(findings) == 0 {
		t.Fatal("the fixture produced no finding; the test would prove nothing")
	}

	target, err := domain.NewTarget(endpoint)
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	vantage, err := domain.NewLocalVantage("runner-" + pgFindingCanaryHost)
	if err != nil {
		t.Fatalf("vantage: %v", err)
	}
	service, err := domain.NewServiceID("postgres")
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	run, err := domain.NewRunMetadata("0.1.0-test", at, time.Second, service)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("security: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage,
		Graph: graph, Findings: findings, Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

// TestPostgreSQLFindingsCarryNoIdentityIntoASharedReport is the canary sweep.
//
// The whole shareable report is encoded and searched. A hostname, an address, a
// role name or a database name surviving anywhere in it — prose, subject,
// recommendation or evidence reference — fails here.
func TestPostgreSQLFindingsCarryNoIdentityIntoASharedReport(t *testing.T) {
	shareable, err := redaction.Redact(postgresFailureReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	encoded, err := json.Marshal(shareable)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	for _, canary := range []string{
		pgFindingCanaryHost, pgFindingCanaryIP, pgFindingCanaryRole, pgFindingCanaryDatabase,
	} {
		if strings.Contains(string(encoded), canary) {
			t.Errorf("canary %q survived into the shareable report", canary)
		}
	}
}

// TestPostgreSQLFindingSemanticsSurviveRedaction pins that redaction removes
// identity and changes nothing else.
//
// A finding's meaning must not depend on identity: the code, kind, severity,
// confidence, layer and vantage flag stay put, and every sentence comes through
// byte-identical because none of them interpolates a value from the graph.
func TestPostgreSQLFindingSemanticsSurviveRedaction(t *testing.T) {
	local := postgresFailureReport(t)

	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	before, after := local.Findings(), shareable.Findings()
	if len(before) != len(after) {
		t.Fatalf("redaction changed the finding count: %d -> %d", len(before), len(after))
	}

	for i := range before {
		a, b := before[i], after[i]
		if a.Code() != b.Code() {
			t.Errorf("code changed: %s -> %s", a.Code(), b.Code())
		}
		if a.Kind() != b.Kind() || a.Severity() != b.Severity() || a.Confidence() != b.Confidence() {
			t.Errorf("%s: kind, severity or confidence changed", a.Code())
		}
		if a.Layer() != b.Layer() {
			t.Errorf("%s: layer changed", a.Code())
		}
		if a.VantageDependent() != b.VantageDependent() {
			t.Errorf("%s: vantageDependent changed", a.Code())
		}
		if a.Summary() != b.Summary() {
			t.Errorf("%s: summary changed:\n %q\n %q", a.Code(), a.Summary(), b.Summary())
		}
		if a.Detail() != b.Detail() {
			t.Errorf("%s: detail changed:\n %q\n %q", a.Code(), a.Detail(), b.Detail())
		}

		beforeActions, afterActions := a.Recommendations(), b.Recommendations()
		if len(beforeActions) != len(afterActions) {
			t.Fatalf("%s: recommendation count changed", a.Code())
		}
		for j := range beforeActions {
			if beforeActions[j].Action() != afterActions[j].Action() {
				t.Errorf("%s: recommendation changed:\n %q\n %q",
					a.Code(), beforeActions[j].Action(), afterActions[j].Action())
			}
		}

		// The references must be pseudonyms now, and every one must still
		// resolve against the redacted graph.
		if a.EvidenceRefCount() != b.EvidenceRefCount() {
			t.Errorf("%s: evidence reference count changed", a.Code())
		}
		for _, ref := range b.EvidenceRefs() {
			if _, ok := shareable.Graph().Node(ref); !ok {
				t.Errorf("%s: reference %q does not resolve after redaction", a.Code(), ref)
			}
		}
	}
}

// TestPostgreSQLFindingRedactionIsIdempotent pins that a shareable report cannot
// drift by being passed around.
func TestPostgreSQLFindingRedactionIsIdempotent(t *testing.T) {
	once, err := redaction.Redact(postgresFailureReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	twice, err := redaction.Redact(once)
	if err != nil {
		t.Fatalf("Redact twice: %v", err)
	}

	a, err := json.Marshal(once.Findings())
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	b, err := json.Marshal(twice.Findings())
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("redaction is not idempotent:\n %s\n %s", a, b)
	}
}
