package security

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	diagnosiskafka "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// The security check for Phase 6.1c-P2: the ten Kafka protocol findings, taken
// through redaction.
//
// The advertised-broker findings were checked when they landed. These are a new
// surface for one specific reason: they are the first Kafka findings whose
// subject is a **resolved address** rather than an advertised host:port, and
// three of them concern a credential. If any of that reached a shareable report
// intact, redaction would be leaking exactly what it exists to remove.
//
// The design intent is again that no new heuristic is needed — identity travels
// on the subject and the referenced evidence, and the prose names only a
// mechanism from a public registry. This file makes that a checked property.

const (
	// Canaries, unique in the repository.
	protocolCanaryHost = "bootstrap-91.corp-hidden.internal"
	protocolCanaryIP   = "10.91.92.93"
	protocolCanaryPort = "9412"
)

// protocolReport builds one Kafka protocol node, diagnoses it, and assembles a
// local report.
func protocolReport(
	t *testing.T, step domain.Step, state domain.State, class domain.FailureClass,
) domain.Report {
	t.Helper()

	builder := domain.NewGraphBuilder()
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	subject, err := domain.NewEndpointSubject(protocolCanaryIP + ":" + protocolCanaryPort)
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	layer := map[domain.Step]domain.Layer{
		servicekafka.StepAPIVersions:      domain.LayerProtocol,
		servicekafka.StepSASLHandshake:    domain.LayerAuth,
		servicekafka.StepSASLAuthenticate: domain.LayerAuth,
		servicekafka.StepMetadata:         domain.LayerTopology,
	}[step]

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		// The identifier carries the logical endpoint and the resolved address,
		// exactly as internal/probe encodes it.
		ID: domain.EvidenceID(string(step) + "/" + protocolCanaryHost + ":" +
			protocolCanaryPort + "/" + protocolCanaryIP),
		Subject: subject, Layer: layer, Step: step, State: state, FailureClass: class,
		Attributes: map[domain.AttributeKey]domain.AttrValue{
			servicekafka.AttrSASLMechanism: domain.StringAttr("PLAIN"),
		},
		StartedAt: at, Elapsed: domain.Measured(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	if err := builder.AddEvidence(evidence); err != nil {
		t.Fatalf("adding evidence: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("freezing: %v", err)
	}

	findings := diagnosiskafka.Protocol(graph)
	if len(findings) != 1 {
		t.Fatalf("%s %s/%s produced %d findings, want 1", step, state, class, len(findings))
	}

	run, err := domain.NewRunMetadata("0.1.0-test", at, time.Second, "kafka")
	if err != nil {
		t.Fatalf("run metadata: %v", err)
	}
	target, err := domain.NewTarget(protocolCanaryHost + ":" + protocolCanaryPort)
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	vantage, err := domain.NewLocalVantage("workstation.local")
	if err != nil {
		t.Fatalf("vantage: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("report security: %v", err)
	}
	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage,
		Graph: graph, Findings: findings, Security: security,
	})
	if err != nil {
		t.Fatalf("assembling: %v", err)
	}
	return report
}

// everyProtocolOutcome is one representative of each of the ten codes.
//
// It is written out rather than derived from the rule's unexported table,
// because this package tests the rule from outside — which is the position a
// leak would be found from.
func everyProtocolOutcome() []struct {
	name  string
	step  domain.Step
	state domain.State
	class domain.FailureClass
} {
	return []struct {
		name  string
		step  domain.Step
		state domain.State
		class domain.FailureClass
	}{
		{"api versions version rejected", servicekafka.StepAPIVersions,
			domain.StateFail, domain.FailureProtocolUnsupportedVersion},
		{"api versions floor", servicekafka.StepAPIVersions,
			domain.StateFail, domain.FailureProtocolPeerClosed},
		{"mechanism not offered", servicekafka.StepSASLHandshake,
			domain.StateFail, domain.FailureAuthMechanismNotOffered},
		{"handshake floor", servicekafka.StepSASLHandshake,
			domain.StateFail, domain.FailureProtocolMalformedResponse},
		{"credentials rejected", servicekafka.StepSASLAuthenticate,
			domain.StateFail, domain.FailureAuthCredentialsRejected},
		{"unsupported by svcdoctor", servicekafka.StepSASLAuthenticate,
			domain.StateUnknown, domain.FailureAuthMechanismUnsupported},
		{"credential withheld", servicekafka.StepSASLAuthenticate,
			domain.StateSkipped, domain.FailureExecSkippedByPolicy},
		{"credential not configured", servicekafka.StepSASLAuthenticate,
			domain.StateSkipped, domain.FailureExecRequiredInputMissing},
		{"authentication floor", servicekafka.StepSASLAuthenticate,
			domain.StateFail, domain.FailureProtocolPeerClosed},
		{"metadata floor", servicekafka.StepMetadata,
			domain.StateFail, domain.FailureProtocolPeerClosed},
	}
}

// TestTheProtocolCanariesActuallyTravel proves the canaries reach the local
// report, so the shareable assertions below cannot pass vacuously.
func TestTheProtocolCanariesActuallyTravel(t *testing.T) {
	for _, test := range everyProtocolOutcome() {
		t.Run(test.name, func(t *testing.T) {
			encoded := marshal(t, protocolReport(t, test.step, test.state, test.class))
			for _, canary := range []string{protocolCanaryHost, protocolCanaryIP} {
				if !strings.Contains(encoded, canary) {
					t.Fatalf("canary %q is absent from the local report; the "+
						"shareable assertion would prove nothing", canary)
				}
			}
		})
	}
}

// TestNoProtocolFindingLeaksIdentity is the property.
func TestNoProtocolFindingLeaksIdentity(t *testing.T) {
	for _, test := range everyProtocolOutcome() {
		t.Run(test.name, func(t *testing.T) {
			shareable, err := redaction.Redact(protocolReport(t, test.step, test.state, test.class))
			if err != nil {
				t.Fatalf("redacting: %v", err)
			}
			encoded := marshal(t, shareable)
			for _, canary := range []string{protocolCanaryHost, protocolCanaryIP} {
				if strings.Contains(encoded, canary) {
					t.Errorf("%q survived redaction into a shareable report", canary)
				}
			}
		})
	}
}

// TestProtocolFindingsCarryNoCredentialMaterial is the check the three
// credential-shaped codes exist for.
//
// None of the three rules ever sees a credential — diagnosis may not import
// internal/security and reads a frozen graph — so this asserts the prose does
// not describe one either. A length, an identity or an "empty password" string
// would each be a disclosure about a secret.
func TestProtocolFindingsCarryNoCredentialMaterial(t *testing.T) {
	for _, test := range everyProtocolOutcome() {
		t.Run(test.name, func(t *testing.T) {
			report := protocolReport(t, test.step, test.state, test.class)
			finding := report.Findings()[0]

			prose := strings.ToLower(finding.Summary() + " " + finding.Detail())
			for _, phrase := range []string{
				"password is", "password was", "secret is", "secret was",
				"characters long", "empty password", "username", "principal name",
			} {
				if strings.Contains(prose, phrase) {
					t.Errorf("prose contains %q, which describes credential material", phrase)
				}
			}
		})
	}
}

// TestProtocolFindingsStayCorrelatedAfterRedaction: identity goes, structure
// stays.
//
// A shareable report is useless if a finding can no longer be tied to the
// evidence that produced it, so the references must still resolve into the
// redacted graph and the semantic fields must be untouched.
func TestProtocolFindingsStayCorrelatedAfterRedaction(t *testing.T) {
	for _, test := range everyProtocolOutcome() {
		t.Run(test.name, func(t *testing.T) {
			local := protocolReport(t, test.step, test.state, test.class)
			shareable, err := redaction.Redact(local)
			if err != nil {
				t.Fatalf("redacting: %v", err)
			}

			if len(shareable.Findings()) != 1 {
				t.Fatalf("findings = %d, want 1", len(shareable.Findings()))
			}
			before, after := local.Findings()[0], shareable.Findings()[0]

			if before.Code() != after.Code() {
				t.Errorf("code changed: %s then %s", before.Code(), after.Code())
			}
			if before.Severity() != after.Severity() {
				t.Errorf("severity changed: %s then %s", before.Severity(), after.Severity())
			}
			if before.Confidence() != after.Confidence() {
				t.Errorf("confidence changed: %s then %s", before.Confidence(), after.Confidence())
			}
			if before.Kind() != after.Kind() {
				t.Errorf("kind changed: %s then %s", before.Kind(), after.Kind())
			}
			if before.Layer() != after.Layer() {
				t.Errorf("layer changed: %s then %s", before.Layer(), after.Layer())
			}
			if before.VantageDependent() != after.VantageDependent() {
				t.Errorf("vantageDependent changed: %v then %v",
					before.VantageDependent(), after.VantageDependent())
			}
			if len(before.Recommendations()) != len(after.Recommendations()) {
				t.Errorf("recommendation count changed: %d then %d",
					len(before.Recommendations()), len(after.Recommendations()))
			}

			if len(after.EvidenceRefs()) == 0 {
				t.Fatal("the finding lost its references")
			}
			for _, ref := range after.EvidenceRefs() {
				if _, ok := shareable.Graph().Node(ref); !ok {
					t.Errorf("reference %s does not resolve in the redacted graph", ref)
				}
			}
		})
	}
}

// TestProtocolFindingProseNeededNoNewHeuristic: the mechanism name is the only
// thing the prose adds, and it is a protocol constant from a public registry.
//
// If a later change put a hostname into the prose, redaction would have to grow
// a text heuristic to catch it — which ADR 0018 declines. This is what keeps the
// design honest.
func TestProtocolFindingProseNeededNoNewHeuristic(t *testing.T) {
	for _, test := range everyProtocolOutcome() {
		t.Run(test.name, func(t *testing.T) {
			local := protocolReport(t, test.step, test.state, test.class)
			shareable, err := redaction.Redact(local)
			if err != nil {
				t.Fatalf("redacting: %v", err)
			}
			before, after := local.Findings()[0], shareable.Findings()[0]

			if before.Summary() != after.Summary() {
				t.Errorf("the summary was rewritten by redaction, so it carried identity:\n"+
					"  local:     %q\n  shareable: %q", before.Summary(), after.Summary())
			}
			if before.Detail() != after.Detail() {
				t.Errorf("the detail was rewritten by redaction, so it carried identity:\n"+
					"  local:     %q\n  shareable: %q", before.Detail(), after.Detail())
			}
		})
	}
}

// TestProtocolRedactionIsIdempotent: redacting a shareable report changes
// nothing further.
func TestProtocolRedactionIsIdempotent(t *testing.T) {
	for _, test := range everyProtocolOutcome() {
		t.Run(test.name, func(t *testing.T) {
			once, err := redaction.Redact(protocolReport(t, test.step, test.state, test.class))
			if err != nil {
				t.Fatalf("redacting: %v", err)
			}
			twice, err := redaction.Redact(once)
			if err != nil {
				t.Fatalf("redacting twice: %v", err)
			}
			if marshal(t, once) != marshal(t, twice) {
				t.Error("a second redaction changed the report")
			}
		})
	}
}

// marshal encodes a report for substring inspection.
func marshal(t *testing.T, report domain.Report) string {
	t.Helper()

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	return string(encoded)
}
