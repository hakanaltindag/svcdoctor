package security

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	diagnosiskafka "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// The security check for Phase 3.7.
//
// An unusable advertisement is a new shape for redaction: its subject is not a
// well-formed endpoint. ":9093" has no host at all and "broker:-1" has no usable
// port, so neither takes the ordinary host:port path through the pseudonym
// table. That is worth checking directly rather than assuming the reachability
// finding's result carries over.

const (
	unusableCanaryHost = "broker-9.corp-unusable.internal"
	unusableBootstrap  = "bootstrap.corp-unusable.internal"
)

// unusableReport builds a Metadata exchange carrying one unusable advertisement
// and diagnoses it with the real rule.
func unusableReport(t *testing.T, ref, host string, port int64) domain.Report {
	t.Helper()

	builder := domain.NewGraphBuilder()
	at := time.Date(2026, 8, 22, 11, 30, 0, 0, time.UTC)

	add := func(
		id, subject string, step domain.Step, state domain.State,
		class domain.FailureClass, parent domain.EvidenceID,
		attributes map[domain.AttributeKey]domain.AttrValue,
	) domain.EvidenceID {
		t.Helper()
		ref, err := domain.NewEndpointSubject(subject)
		if err != nil {
			t.Fatalf("subject %q: %v", subject, err)
		}
		at = at.Add(time.Millisecond)
		evidence, err := domain.NewEvidence(domain.EvidenceInput{
			ID: domain.EvidenceID(id), Subject: ref, Layer: domain.LayerTopology,
			Step: step, State: state, FailureClass: class, Attributes: attributes,
			StartedAt: at, Duration: time.Millisecond,
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

	exchange := add(
		"kafka.metadata/"+unusableBootstrap+":9092/10.9.0.1", unusableBootstrap+":9092",
		servicekafka.StepMetadata, domain.StatePass, domain.FailureNone, "",
		map[domain.AttributeKey]domain.AttrValue{
			"kafka.metadata.controller_id": domain.IntAttr(1),
		})

	add(
		"kafka.broker_advertised/"+unusableBootstrap+":9092/10.9.0.1/9/"+ref, ref,
		servicekafka.StepBrokerAdvertised, domain.StateFail,
		domain.FailureProtocolUnexpectedResponse, exchange,
		map[domain.AttributeKey]domain.AttrValue{
			servicekafka.AttrBrokerNodeID:  domain.IntAttr(9),
			"kafka.broker.advertised_host": domain.HostAttr(host),
			"kafka.broker.advertised_port": domain.IntAttr(port),
		})

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("freezing: %v", err)
	}

	findings := diagnosiskafka.UnusableAdvertisement(graph)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}

	run, err := domain.NewRunMetadata("0.1.0-test", at, time.Second, "kafka")
	if err != nil {
		t.Fatal(err)
	}
	target, err := domain.NewTarget(unusableBootstrap + ":9092")
	if err != nil {
		t.Fatal(err)
	}
	vantage, err := domain.NewLocalVantage("runner.corp-unusable.internal")
	if err != nil {
		t.Fatal(err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatal(err)
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

// TestTheUnusableCanariesActuallyTravel is the control. A leak test that passes
// because the value was never present proves nothing.
func TestTheUnusableCanariesActuallyTravel(t *testing.T) {
	report := unusableReport(t, unusableCanaryHost+":70000", unusableCanaryHost, 70000)
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	for _, canary := range []string{unusableCanaryHost, unusableBootstrap} {
		if !strings.Contains(string(encoded), canary) {
			t.Fatalf("canary %q absent from the local report; the leak test would be vacuous", canary)
		}
	}
}

// TestAnUnusableAdvertisementLeaksNothing is the check itself, over the two
// shapes that differ structurally: an advertised host with an impossible port,
// and no advertised host at all.
func TestAnUnusableAdvertisementLeaksNothing(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		host string
		port int64
	}{
		{"host present, port impossible", unusableCanaryHost + ":70000", unusableCanaryHost, 70000},
		{"no host advertised", ":9093", "", 9093},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			shareable, err := redaction.Redact(unusableReport(t, tc.ref, tc.host, tc.port))
			if err != nil {
				t.Fatalf("redacting: %v", err)
			}
			encoded, err := json.Marshal(shareable)
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			for _, canary := range []string{unusableCanaryHost, unusableBootstrap, "corp-unusable"} {
				if strings.Contains(string(encoded), canary) {
					t.Errorf("shareable report leaks %q", canary)
				}
			}
		})
	}
}

// TestTheUnusableFindingStaysUsefulAfterRedaction checks that removing identity
// did not remove meaning.
func TestTheUnusableFindingStaysUsefulAfterRedaction(t *testing.T) {
	local := unusableReport(t, unusableCanaryHost+":70000", unusableCanaryHost, 70000)
	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("redacting: %v", err)
	}

	before, after := local.Findings()[0], shareable.Findings()[0]

	if after.Code() != before.Code() {
		t.Errorf("code changed: %s -> %s", before.Code(), after.Code())
	}
	if after.Kind() != before.Kind() || after.Severity() != before.Severity() ||
		after.Confidence() != before.Confidence() || after.Layer() != before.Layer() {
		t.Error("redaction changed a classification field")
	}
	if after.VantageDependent() {
		t.Error("redaction turned on vantageDependent")
	}
	if after.Subject().Kind() != domain.SubjectKindEndpoint {
		t.Errorf("subject kind = %s, want the endpoint kind preserved", after.Subject().Kind())
	}
	if after.Subject().Ref() == "" {
		t.Error("the finding lost its subject entirely")
	}
	for _, ref := range after.EvidenceRefs() {
		if _, ok := shareable.Graph().Node(ref); !ok {
			t.Errorf("reference %s does not resolve in the redacted graph", ref)
		}
	}

	// Prose carries no identity, so it must survive untouched.
	if before.Summary() != after.Summary() {
		t.Errorf("summary was rewritten by redaction:\n %q\n %q", before.Summary(), after.Summary())
	}
	if before.Detail() != after.Detail() {
		t.Error("detail was rewritten by redaction")
	}
	if before.Recommendations()[0].Action() != after.Recommendations()[0].Action() {
		t.Error("the recommendation was rewritten by redaction")
	}
	// The node identifier is what tells two redacted unusable advertisements
	// apart, so it must survive.
	if !strings.Contains(after.Summary(), "broker node 9") {
		t.Errorf("summary no longer names the broker: %q", after.Summary())
	}
}

// TestAnAdvertisementWithNoHostRedactsWithoutInventingOne is the shape most
// likely to go wrong quietly.
//
// ":9093" has no host. Redaction must not substitute a pseudonym there, because
// a reader of the shareable report would then see "host-001:9093" and conclude
// the cluster advertised a host — which is the opposite of what the finding
// says. The absence is the evidence.
func TestAnAdvertisementWithNoHostRedactsWithoutInventingOne(t *testing.T) {
	shareable, err := redaction.Redact(unusableReport(t, ":9093", "", 9093))
	if err != nil {
		t.Fatalf("redacting: %v", err)
	}

	got := shareable.Findings()[0].Subject().Ref()
	if got != ":9093" {
		t.Errorf("subject ref = %q, want %q: redaction must not invent a host that was "+
			"never advertised, and there is no identity here to remove", got, ":9093")
	}
}

// TestKnownDefectAdvertisedRefCollidingWithJSONPunctuation pins a **bug**, not a
// contract, so that it is visible and so that fixing it is noticed here.
//
// A broker advertising host="" and port=0 produces the subject ":0". Redaction
// classifies that as a hostname — splitHostPort rejects "0" as a port, so the
// whole ref becomes the host — and then verifyNoResidual scans the encoded
// report for the literal text ":0". Every report contains it: `"info":0` in the
// severity counts, and any timestamp with a zero in the seconds field. The scan
// matches its own punctuation and redaction fails closed on a transformation
// that actually succeeded.
//
// The consequence is that **no shareable report can be produced for a run in
// which a broker advertises ":0"**, which is a producible case — the adapter's
// own TestUnusableAdvertisementsBecomeEvidence covers it.
//
// This predates Phase 3.7 and is not caused by the finding: the subject is on
// the evidence node whether or not any rule reads it. It is recorded here rather
// than worked around, because widening the residual scan is a change to a
// security-critical component and needs its own decision.
//
// **Delete this test when the defect is fixed.**
func TestKnownDefectAdvertisedRefCollidingWithJSONPunctuation(t *testing.T) {
	_, err := redaction.Redact(unusableReport(t, ":0", "", 0))
	if err == nil {
		t.Fatal("redaction now succeeds for the \":0\" advertisement — the known defect is " +
			"fixed, so delete this test and add a positive one in its place")
	}
	if !errors.Is(err, redaction.ErrRedaction) {
		t.Fatalf("error = %v, want a redaction error", err)
	}
	if !strings.Contains(err.Error(), "hostname survived redaction") {
		t.Errorf("error = %v, want the residual-hostname false positive", err)
	}
}
