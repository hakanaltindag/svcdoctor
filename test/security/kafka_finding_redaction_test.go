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

// The security check for Phase 3.6: the first finding svcdoctor produces, taken
// through redaction.
//
// Everything before this proved that *evidence* redacts. A finding is a new kind
// of carrier — it has a subject, prose, recommendations and a discriminator, and
// each of those is a place a hostname could reach a shared report by a route
// structural redaction of the graph would never see.
//
// The rule is written so that no new redaction heuristic is needed: identity
// travels on the subject and on the referenced evidence, where redaction already
// transforms it, and the prose carries the broker's node identifier and nothing
// else. This test is what makes that a checked property rather than a claim.

const (
	// Canaries. They appear nowhere else in the repository, so finding one in a
	// shareable report is unambiguous.
	findingCanaryHost = "broker-77.corp-secret.internal"
	findingCanaryIP   = "10.77.78.79"
)

// unreachableAdvertisementReport builds a graph in the shape Phase 3.3 and
// Phase 3.4 produce, diagnoses it, and assembles a local report.
func unreachableAdvertisementReport(t *testing.T) domain.Report {
	t.Helper()

	builder := domain.NewGraphBuilder()
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

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

	exchange := add(
		"kafka.metadata/bootstrap.example:9092/10.0.0.1", "bootstrap.example:9092",
		domain.LayerTopology, servicekafka.StepMetadata,
		domain.StatePass, domain.FailureNone, "", nil)

	advertisement := add(
		"kafka.broker_advertised/bootstrap.example:9092/10.0.0.1/77/"+findingCanaryHost+":9093",
		findingCanaryHost+":9093",
		domain.LayerTopology, servicekafka.StepBrokerAdvertised,
		domain.StatePass, domain.FailureNone, exchange,
		map[domain.AttributeKey]domain.AttrValue{
			servicekafka.AttrBrokerNodeID:  domain.IntAttr(77),
			"kafka.broker.advertised_host": domain.HostAttr(findingCanaryHost),
			"kafka.broker.advertised_port": domain.IntAttr(9093),
		})

	lookup := add(
		"dns.lookup/advertised.abc123/"+findingCanaryHost, findingCanaryHost,
		domain.LayerDNS, "dns.lookup", domain.StatePass, domain.FailureNone, advertisement,
		map[domain.AttributeKey]domain.AttrValue{
			"dns.answers": domain.HostListAttr(findingCanaryIP),
		})

	add(
		"tcp.connect/advertised.abc123/"+findingCanaryIP, findingCanaryIP+":9093",
		domain.LayerTCP, "tcp.connect", domain.StateFail, domain.FailureTCPConnectionRefused,
		lookup, nil)

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("freezing: %v", err)
	}

	findings := diagnosiskafka.AdvertisedEndpointUnreachable(graph)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}

	run, err := domain.NewRunMetadata("0.1.0-test", at, time.Second, "kafka")
	if err != nil {
		t.Fatalf("run metadata: %v", err)
	}
	target, err := domain.NewTarget("bootstrap.example:9092")
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	vantage, err := domain.NewLocalVantage("workstation.local")
	if err != nil {
		t.Fatalf("vantage: %v", err)
	}
	reportSecurity, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("report security: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage,
		Graph: graph, Findings: findings, Security: reportSecurity,
	})
	if err != nil {
		t.Fatalf("assembling: %v", err)
	}
	return report
}

// TestTheFindingCanariesActuallyTravel is the control. A leak test that passes
// because the value was never in the report proves nothing.
func TestTheFindingCanariesActuallyTravel(t *testing.T) {
	encoded, err := json.Marshal(unreachableAdvertisementReport(t))
	if err != nil {
		t.Fatalf("marshalling the local report: %v", err)
	}
	for _, canary := range []string{findingCanaryHost, findingCanaryIP} {
		if !strings.Contains(string(encoded), canary) {
			t.Fatalf("canary %q is absent from the unredacted report; the leak test is vacuous", canary)
		}
	}
}

// TestAShareableFindingLeaksNoIdentity is the check itself.
func TestAShareableFindingLeaksNoIdentity(t *testing.T) {
	shareable, err := redaction.Redact(unreachableAdvertisementReport(t))
	if err != nil {
		t.Fatalf("redacting: %v", err)
	}
	encoded, err := json.Marshal(shareable)
	if err != nil {
		t.Fatalf("marshalling the shareable report: %v", err)
	}
	for _, canary := range []string{findingCanaryHost, findingCanaryIP} {
		if strings.Contains(string(encoded), canary) {
			t.Errorf("shareable report leaks %q", canary)
		}
	}
}

// TestTheFindingStaysCorrelatedAfterRedaction is the other half. Removing
// identity must not remove meaning: the finding must still name a pseudonymous
// subject and must still point at nodes that exist in the redacted graph, or a
// shared report can no longer answer "why did svcdoctor say this?".
func TestTheFindingStaysCorrelatedAfterRedaction(t *testing.T) {
	local := unreachableAdvertisementReport(t)
	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("redacting: %v", err)
	}

	if len(shareable.Findings()) != 1 {
		t.Fatalf("findings = %d, want the finding to survive redaction", len(shareable.Findings()))
	}
	before, after := local.Findings()[0], shareable.Findings()[0]

	if after.Code() != before.Code() {
		t.Errorf("code changed: %s -> %s", before.Code(), after.Code())
	}
	if after.Kind() != before.Kind() || after.Severity() != before.Severity() ||
		after.Confidence() != before.Confidence() {
		t.Error("redaction changed a finding's kind, severity or confidence")
	}
	if !after.VantageDependent() {
		t.Error("redaction dropped vantageDependent; the claim is meaningless without it")
	}
	if after.Subject().Kind() != domain.SubjectKindEndpoint {
		t.Errorf("subject kind = %s, want the endpoint kind preserved", after.Subject().Kind())
	}
	if after.Subject().Ref() == "" {
		t.Error("the finding lost its subject entirely")
	}

	if len(after.EvidenceRefs()) != len(before.EvidenceRefs()) {
		t.Fatalf("evidence refs = %d, want %d", len(after.EvidenceRefs()), len(before.EvidenceRefs()))
	}
	for _, ref := range after.EvidenceRefs() {
		if _, ok := shareable.Graph().Node(ref); !ok {
			t.Errorf("reference %s does not resolve in the redacted graph", ref)
		}
	}
}

// TestTheBrokerNodeIDSurvivesRedaction pins the deliberate exception. A node
// identifier names a position in a cluster rather than a host or an address, so
// it is not identity in the redaction sense — and it is the only thing left that
// tells a reader which broker a shared finding is about.
func TestTheBrokerNodeIDSurvivesRedaction(t *testing.T) {
	shareable, err := redaction.Redact(unreachableAdvertisementReport(t))
	if err != nil {
		t.Fatalf("redacting: %v", err)
	}
	if got := shareable.Findings()[0].Summary(); !strings.Contains(got, "broker node 77") {
		t.Errorf("summary = %q, want it to still name the broker", got)
	}
}

// TestTheFindingProseNeededNoNewHeuristic states the design property directly:
// the prose is identical before and after, because it never carried identity in
// the first place.
func TestTheFindingProseNeededNoNewHeuristic(t *testing.T) {
	local := unreachableAdvertisementReport(t)
	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("redacting: %v", err)
	}
	before, after := local.Findings()[0], shareable.Findings()[0]

	if before.Summary() != after.Summary() {
		t.Errorf("summary was rewritten by redaction:\n %q\n %q", before.Summary(), after.Summary())
	}
	if before.Detail() != after.Detail() {
		t.Errorf("detail was rewritten by redaction:\n %q\n %q", before.Detail(), after.Detail())
	}
	if len(before.Recommendations()) != len(after.Recommendations()) {
		t.Fatal("redaction changed the number of recommendations")
	}
	for i := range before.Recommendations() {
		if before.Recommendations()[i].Action() != after.Recommendations()[i].Action() {
			t.Errorf("recommendation %d was rewritten by redaction", i)
		}
	}
}
