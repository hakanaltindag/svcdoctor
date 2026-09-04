package kafka

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Report integration: the rule's output has to survive assembly unchanged.
//
// ADR 0014 validates every evidence reference against the graph at report
// construction, and it fails the whole report on one dangling identifier rather
// than dropping a finding. So "the references resolve" is not a property of the
// rule's unit tests alone — it is the acceptance criterion of the layer above.

// assemble builds a report from a graph and the findings the rule produced.
func assemble(t *testing.T, graph domain.Graph, findings []domain.Finding) domain.Report {
	t.Helper()

	run, err := domain.NewRunMetadata("0.1.0-test", origin, time.Second, "kafka")
	if err != nil {
		t.Fatalf("run metadata: %v", err)
	}
	target, err := domain.NewTarget("primary.internal:9092")
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
		t.Fatalf("assembling the report: %v", err)
	}
	return report
}

// TestEveryAuthorizedFindingAssemblesIntoAReport runs the whole matrix through
// ADR 0014 validation.
func TestEveryAuthorizedFindingAssemblesIntoAReport(t *testing.T) {
	eachShape(t, func(t *testing.T, g domain.Graph, f domain.Finding) {
		report := assemble(t, g, []domain.Finding{f})
		if len(report.Findings()) != 1 {
			t.Fatalf("report findings = %d, want 1", len(report.Findings()))
		}
		if _, err := json.Marshal(report); err != nil {
			t.Errorf("report does not marshal: %v", err)
		}
	})
}

// TestAConfirmedFindingMakesTheRunReportProblems states ADR 0034 section 20's
// operational consequence rather than leaving it to be discovered: one
// unreachable advertised broker makes a Kafka run exit non-zero.
//
// That is accepted deliberately. Exit 1 means "svcdoctor worked and found a
// target-side problem", and an advertised endpoint no client can reach is the
// problem the tool was run to find.
func TestAConfirmedFindingMakesTheRunReportProblems(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	unreachable(b, exchange, 2, "broker-2.internal:9093", "broker-2.internal", "10.20.0.2")
	graph := b.freeze()

	report := assemble(t, graph, AdvertisedEndpointUnreachable(rctx(graph)))
	summary := report.Summary()

	if summary.Status() != domain.SummaryStatusProblemsFound {
		t.Errorf("status = %s, want PROBLEMS_FOUND", summary.Status())
	}
	if got := summary.FindingCountsBySeverity().Error; got != 1 {
		t.Errorf("error findings = %d, want 1", got)
	}
	// firstBrokenLayer is derived from the graph, not from the finding's layer.
	if got := summary.FirstBrokenLayer(); got != domain.LayerTCP {
		t.Errorf("firstBrokenLayer = %s, want L2 from the failing evidence", got)
	}
}

// TestAHypothesisAloneDoesNotReportProblems is the other half: an incomplete
// measurement must never fail a pipeline on svcdoctor's own timeout.
func TestAHypothesisAloneDoesNotReportProblems(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	ad := b.advertised(exchange, 2, "broker-2.internal:9093")
	l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
	b.connect(l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	b.connect(l, "10.20.0.2", 9093, domain.StateUnknown, domain.FailureExecLocalTimeout)
	graph := b.freeze()

	report := assemble(t, graph, AdvertisedEndpointUnreachable(rctx(graph)))
	summary := report.Summary()

	if summary.Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK: a hypothesis is WARN", summary.Status())
	}
	counts := summary.FindingCountsBySeverity()
	if counts.Warn != 1 || counts.Error != 0 || counts.Critical != 0 {
		t.Errorf("counts = %+v, want exactly one WARN", counts)
	}
	if summary.UnknownEvidenceCount() != 1 {
		t.Errorf("unknown evidence count = %d, want 1: the gap must stay visible",
			summary.UnknownEvidenceCount())
	}
}

// TestCanonicalJSONIsStable pins byte-stability across assemblies of the same
// facts recorded in different orders.
func TestCanonicalJSONIsStable(t *testing.T) {
	encode := func(t *testing.T, reversed bool) string {
		t.Helper()
		b := newBuilder(t)
		exchange := b.metadata(domain.StatePass)
		ids := []int64{1, 2, 3}
		if reversed {
			ids = []int64{3, 2, 1}
		}
		for _, id := range ids {
			switch id {
			case 1:
				unreachable(b, exchange, 1, "broker-1.internal:9093", "broker-1.internal", "10.20.0.1")
			case 2:
				unreachable(b, exchange, 2, "broker-2.internal:9093", "broker-2.internal", "10.20.0.2")
			case 3:
				reachable(b, exchange, 3, "broker-3.internal:9093", "broker-3.internal", "10.20.0.3")
			}
		}
		graph := b.freeze()

		encoded, err := json.Marshal(assemble(t, graph, AdvertisedEndpointUnreachable(rctx(graph))).Findings())
		if err != nil {
			t.Fatalf("marshalling findings: %v", err)
		}
		return string(encoded)
	}

	if forward, reverse := encode(t, false), encode(t, true); forward != reverse {
		t.Errorf("encoded findings depend on assembly order:\n %s\n %s", forward, reverse)
	}
}

// TestTheRuleWiresIntoTheEngineUnchanged proves the function already has the
// diagnosis.Rule shape, so no contract change was needed to add the first
// service rule.
//
// There is still no RulesForService and no init registration. Phase 10.1a added
// a Registry, and it changed nothing about that: a registry is assembled by
// explicit wiring at a composition root and holds only what that root put in it
// (ADR 0009, ADR 0080 section 2.4).
func TestTheRuleWiresIntoTheEngineUnchanged(t *testing.T) {
	var _ diagnosis.Rule = AdvertisedEndpointUnreachable

	engine := testEngine(AdvertisedEndpointUnreachable)
	if engine.RuleCount() != 1 {
		t.Fatalf("rule count = %d, want 1", engine.RuleCount())
	}

	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	unreachable(b, exchange, 2, "broker-2.internal:9093", "broker-2.internal", "10.20.0.2")
	reachable(b, exchange, 3, "broker-3.internal:9093", "broker-3.internal", "10.20.0.3")

	findings := engine.Diagnose(rctx(b.freeze()))
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	confirmed(t, findings[0])
}

// TestAnUnusableAdvertisementAssemblesAndReportsProblems covers the Phase 3.7
// finding through report assembly.
//
// It is also the case that exercises docs/REPORT_SCHEMA.md section 7.5 from the
// opposite direction to the reachability finding: here the claim layer and the
// first broken layer **coincide**, because the only FAIL node in the run is the
// advertisement itself and it is an L6 node. The reachability finding has them
// differ. Both are correct, and a reader who has internalized only one of the
// two shapes will misread the other.
func TestAnUnusableAdvertisementAssemblesAndReportsProblems(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	b.unusable(exchange, 2, ":9093", "", 9093)
	graph := b.freeze()

	findings := UnusableAdvertisement(rctx(graph))
	report := assemble(t, graph, findings)
	summary := report.Summary()

	if summary.Status() != domain.SummaryStatusProblemsFound {
		t.Errorf("status = %s, want PROBLEMS_FOUND", summary.Status())
	}
	if got := summary.FindingCountsBySeverity().Error; got != 1 {
		t.Errorf("error findings = %d, want 1", got)
	}
	if got := summary.FirstBrokenLayer(); got != domain.LayerTopology {
		t.Errorf("firstBrokenLayer = %s, want L6: the advertisement node is the only FAIL, "+
			"and no transport was attempted", got)
	}
	if got := report.Findings()[0].Layer(); got != summary.FirstBrokenLayer() {
		t.Errorf("claim layer %s and first broken layer %s: for this finding they coincide",
			got, summary.FirstBrokenLayer())
	}
	if _, err := json.Marshal(report); err != nil {
		t.Errorf("report does not marshal: %v", err)
	}
}

// TestBothKafkaFindingsAssembleTogether runs the composed engine into a report
// and checks ADR 0014 validation over the union of their references.
func TestBothKafkaFindingsAssembleTogether(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	unreachable(b, exchange, 2, "broker-2.internal:9092", "broker-2.internal", "10.20.0.2")
	b.unusable(exchange, 3, "broker-3.internal:0", "broker-3.internal", 0)
	graph := b.freeze()

	report := assemble(t, graph, bothRules().Diagnose(rctx(graph)))
	if len(report.Findings()) != 2 {
		t.Fatalf("findings = %d, want 2", len(report.Findings()))
	}

	counts := report.Summary().FindingCountsBySeverity()
	if counts.Error != 2 {
		t.Errorf("error findings = %d, want 2", counts.Error)
	}
	// The lowest FAIL layer across the graph, which is the transport failure of
	// the *other* broker rather than either finding's claim layer.
	if got := report.Summary().FirstBrokenLayer(); got != domain.LayerTCP {
		t.Errorf("firstBrokenLayer = %s, want L2", got)
	}
	for _, f := range report.Findings() {
		for _, ref := range f.EvidenceRefs() {
			if _, ok := graph.Node(ref); !ok {
				t.Errorf("%s references %s, which is not in the graph", f.Code(), ref)
			}
		}
	}
}
