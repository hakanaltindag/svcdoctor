// Package diagnosis_test drives the activated reasoning pipeline end to end.
//
// Phase 10.1B activated generic diagnosis in production. The engine's own tests
// prove the machinery; these prove the *pipeline*: a frozen graph goes into the
// same registry the composition roots wire, the findings go into a real
// domain.Report, and the report goes into a real renderer. Nothing here builds a
// finding by hand and nothing here stubs a layer.
//
// The scenarios are numbered S01-S10 and the refusals FP01-FP05, matching the
// Phase 10.1B contract so a reader can find one from the other.
package diagnosis_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/render"
	renderjson "github.com/hakanaltindag/svcdoctor/internal/render/json"
	renderterminal "github.com/hakanaltindag/svcdoctor/internal/render/terminal"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
)

// fixedStart keeps every rendered artifact reproducible.
var fixedStart = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

// graphSpec accumulates one scenario's evidence.
type graphSpec struct {
	t *testing.T
	b *domain.GraphBuilder
}

func newGraph(t *testing.T) *graphSpec {
	t.Helper()
	return &graphSpec{t: t, b: domain.NewGraphBuilder()}
}

// node records one measured step.
//
// The failure class is derived from the state rather than taken as an argument,
// because no scenario here turns on which class it was: every one of these tests
// is about states, layers and structure.
func (s *graphSpec) node(
	id, subjectRef string, layer domain.Layer, step string, state domain.State,
) domain.EvidenceID {
	s.t.Helper()

	class := domain.FailureNone
	elapsed := domain.Measured(time.Millisecond)
	switch state {
	case domain.StateFail:
		class = domain.FailureTCPConnectionRefused
	case domain.StateSkipped:
		class = domain.FailureExecSkippedPrerequisiteFailed
		elapsed = domain.Unmeasured()
	case domain.StateUnknown:
		class = domain.FailureExecLocalTimeout
		elapsed = domain.Unmeasured()
	case domain.StateDegraded:
		class = domain.FailureTLSCertificateExpired
	case domain.StatePass:
	}

	subject, err := domain.NewEndpointSubject(subjectRef)
	if err != nil {
		s.t.Fatalf("NewEndpointSubject(%q): %v", subjectRef, err)
	}
	stepName, err := domain.NewStep(step)
	if err != nil {
		s.t.Fatalf("NewStep(%q): %v", step, err)
	}
	evidenceID, err := domain.NewEvidenceID(id)
	if err != nil {
		s.t.Fatalf("NewEvidenceID(%q): %v", id, err)
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID: evidenceID, Subject: subject, Layer: layer, Step: stepName,
		State: state, FailureClass: class, StartedAt: fixedStart, Elapsed: elapsed,
	})
	if err != nil {
		s.t.Fatalf("NewEvidence(%q): %v", id, err)
	}
	if err := s.b.AddEvidence(evidence); err != nil {
		s.t.Fatalf("AddEvidence(%q): %v", id, err)
	}
	return evidenceID
}

// nodeWithClass records a step whose failure class the scenario turns on.
//
// The false-positive corpus needs it: a TCP timeout and a TCP refusal are the
// same state and different claims, and which one a rule may make is exactly the
// distinction those tests are about.
func (s *graphSpec) nodeWithClass(
	id, subjectRef string, layer domain.Layer, step string,
	state domain.State, class domain.FailureClass,
) domain.EvidenceID {
	s.t.Helper()

	subject, err := domain.NewEndpointSubject(subjectRef)
	if err != nil {
		s.t.Fatalf("NewEndpointSubject(%q): %v", subjectRef, err)
	}
	stepName, err := domain.NewStep(step)
	if err != nil {
		s.t.Fatalf("NewStep(%q): %v", step, err)
	}
	evidenceID, err := domain.NewEvidenceID(id)
	if err != nil {
		s.t.Fatalf("NewEvidenceID(%q): %v", id, err)
	}

	elapsed := domain.Measured(time.Millisecond)
	if state == domain.StateUnknown || state == domain.StateSkipped {
		elapsed = domain.Unmeasured()
	}

	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID: evidenceID, Subject: subject, Layer: layer, Step: stepName,
		State: state, FailureClass: class, StartedAt: fixedStart, Elapsed: elapsed,
	})
	if err != nil {
		s.t.Fatalf("NewEvidence(%q): %v", id, err)
	}
	if err := s.b.AddEvidence(evidence); err != nil {
		s.t.Fatalf("AddEvidence(%q): %v", id, err)
	}
	return evidenceID
}

func (s *graphSpec) parent(child, parent domain.EvidenceID) {
	s.t.Helper()
	if err := s.b.AddParent(child, parent); err != nil {
		s.t.Fatalf("AddParent: %v", err)
	}
}

func (s *graphSpec) blocked(skipped, blocker domain.EvidenceID) {
	s.t.Helper()
	if err := s.b.AddBlockedBy(skipped, blocker); err != nil {
		s.t.Fatalf("AddBlockedBy: %v", err)
	}
}

func (s *graphSpec) freeze() domain.Graph {
	s.t.Helper()
	g, err := s.b.Freeze()
	if err != nil {
		s.t.Fatalf("Freeze: %v", err)
	}
	return g
}

// run is one scenario's whole pipeline result.
type run struct {
	graph     domain.Graph
	outcome   diagnosis.Outcome
	report    domain.Report
	shareable domain.Report
}

// diagnose drives graph -> engine -> report, exactly as a composition root does.
func diagnose(t *testing.T, g domain.Graph, incomplete bool, extra ...namedRule) run {
	t.Helper()

	set := diagnosis.NewRuleSet().Add("diag/failure-boundary", diagnosis.FailureBoundary)
	for _, r := range extra {
		set.Add(r.id, r.rule)
	}
	registry, err := set.Freeze()
	if err != nil {
		t.Fatalf("freezing the rule set: %v", err)
	}

	vantage, err := domain.NewLocalVantage("test-host")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	outcome := diagnosis.NewEngine(registry).Evaluate(diagnosis.RuleContext{
		Graph:      g,
		Vantage:    vantage,
		Incomplete: incomplete,
	})

	runMeta, err := domain.NewRunMetadata("0.0.0-test", fixedStart, time.Second, "postgres")
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget("db.example:5432")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run: runMeta, Target: target, Vantage: vantage,
		Graph: g, Findings: outcome.Findings(), Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}

	shareable, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	return run{graph: g, outcome: outcome, report: report, shareable: shareable}
}

type namedRule struct {
	id   string
	rule diagnosis.Rule
}

// boundaries returns the boundary findings, keyed by subject reference.
func (r run) boundaries(t *testing.T) map[string]domain.Finding {
	t.Helper()

	out := map[string]domain.Finding{}
	for _, f := range r.report.Findings() {
		if f.Code() != diagnosis.CodeFailureBoundary {
			continue
		}
		ref := f.Subject().Ref()
		if _, dup := out[ref]; dup {
			t.Fatalf("two boundaries for subject %q; identity is (Code, Subject)", ref)
		}
		out[ref] = f
	}
	return out
}

// terminal renders the report the way an operator sees it.
func (r run) terminal(t *testing.T) string {
	t.Helper()

	var out bytes.Buffer
	if err := renderterminal.Write(&out, render.Input{Report: r.report}); err != nil {
		t.Fatalf("terminal.Write: %v", err)
	}
	return out.String()
}

// canonicalJSON renders the source of truth.
func (r run) canonicalJSON(t *testing.T) string {
	t.Helper()

	var out bytes.Buffer
	if err := renderjson.Write(&out, r.report); err != nil {
		t.Fatalf("json.Write: %v", err)
	}
	return out.String()
}

// shareableJSON renders the redacted projection.
func (r run) shareableJSON(t *testing.T) string {
	t.Helper()

	var out bytes.Buffer
	if err := renderjson.Write(&out, r.shareable); err != nil {
		t.Fatalf("json.Write: %v", err)
	}
	return out.String()
}

// stateOf reads a node's state back out of the graph, for the tests that assert
// diagnosis changed nothing.
func stateOf(t *testing.T, g domain.Graph, id domain.EvidenceID) domain.State {
	t.Helper()

	node, ok := g.Node(id)
	if !ok {
		t.Fatalf("evidence %q is not in the graph", id)
	}
	return node.State()
}

// encode is the byte-level comparison several determinism tests need.
func encode(t *testing.T, v any) string {
	t.Helper()

	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(out)
}
