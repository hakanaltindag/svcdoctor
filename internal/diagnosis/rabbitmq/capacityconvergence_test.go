package rabbitmq_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosisrabbitmq "github.com/hakanaltindag/svcdoctor/internal/diagnosis/rabbitmq"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// Phase 10.8B — convergence and evidence membership, through the real engine.
//
// This file is an external test package on purpose. It exercises the rule the
// way `internal/app` does — registered in a RuleSet, evaluated by the Engine,
// merged by the real convergence code — because the property at risk is a
// property of the *engine's* treatment of the rule's output, and a test that
// called the rule directly would never see a merge at all.
//
// # Why Detail changing touches convergence
//
// ADR 0081 §2.2b made Summary and Detail merge **preconditions**: two findings
// converge only when every field a consumer parses already agrees. Phase 10.8B
// makes Detail vary by capacity scope, so two capacity findings at one subject
// now disagree where they used to agree — and the whole question is whether
// that produces two honest findings or one dishonest one.
//
// RCCE-014 … RCCE-018.

// openAt builds one connection-open node with an explicit id and subject.
func openAt(t *testing.T, id, ref string, class domain.FailureClass, outcome string) domain.Evidence {
	t.Helper()
	subject, err := domain.NewEndpointSubject(ref)
	if err != nil {
		t.Fatalf("subject %q: %v", ref, err)
	}
	attrs := map[domain.AttributeKey]domain.AttrValue{}
	if outcome != "" {
		attrs[servicerabbitmq.AttrCloseOutcome] = domain.StringAttr(outcome)
	}
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           domain.EvidenceID(id),
		Subject:      subject,
		Layer:        domain.LayerAuth,
		Step:         servicerabbitmq.StepConnectionOpen,
		State:        domain.StateFail,
		FailureClass: class,
		Attributes:   attrs,
		StartedAt:    time.Unix(0, 0).UTC(),
		Elapsed:      domain.Measured(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("evidence %q: %v", id, err)
	}
	return evidence
}

// evaluate wires the connection-open rule exactly as internal/app does and runs
// the real engine, so convergence is the production code path.
func evaluate(t *testing.T, nodes ...domain.Evidence) []domain.Finding {
	t.Helper()
	builder := domain.NewGraphBuilder()
	for _, n := range nodes {
		if err := builder.AddEvidence(n); err != nil {
			t.Fatalf("add %s: %v", n.ID(), err)
		}
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	registry, err := diagnosis.NewRuleSet().
		Add("rabbitmq/connection-open", diagnosisrabbitmq.ConnectionOpen).
		Freeze()
	if err != nil {
		t.Fatalf("ruleset: %v", err)
	}
	return diagnosis.NewEngine(registry).Evaluate(diagnosis.RuleContext{Graph: graph}).Findings()
}

func detailsOf(findings []domain.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Detail())
	}
	return out
}

// --- Case A: same subject, same capacity outcome ----------------------------

// TestConvergenceSameSubjectSameOutcome is the case where merging is honest.
//
// Both findings say the identical sentence about the identical scope, so a
// merged finding takes a value both rules stated. Whether the engine merges or
// keeps two is its decision; what this pins is that the surviving prose names
// the node scope and only the node scope.
func TestConvergenceSameSubjectSameOutcome(t *testing.T) {
	findings := evaluate(t,
		openAt(t, "rabbitmq.connection_open|a", "192.0.2.10:5672",
			domain.FailureResourceLimitReached, string(servicerabbitmq.CloseNodeConnectionLimit)),
		openAt(t, "rabbitmq.connection_open|b", "192.0.2.10:5672",
			domain.FailureResourceLimitReached, string(servicerabbitmq.CloseNodeConnectionLimit)),
	)

	for _, detail := range detailsOf(findings) {
		if !strings.Contains(detail, "scoped to the node.") {
			t.Errorf("a surviving finding lost the node scope: %q", detail)
		}
		if strings.Contains(detail, "scoped to the user.") ||
			strings.Contains(detail, "scoped to the virtual host.") {
			t.Errorf("a surviving finding named a scope nobody measured: %q", detail)
		}
	}
}

// --- Case B: same subject, different capacity outcomes ----------------------

// TestConvergenceSameSubjectDifferentOutcomesDoesNotCollapse is the case this
// phase most had to get right.
//
// A node ceiling and a user ceiling at one endpoint are two different facts with
// two different owners. Merging them into one finding whose prose names one
// while its evidence cites both is exactly the defect Phase 10.2A found in Kafka
// and exactly what ADR 0081 §2.2b's precondition prevents — **and it prevents it
// because Detail differs**, which is a property this phase created rather than
// inherited.
//
// Two findings that look like duplicates are safer than one whose sentence
// describes half its own evidence.
func TestConvergenceSameSubjectDifferentOutcomesDoesNotCollapse(t *testing.T) {
	findings := evaluate(t,
		openAt(t, "rabbitmq.connection_open|node", "192.0.2.10:5672",
			domain.FailureResourceLimitReached, string(servicerabbitmq.CloseNodeConnectionLimit)),
		openAt(t, "rabbitmq.connection_open|user", "192.0.2.10:5672",
			domain.FailureResourceLimitReached, string(servicerabbitmq.CloseUserConnectionLimit)),
	)

	if len(findings) != 2 {
		t.Fatalf("two different capacity scopes produced %d findings, want 2:\n%v",
			len(findings), detailsOf(findings))
	}

	var node, user bool
	for _, f := range findings {
		switch {
		case strings.Contains(f.Detail(), "scoped to the node."):
			node = true
		case strings.Contains(f.Detail(), "scoped to the user."):
			user = true
		default:
			t.Errorf("a finding named neither measured scope: %q", f.Detail())
		}
		// Neither may cite both nodes: that is the shape where prose would
		// describe half its evidence.
		if f.EvidenceRefCount() != 1 {
			t.Errorf("a scope-specific finding cites %d nodes, want 1", f.EvidenceRefCount())
		}
	}
	if !node || !user {
		t.Errorf("both scopes must survive; node=%v user=%v", node, user)
	}
}

// --- Case C: mapped capacity outcome beside a generic resource limit --------

// TestConvergenceMappedAndGenericDoNotCollapse covers the truncation case in
// production shape.
//
// A real ceiling whose reply text was truncated arrives as UNSPECIFIED_TRUNCATED
// and gets the generic explanation. Beside a classified one at the same subject,
// merging would let the specific sentence absorb evidence that never named a
// scope — less evidence producing a stronger claim, which is the Phase 10.2A
// defect in its third form.
func TestConvergenceMappedAndGenericDoNotCollapse(t *testing.T) {
	findings := evaluate(t,
		openAt(t, "rabbitmq.connection_open|mapped", "192.0.2.10:5672",
			domain.FailureResourceLimitReached, string(servicerabbitmq.CloseVHostConnectionLimit)),
		openAt(t, "rabbitmq.connection_open|generic", "192.0.2.10:5672",
			domain.FailureResourceLimitReached, string(servicerabbitmq.CloseUnspecifiedTruncated)),
	)

	if len(findings) != 2 {
		t.Fatalf("a mapped and a generic refusal produced %d findings, want 2:\n%v",
			len(findings), detailsOf(findings))
	}
	for _, f := range findings {
		if strings.Contains(f.Detail(), "scoped to the virtual host.") &&
			f.EvidenceRefCount() != 1 {
			t.Error("the specific explanation absorbed evidence that named no scope")
		}
	}
}

// --- Case D: different subjects ---------------------------------------------

// TestConvergenceDifferentSubjectsStayDistinct pins that the subject still
// separates findings, and that each carries its own endpoint's scope.
func TestConvergenceDifferentSubjectsStayDistinct(t *testing.T) {
	findings := evaluate(t,
		openAt(t, "rabbitmq.connection_open|one", "192.0.2.10:5672",
			domain.FailureResourceLimitReached, string(servicerabbitmq.CloseNodeConnectionLimit)),
		openAt(t, "rabbitmq.connection_open|two", "198.51.100.20:5672",
			domain.FailureResourceLimitReached, string(servicerabbitmq.CloseUserConnectionLimit)),
	)

	if len(findings) != 2 {
		t.Fatalf("two subjects produced %d findings, want 2", len(findings))
	}
	for _, f := range findings {
		switch f.Subject().Ref() {
		case "192.0.2.10:5672":
			if !strings.Contains(f.Detail(), "scoped to the node.") {
				t.Errorf("the first endpoint got the wrong scope: %q", f.Detail())
			}
		case "198.51.100.20:5672":
			if !strings.Contains(f.Detail(), "scoped to the user.") {
				t.Errorf("the second endpoint got the wrong scope: %q", f.Detail())
			}
		default:
			t.Errorf("unexpected subject %q", f.Subject().Ref())
		}
	}
}

// --- RCCE-016: evidence membership -------------------------------------------

// TestAnotherNodesOutcomeCannotEnrichThisFinding is the cross-evidence proof.
//
// The graph holds one refusal that named no scope and a second, at a different
// endpoint, that named a user ceiling. A lookup that searched the graph — or
// that took the first RabbitMQ close outcome it found — would put the second
// endpoint's scope on the first endpoint's finding.
//
// The implementation cannot do this: connectionNotPermittedDetail reads the
// evidence node it is handed, which is the node whose identifier becomes the
// finding's only EvidenceRef. This asserts the consequence anyway, because the
// structural property is the kind that a later refactor can quietly lose.
func TestAnotherNodesOutcomeCannotEnrichThisFinding(t *testing.T) {
	findings := evaluate(t,
		openAt(t, "rabbitmq.connection_open|bare", "192.0.2.10:5672",
			domain.FailureAuthzNotPermitted, string(servicerabbitmq.CloseUnspecified)),
		openAt(t, "rabbitmq.connection_open|scoped", "198.51.100.20:5672",
			domain.FailureResourceLimitReached, string(servicerabbitmq.CloseUserConnectionLimit)),
	)

	if len(findings) != 2 {
		t.Fatalf("produced %d findings, want 2", len(findings))
	}
	for _, f := range findings {
		if f.Subject().Ref() != "192.0.2.10:5672" {
			continue
		}
		if strings.Contains(f.Detail(), "scoped to") {
			t.Errorf("an endpoint that named no scope acquired one from a sibling: %q",
				f.Detail())
		}
	}
}
