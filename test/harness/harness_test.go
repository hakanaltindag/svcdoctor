package harness

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The harness's own tests.
//
// # What these prove
//
// That each assertion **can fail**, and fails for the reason it claims. A
// helper that silently passes is worse than no helper: every scenario that
// leans on it becomes a green test asserting nothing, which is the exact
// failure mode Phase 7.6A found in a hand-written guard.
//
// They are not a matrix over the assertion surface. Each one drives a distinct
// mechanism through `Assert` and checks the recorded failure names the right
// thing.

const (
	testStep  = domain.Step("probe.step")
	otherStep = domain.Step("probe.other")
	testCode  = domain.FindingCode("TEST_CODE")
	otherCode = domain.FindingCode("OTHER_CODE")
)

// recorder is a T that remembers what Assert reported instead of failing a test.
type recorder struct{ messages []string }

var errFatal = errors.New("harness: Fatalf")

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.messages = append(r.messages, fmt.Sprintf(format, args...))
}

// Fatalf records and unwinds, mirroring testing.T's stop-this-test semantics.
func (r *recorder) Fatalf(format string, args ...any) {
	r.Errorf(format, args...)
	panic(errFatal)
}

func (r *recorder) failed() bool { return len(r.messages) > 0 }

func (r *recorder) joined() string { return strings.Join(r.messages, "\n") }

// check runs Assert against a recorder and returns it.
func check(s Subject, e Expectation) (rec *recorder) {
	rec = &recorder{}
	defer func() {
		if p := recover(); p != nil && !errors.Is(p.(error), errFatal) {
			panic(p)
		}
	}()
	Assert(rec, s, e)
	return rec
}

// mustReject asserts the expectation was not satisfied, and that the complaint
// mentions `wants` so the failure is for the intended reason.
func mustReject(t *testing.T, name string, s Subject, e Expectation, wants ...string) {
	t.Helper()
	rec := check(s, e)
	if !rec.failed() {
		t.Errorf("%s: the harness accepted a subject it should have rejected", name)
		return
	}
	for _, want := range wants {
		if !strings.Contains(strings.ToLower(rec.joined()), strings.ToLower(want)) {
			t.Errorf("%s: the complaint does not mention %q.\n\nReported:\n%s",
				name, want, rec.joined())
		}
	}
}

// mustAccept asserts the expectation held.
func mustAccept(t *testing.T, name string, s Subject, e Expectation) {
	t.Helper()
	if rec := check(s, e); rec.failed() {
		t.Errorf("%s: the harness rejected a satisfied expectation:\n%s", name, rec.joined())
	}
}

// --- fixtures ---------------------------------------------------------------

type fixture struct {
	step         domain.Step
	state        domain.State
	failureClass domain.FailureClass
	code         domain.FindingCode
	summary      string
	detail       string
	secret       string
}

func healthyFixture() fixture {
	return fixture{
		step: testStep, state: domain.StateFail,
		failureClass: domain.FailureAuthCredentialsRejected,
		code:         testCode,
		summary:      "The endpoint rejected the credential that was presented",
		detail:       "It named no cause and neither does svcdoctor.",
	}
}

// buildSubject assembles a genuine report through the ordinary domain
// constructors, so every invariant the report enforces is in force here too.
func buildSubject(t *testing.T, f fixture) Subject {
	t.Helper()

	service, err := domain.NewServiceID("postgres")
	if err != nil {
		t.Fatalf("NewServiceID: %v", err)
	}
	run, err := domain.NewRunMetadata("0.0.0-test", time.Unix(0, 0).UTC(), time.Second, service)
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget("db.internal:5432", "db.internal:5432")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage("svcdoctor-test")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	subject, err := domain.NewEndpointSubject("db.internal:5432")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}

	parent, err := domain.NewEvidence(domain.EvidenceInput{
		ID: "tcp.connect/db.internal", Subject: subject, Layer: domain.LayerTCP,
		Step: otherStep, State: domain.StatePass,
		StartedAt: time.Unix(0, 0).UTC(), Elapsed: domain.Measured(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("NewEvidence(parent): %v", err)
	}
	node, err := domain.NewEvidence(domain.EvidenceInput{
		ID: "probe.step/db.internal", Subject: subject, Layer: domain.LayerAuth,
		Step: f.step, State: f.state, FailureClass: f.failureClass,
		StartedAt: time.Unix(0, 0).UTC(), Elapsed: domain.Measured(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("NewEvidence(node): %v", err)
	}

	builder := domain.NewGraphBuilder()
	for _, e := range []domain.Evidence{parent, node} {
		if err := builder.AddEvidence(e); err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
	}
	if err := builder.AddParent(node.ID(), parent.ID()); err != nil {
		t.Fatalf("AddParent: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	recommendation, err := domain.NewRecommendation("Check the endpoint's own log")
	if err != nil {
		t.Fatalf("NewRecommendation: %v", err)
	}
	finding, err := domain.NewFinding(domain.FindingInput{
		Code: f.code, Kind: domain.FindingKindConfirmed, Severity: domain.SeverityError,
		Confidence: domain.ConfidenceHigh, Layer: domain.LayerAuth, Subject: subject,
		Summary: f.summary, Detail: f.detail,
		EvidenceRefs:    []domain.EvidenceID{node.ID()},
		Recommendations: []domain.Recommendation{recommendation},
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
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
	return Subject{Name: "harness-fixture", Report: report, Text: f.secret}
}

// baseline is the expectation the fixture satisfies, so each test below can
// change exactly one thing.
func baseline() Expectation {
	return Expectation{
		RequireFindings: []domain.FindingCode{testCode},
		Nodes: []Node{{
			Step: testStep, State: domain.StateFail,
			FailureClass: domain.FailureAuthCredentialsRejected,
		}},
	}
}

// TestTheFixtureSatisfiesTheBaseline is the non-vacuity floor: if this failed,
// every test below would pass for the wrong reason.
func TestTheFixtureSatisfiesTheBaseline(t *testing.T) {
	s := buildSubject(t, healthyFixture())
	mustAccept(t, "baseline", s, baseline())
}

// H-M1 — a required finding is missing.
func TestARequiredFindingThatIsMissingFails(t *testing.T) {
	s := buildSubject(t, healthyFixture())
	e := baseline()
	e.RequireFindings = []domain.FindingCode{otherCode}
	mustReject(t, "missing-required-finding", s, e, "OTHER_CODE is missing")
}

// H-M2 — a forbidden finding appears.
func TestAForbiddenFindingThatAppearsFails(t *testing.T) {
	s := buildSubject(t, healthyFixture())
	e := baseline()
	e.ForbidFindings = []domain.FindingCode{testCode}
	mustReject(t, "forbidden-finding-present", s, e, "must not be")
}

// H-M3 — a required node is missing.
func TestARequiredNodeThatIsMissingFails(t *testing.T) {
	s := buildSubject(t, healthyFixture())
	e := baseline()
	e.Nodes = []Node{{
		Step: domain.Step("probe.absent"), State: domain.StatePass,
		FailureClass: domain.FailureNone,
	}}
	mustReject(t, "missing-node", s, e, "no node at probe.absent")
}

// H-M4 — a node's state differs.
//
// Both halves are checked: a wrong state and a wrong failure class each fail on
// their own, because a step's claim is the pair and not either alone.
func TestANodeWhoseStateOrClassDiffersFails(t *testing.T) {
	s := buildSubject(t, healthyFixture())

	wrongState := baseline()
	wrongState.Nodes = []Node{{
		Step: testStep, State: domain.StatePass, FailureClass: domain.FailureNone,
	}}
	mustReject(t, "wrong-state", s, wrongState, "no node at probe.step is PASS")

	wrongClass := baseline()
	wrongClass.Nodes = []Node{{
		Step: testStep, State: domain.StateFail,
		FailureClass: domain.FailureProtocolPeerClosed,
	}}
	mustReject(t, "wrong-failure-class", s, wrongClass, "PROTOCOL_PEER_CLOSED")
}

// H-M5 — a forbidden claim appears in the prose.
func TestAForbiddenClaimInTheProseFails(t *testing.T) {
	f := healthyFixture()
	f.detail = "The password is wrong."
	s := buildSubject(t, f)

	e := baseline()
	e.ForbidProse = []string{"the password is wrong"}
	mustReject(t, "forbidden-prose", s, e, "the password is wrong", "TEST_CODE")

	// And the same phrase absent is accepted, so the check is about the phrase
	// rather than about prose existing at all.
	clean := buildSubject(t, healthyFixture())
	mustAccept(t, "prose-clean", clean, e)
}

// TestAForbiddenClaimIsNotQuotedBack proves the failure message names the
// finding without reproducing the surrounding text.
//
// Prose can carry an endpoint's own words or an operator's identifier, so a
// diagnostic must not become the place those escape.
func TestAForbiddenClaimIsNotQuotedBack(t *testing.T) {
	f := healthyFixture()
	f.detail = "The password is wrong for operator-identity-canary."
	s := buildSubject(t, f)

	context := forbiddenClaimContext(s.Report, "the password is wrong")
	if !strings.Contains(context, testCode.String()) {
		t.Errorf("the context does not name the finding: %q", context)
	}
	if strings.Contains(context, "operator-identity-canary") {
		t.Errorf("the context reproduced surrounding prose: %q", context)
	}
}

// H-M6 — the credential attempt count exceeds its bound.
func TestACredentialAttemptCountOverTheBoundFails(t *testing.T) {
	s := buildSubject(t, healthyFixture())
	two := 2
	s.CredentialAttempts = &two

	e := baseline()
	e.MaxCredentialAttempts = Count(1)
	mustReject(t, "over-bound", s, e, "2 credential-bearing attempt")

	one := 1
	s.CredentialAttempts = &one
	mustAccept(t, "at-bound", s, e)
}

// TestAnUnmeasuredCredentialBoundFails closes the gap a bound alone would leave.
//
// Stating a maximum while measuring nothing is the shape of an assertion that
// cannot fail, so the harness refuses it rather than reporting a pass.
func TestAnUnmeasuredCredentialBoundFails(t *testing.T) {
	s := buildSubject(t, healthyFixture())
	e := baseline()
	e.MaxCredentialAttempts = Count(0)
	mustReject(t, "bound-without-measurement", s, e, "measured no count")
}

// TestASecretInTheReportFailsWithoutReproducingIt covers the leak assertion and
// its own discipline at once.
func TestASecretInTheReportFailsWithoutReproducingIt(t *testing.T) {
	f := healthyFixture()
	f.detail = "The credential swordfish-canary was presented."
	s := buildSubject(t, f)

	e := baseline()
	e.ForbidSecrets = []string{"swordfish-canary"}
	mustReject(t, "secret-present", s, e, "the canonical report")

	clean := buildSubject(t, healthyFixture())
	mustAccept(t, "secret-absent", clean, e)
}

// TestAnEmptyForbiddenSecretIsRejected stops an assertion that always passes.
func TestAnEmptyForbiddenSecretIsRejected(t *testing.T) {
	s := buildSubject(t, healthyFixture())
	e := baseline()
	e.ForbidSecrets = []string{""}
	mustReject(t, "empty-secret", s, e, "never fail")
}

// TestResultLevelExpectationsFail covers summary, incompleteness and edges.
func TestResultLevelExpectationsFail(t *testing.T) {
	s := buildSubject(t, healthyFixture())

	wrongSummary := baseline()
	wrongSummary.Summary = Status(domain.SummaryStatusOK)
	mustReject(t, "wrong-summary", s, wrongSummary, "summary status")

	wrongIncomplete := baseline()
	wrongIncomplete.Incomplete = Incomplete()
	mustReject(t, "wrong-incomplete", s, wrongIncomplete, "Incomplete()")

	missingEdge := baseline()
	missingEdge.Edges = []Edge{{Parent: domain.Step("probe.absent"), Child: testStep}}
	mustReject(t, "missing-edge", s, missingEdge, "no probe.step node has a probe.absent parent")

	presentEdge := baseline()
	presentEdge.Edges = []Edge{{Parent: otherStep, Child: testStep}}
	mustAccept(t, "present-edge", s, presentEdge)

	unexpectedNode := baseline()
	unexpectedNode.AbsentSteps = []domain.Step{testStep}
	mustReject(t, "node-should-be-absent", s, unexpectedNode, "want none")
}
