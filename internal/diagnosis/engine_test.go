package diagnosis

import (
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

var testStart = time.Date(2026, 8, 21, 10, 30, 0, 0, time.UTC)

// --- fixtures ----------------------------------------------------------------

func mustEvidence(t *testing.T, id string, layer domain.Layer, state domain.State) domain.Evidence {
	t.Helper()

	failure := domain.FailureNone
	switch state {
	case domain.StateFail:
		failure = domain.FailureTCPConnectionRefused
	case domain.StateSkipped:
		failure = domain.FailureExecSkippedPrerequisiteFailed
	case domain.StateUnknown, domain.StatePass, domain.StateDegraded:
	}

	subject, err := domain.NewEndpointSubject("kafka.internal:9092")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	evidenceID, err := domain.NewEvidenceID(id)
	if err != nil {
		t.Fatalf("NewEvidenceID(%q): %v", id, err)
	}
	step, err := domain.NewStep("tcp.connect")
	if err != nil {
		t.Fatalf("NewStep: %v", err)
	}

	e, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           evidenceID,
		Subject:      subject,
		Layer:        layer,
		Step:         step,
		State:        state,
		FailureClass: failure,
		StartedAt:    testStart,
		Elapsed:      domain.Measured(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("NewEvidence(%q): %v", id, err)
	}
	return e
}

// testGraph builds a small frozen graph:
//
//	ok    L1 PASS
//	bad   L2 FAIL
//	later L3 SKIPPED, blocked by bad
func testGraph(t *testing.T) domain.Graph {
	t.Helper()

	b := domain.NewGraphBuilder()
	for _, e := range []domain.Evidence{
		mustEvidence(t, "ok", domain.LayerDNS, domain.StatePass),
		mustEvidence(t, "bad", domain.LayerTCP, domain.StateFail),
		mustEvidence(t, "later", domain.LayerTLS, domain.StateSkipped),
	} {
		if err := b.AddEvidence(e); err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
	}
	if err := b.AddParent("bad", "ok"); err != nil {
		t.Fatalf("AddParent: %v", err)
	}
	if err := b.AddBlockedBy("later", "bad"); err != nil {
		t.Fatalf("AddBlockedBy: %v", err)
	}

	g, err := b.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return g
}

// testFinding builds a valid finding referencing one node of the test graph.
func testFinding(t *testing.T, code string, severity domain.Severity, ref string) domain.Finding {
	t.Helper()

	findingCode, err := domain.NewFindingCode(code)
	if err != nil {
		t.Fatalf("NewFindingCode(%q): %v", code, err)
	}
	evidenceID, err := domain.NewEvidenceID(ref)
	if err != nil {
		t.Fatalf("NewEvidenceID(%q): %v", ref, err)
	}

	f, err := domain.NewFinding(domain.FindingInput{
		Code:         findingCode,
		Kind:         domain.FindingKindConfirmed,
		Severity:     severity,
		Confidence:   domain.ConfidenceHigh,
		Layer:        domain.LayerTCP,
		Summary:      "example finding for engine tests",
		EvidenceRefs: []domain.EvidenceID{evidenceID},
	})
	if err != nil {
		t.Fatalf("NewFinding(%q): %v", code, err)
	}
	return f
}

// ruleReturning returns a rule that always emits the given findings.
func ruleReturning(findings ...domain.Finding) Rule {
	return func(RuleContext) []domain.Finding { return findings }
}

// rctx wraps a graph in the context a rule receives.
//
// These tests are about the engine, not about what a rule reads, so the vantage
// is unset and the run is not marked incomplete. A test that needs either says
// so at its own call site.
func rctx(g domain.Graph) RuleContext { return RuleContext{Graph: g} }

// engineOf wires rules under positional identities and returns the engine.
//
// Identity matters to the engine only for duplicate detection and, later, for
// the merge tie-break; which rule holds which name is the composition root's
// business. Naming them positionally keeps these tests about evaluation.
func engineOf(t *testing.T, rules ...Rule) Engine {
	t.Helper()

	set := NewRuleSet()
	for i, rule := range rules {
		set.Add("test/rule-"+strconv.Itoa(i), rule)
	}
	registry, err := set.Freeze()
	if err != nil {
		t.Fatalf("freezing the rule set: %v", err)
	}
	return NewEngine(registry)
}

func codesOf(findings []domain.Finding) []domain.FindingCode {
	out := make([]domain.FindingCode, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Code())
	}
	return out
}

func equalCodes(a, b []domain.FindingCode) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- engine basics -----------------------------------------------------------

func TestZeroEngineHasNoRules(t *testing.T) {
	var e Engine

	if e.RuleCount() != 0 {
		t.Errorf("RuleCount() = %d, want 0", e.RuleCount())
	}
	if got := e.Diagnose(rctx(testGraph(t))); got != nil {
		t.Errorf("Diagnose() = %v, want nil", got)
	}
}

func TestEmptyRuleSet(t *testing.T) {
	e := engineOf(t)

	if e.RuleCount() != 0 {
		t.Errorf("RuleCount() = %d, want 0", e.RuleCount())
	}
	if got := e.Diagnose(rctx(testGraph(t))); got != nil {
		t.Errorf("Diagnose() = %v, want nil", got)
	}
}

// TestEmptyGraphIsValid covers a run that produced no evidence. Rules see an
// empty graph and normally have nothing to report.
func TestEmptyGraphIsValid(t *testing.T) {
	empty, err := domain.NewGraphBuilder().Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	seen := 0
	e := engineOf(t, func(ctx RuleContext) []domain.Finding {
		seen = ctx.Graph.Len()
		return nil
	})

	if got := e.Diagnose(rctx(empty)); got != nil {
		t.Errorf("Diagnose() = %v, want nil", got)
	}
	if seen != 0 {
		t.Errorf("the rule saw %d nodes, want 0", seen)
	}
}

func TestOneRuleOneFinding(t *testing.T) {
	want := testFinding(t, "TCP_CONNECTION_REFUSED", domain.SeverityError, "bad")
	e := engineOf(t, ruleReturning(want))

	got := e.Diagnose(rctx(testGraph(t)))
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Code() != want.Code() {
		t.Errorf("Code() = %s, want %s", got[0].Code(), want.Code())
	}
}

func TestMultipleRules(t *testing.T) {
	e := engineOf(t,
		ruleReturning(testFinding(t, "AAA_FIRST", domain.SeverityError, "bad")),
		ruleReturning(testFinding(t, "BBB_SECOND", domain.SeverityError, "ok")),
		ruleReturning(), // a rule that finds nothing
		ruleReturning(
			testFinding(t, "CCC_THIRD", domain.SeverityError, "later"),
			testFinding(t, "DDD_FOURTH", domain.SeverityError, "bad"),
		),
	)

	got := e.Diagnose(rctx(testGraph(t)))
	if len(got) != 4 {
		t.Fatalf("got %d findings, want 4", len(got))
	}
	if e.RuleCount() != 4 {
		t.Errorf("RuleCount() = %d, want 4", e.RuleCount())
	}
}

// TestNilRulesAreRejected pins that a wiring mistake cannot silently shrink the
// rule set.
//
// # What changed in Phase 10.1a, and why it is stronger
//
// NewEngine used to skip a nil rule while its documentation said it rejected
// one, so a wiring mistake produced an engine with fewer rules than the
// composition listed and a report missing findings nobody noticed were absent.
// Registration now refuses it: the rule set carries the error and Freeze returns
// it, so the mistake cannot reach an Engine at all.
func TestNilRulesAreRejected(t *testing.T) {
	set := NewRuleSet().
		Add("test/one", ruleReturning(testFinding(t, "AAA_ONE", domain.SeverityError, "bad"))).
		Add("test/nil", nil).
		Add("test/two", ruleReturning(testFinding(t, "BBB_TWO", domain.SeverityError, "ok")))

	registry, err := set.Freeze()
	if !errors.Is(err, ErrInvalidRuleSet) {
		t.Fatalf("Freeze() error = %v, want ErrInvalidRuleSet", err)
	}
	if registry.Len() != 0 {
		t.Errorf("a refused rule set produced %d rules, want none", registry.Len())
	}
}

// TestEngineIsImmutableAfterConstruction proves a caller cannot change an
// engine's behaviour by reusing the slice it passed in.
func TestEngineIsImmutableAfterConstruction(t *testing.T) {
	set := NewRuleSet().
		Add("test/one", ruleReturning(testFinding(t, "AAA_ONE", domain.SeverityError, "bad")))

	registry, err := set.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	e := NewEngine(registry)

	// Adding to the builder after the freeze, and editing the slice the frozen
	// registry hands out, are the two ways a caller could reach an engine's
	// behaviour. Neither does.
	set.Add("test/injected", ruleReturning(
		testFinding(t, "ZZZ_INJECTED", domain.SeverityCritical, "ok"),
		testFinding(t, "YYY_INJECTED", domain.SeverityCritical, "ok"),
	))
	handedOut := registry.Rules()
	if len(handedOut) != 1 {
		t.Fatalf("Rules() = %d entries, want 1", len(handedOut))
	}
	handedOut[0] = RegisteredRule{}

	got := e.Diagnose(rctx(testGraph(t)))
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Code() != "AAA_ONE" {
		t.Errorf("the engine changed with the caller's slice: %s", got[0].Code())
	}
}

// --- determinism -------------------------------------------------------------

func TestRepeatedEvaluationIsIdentical(t *testing.T) {
	g := testGraph(t)
	e := engineOf(t,
		ruleReturning(testFinding(t, "BBB_TWO", domain.SeverityWarn, "ok")),
		ruleReturning(testFinding(t, "AAA_ONE", domain.SeverityCritical, "bad")),
		ruleReturning(testFinding(t, "CCC_THREE", domain.SeverityInfo, "later")),
	)

	first, err := json.Marshal(e.Diagnose(rctx(g)))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	for i := 0; i < 25; i++ {
		again, err := json.Marshal(e.Diagnose(rctx(g)))
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if string(first) != string(again) {
			t.Fatalf("evaluation %d differed:\n%s\n%s", i, first, again)
		}
	}
}

// TestFindingOrderIsCanonicalNotRuleOrder is the ordering guarantee: how the
// engine was wired must not reach the output.
func TestFindingOrderIsCanonicalNotRuleOrder(t *testing.T) {
	build := func(t *testing.T) []Rule {
		t.Helper()
		return []Rule{
			ruleReturning(testFinding(t, "AAA_INFO", domain.SeverityInfo, "ok")),
			ruleReturning(testFinding(t, "BBB_CRITICAL", domain.SeverityCritical, "bad")),
			ruleReturning(testFinding(t, "CCC_WARN", domain.SeverityWarn, "later")),
			ruleReturning(testFinding(t, "DDD_ERROR", domain.SeverityError, "bad")),
		}
	}

	want := []domain.FindingCode{"BBB_CRITICAL", "DDD_ERROR", "CCC_WARN", "AAA_INFO"}
	g := testGraph(t)

	for _, order := range [][]int{{0, 1, 2, 3}, {3, 2, 1, 0}, {2, 0, 3, 1}, {1, 3, 0, 2}} {
		src := build(t)
		wired := make([]Rule, 0, len(order))
		for _, i := range order {
			wired = append(wired, src[i])
		}

		got := codesOf(engineOf(t, wired...).Diagnose(rctx(g)))
		if !equalCodes(got, want) {
			t.Errorf("rule order %v produced %v, want %v", order, got, want)
		}
	}
}

// TestOrderMatchesReportOrder pins that the engine and the report agree, because
// both use domain.SortFindings rather than two implementations of one order.
func TestOrderMatchesReportOrder(t *testing.T) {
	findings := []domain.Finding{
		testFinding(t, "AAA_INFO", domain.SeverityInfo, "ok"),
		testFinding(t, "BBB_CRITICAL", domain.SeverityCritical, "bad"),
		testFinding(t, "CCC_WARN", domain.SeverityWarn, "later"),
	}

	fromEngine := codesOf(engineOf(t, ruleReturning(findings...)).Diagnose(rctx(testGraph(t))))

	independent := make([]domain.Finding, len(findings))
	copy(independent, findings)
	domain.SortFindings(independent)

	if !equalCodes(fromEngine, codesOf(independent)) {
		t.Errorf("engine order %v differs from canonical order %v",
			fromEngine, codesOf(independent))
	}
}

// --- graph is untouched ------------------------------------------------------

func TestGraphIsUnchangedByDiagnosis(t *testing.T) {
	g := testGraph(t)

	before := make([]domain.EvidenceID, 0, g.Len())
	for _, n := range g.Nodes() {
		before = append(before, n.ID())
	}

	// A rule that reads everything it can reach, including relationship lists.
	e := engineOf(t, func(ctx RuleContext) []domain.Finding {
		for _, n := range ctx.Graph.Nodes() {
			parents := ctx.Graph.Parents(n.ID())
			for i := range parents {
				parents[i] = "mutated"
			}
			blockers := ctx.Graph.BlockedBy(n.ID())
			for i := range blockers {
				blockers[i] = "mutated"
			}
		}
		return nil
	})
	e.Diagnose(rctx(g))

	if g.Len() != 3 {
		t.Errorf("Len() = %d, want 3", g.Len())
	}
	after := make([]domain.EvidenceID, 0, g.Len())
	for _, n := range g.Nodes() {
		after = append(after, n.ID())
	}
	for i := range before {
		if before[i] != after[i] {
			t.Errorf("node %d changed: %q -> %q", i, before[i], after[i])
		}
	}
	if got := g.Parents("bad"); len(got) != 1 || got[0] != "ok" {
		t.Errorf("Parents(bad) = %v, want [ok]", got)
	}
	if got := g.BlockedBy("later"); len(got) != 1 || got[0] != "bad" {
		t.Errorf("BlockedBy(later) = %v, want [bad]", got)
	}
}

// --- duplicates --------------------------------------------------------------

// TestDuplicateFindingsConverge closes ADR 0017's deferral.
//
// That record declined to deduplicate for want of a definition of when two
// findings are the same conclusion, and named the missing definition as the
// blocker. ADR 0081 section 2.1 supplies it and section 2.2 the merge; Phase
// 10.1a implemented both and wired neither, so that activating them would be one
// reviewable change. This is that change's assertion.
//
// It read "want 2 (no deduplication)" in Phase 10.1a, and its doc comment said
// it would fail the day merging was wired in. That day was Phase 10.1b.
func TestDuplicateFindingsConverge(t *testing.T) {
	duplicate := testFinding(t, "TCP_CONNECTION_REFUSED", domain.SeverityError, "bad")

	e := engineOf(t, ruleReturning(duplicate), ruleReturning(duplicate))

	got := e.Diagnose(rctx(testGraph(t)))
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: two rules stating one conclusion is one "+
			"conclusion (ADR 0081 section 2.2)", len(got))
	}
	if got[0].Code() != duplicate.Code() {
		t.Errorf("Code = %s, want %s", got[0].Code(), duplicate.Code())
	}
	// The claim rests on what both routes cited, which here is the same node.
	if want := []domain.EvidenceID{"bad"}; !slices.Equal(got[0].EvidenceRefs(), want) {
		t.Errorf("EvidenceRefs = %v, want %v", got[0].EvidenceRefs(), want)
	}
}

// --- architectural boundaries ------------------------------------------------

// TestEngineCannotReceiveGraphBuilder pins ADR 0013 at the diagnosis boundary:
// a rule reads a frozen graph, never a builder.
func TestEngineCannotReceiveGraphBuilder(t *testing.T) {
	var e any = Engine{}

	if _, ok := e.(interface {
		Diagnose(*domain.GraphBuilder) []domain.Finding
	}); ok {
		t.Error("Engine must not accept a GraphBuilder")
	}
	if _, ok := e.(interface{ Freeze() domain.Graph }); ok {
		t.Error("Engine must not freeze a graph")
	}
}

// TestEngineProducesNoReportOrSummary pins that diagnosis stops at findings.
func TestEngineProducesNoReportOrSummary(t *testing.T) {
	var e any = Engine{}

	forbidden := []struct {
		name string
		has  bool
	}{
		{"Report", hasMethod[interface{ Report() domain.Report }](e)},
		{"Summary", hasMethod[interface{ Summary() domain.Summary }](e)},
		{"ExitCode", hasMethod[interface{ ExitCode() int }](e)},
		{"Render", hasMethod[interface{ Render() string }](e)},
		{"Redact", hasMethod[interface{ Redact() error }](e)},
	}
	for _, f := range forbidden {
		if f.has {
			t.Errorf("Engine must not expose %s", f.name)
		}
	}
}

// TestEngineHasNoServiceDispatch pins the core invariant. The engine holds no
// service name, so there is nothing for it to branch on.
func TestEngineHasNoServiceDispatch(t *testing.T) {
	var e any = Engine{}

	forbidden := []struct {
		name string
		has  bool
	}{
		{"Service", hasMethod[interface{ Service() domain.ServiceID }](e)},
		{"ForService", hasMethod[interface {
			ForService(domain.ServiceID) Engine
		}](e)},
		{"Register", hasMethod[interface{ Register(string, Rule) }](e)},
		{"RulesFor", hasMethod[interface{ RulesFor(string) []Rule }](e)},
		{"ForOwner", hasMethod[interface{ ForOwner(string) Engine }](e)},
	}
	for _, f := range forbidden {
		if f.has {
			t.Errorf("Engine must not expose %s", f.name)
		}
	}

	// An engine takes a frozen registry, not a service name: a rule set is
	// chosen by wiring, and the engine cannot narrow or widen it afterwards.
	if NewEngine(Registry{}).RuleCount() != 0 {
		t.Error("an engine over the zero registry should hold no rules")
	}
}

// TestDiagnoseReturnsNoError pins the contract decision. Rules read a frozen
// in-memory graph and have nothing operational to fail at, so an error result
// would exist only to be always nil.
func TestDiagnoseReturnsNoError(t *testing.T) {
	var e any = Engine{}

	if _, ok := e.(interface {
		Diagnose(RuleContext) ([]domain.Finding, error)
	}); ok {
		t.Error("Diagnose must not return an error")
	}
	if _, ok := e.(interface {
		Diagnose(RuleContext) []domain.Finding
	}); !ok {
		t.Error("Diagnose should return findings only")
	}
}

// TestRuleSignatureTakesOnlyTheRuleContext pins the contract shape.
//
// ADR 0017 fixed it at a graph; ADR 0080 section 2.1 widened it to RuleContext
// in Phase 10.1a, and the widening was made once so that the next admitted fact
// is a field rather than a third signature. The old shape must no longer
// satisfy the type, which is what the negative half asserts.
func TestRuleSignatureTakesOnlyTheRuleContext(t *testing.T) {
	// Compiles only while Rule is exactly func(RuleContext) []domain.Finding.
	var r Rule = func(RuleContext) []domain.Finding { return nil }

	if got := r(rctx(testGraph(t))); got != nil {
		t.Errorf("a rule returning nil should yield nil, got %v", got)
	}

	var e any = Engine{}
	if _, ok := e.(interface {
		Diagnose(domain.Graph) []domain.Finding
	}); ok {
		t.Error("the pre-10.1a graph-only shape must no longer be accepted")
	}
}

func hasMethod[T any](v any) bool {
	_, ok := v.(T)
	return ok
}
