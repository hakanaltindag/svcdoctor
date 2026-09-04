package diagnosis

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.1a, ADR 0083 section 2.3: when diagnosis itself fails.
//
// A rule that panics is a defect in svcdoctor, not a fact about the target. The
// response is narrow and fail-closed, and every clause of it is asserted here
// because the whole value of the policy is that it is not improvised at the
// moment it fires.

// TestDIAG041APanickingRuleLosesItsOutputAndTheRunContinues is the core of ADR
// 0083 section 2.3.
func TestDIAG041APanickingRuleLosesItsOutputAndTheRunContinues(t *testing.T) {
	g, subject := linearGraph(t)

	good := findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
		domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
		"the rule that worked", "a-tcp")

	registry, err := NewRuleSet().
		Add("test/panics", func(RuleContext) []domain.Finding { panic("a defect in a rule") }).
		Add("test/works", func(RuleContext) []domain.Finding { return []domain.Finding{good} }).
		Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	out := NewEngine(registry).Evaluate(RuleContext{Graph: g})

	if !out.Failed() {
		t.Fatal("a panicking rule did not mark the evaluation failed")
	}
	failures := out.Failures()
	if len(failures) != 1 || failures[0].Rule() != "test/panics" {
		t.Fatalf("Failures() = %v, want exactly the panicking rule", failures)
	}
	if got := out.Findings(); len(got) != 1 || got[0].Code() != "TCP_CONNECTION_REFUSED" {
		t.Errorf("the surviving rule's findings = %v, want the one it produced", got)
	}
}

// TestAPanickingRuleLosesEveryFindingNotJustTheLastOne pins that the output is
// discarded whole.
//
// Half a rule's findings are not a weaker version of its conclusion; they are an
// arbitrary prefix of one. Keeping them would be trusting a rule that has just
// demonstrated it cannot be trusted.
func TestAPanickingRuleLosesEveryFindingNotJustTheLastOne(t *testing.T) {
	g, subject := linearGraph(t)

	registry, err := NewRuleSet().
		Add("test/half", func(RuleContext) []domain.Finding {
			produced := []domain.Finding{findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
				domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
				"produced before the defect fired", "a-tcp")}
			_ = produced
			panic("after producing something")
		}).
		Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	out := NewEngine(registry).Evaluate(RuleContext{Graph: g})
	if got := out.Findings(); len(got) != 0 {
		t.Errorf("a partial result survived a panic: %v", got)
	}
}

// TestARuleFailureNeverBecomesAFinding is the clause ADR 0083 section 2.3 states
// twice, and the one a well-meaning future edit would break first.
//
// A finding is a claim about the target. svcdoctor falling over is a claim about
// svcdoctor, and a document whose findings are claims about a service must not
// carry one.
func TestARuleFailureNeverBecomesAFinding(t *testing.T) {
	g, _ := linearGraph(t)

	registry, err := NewRuleSet().
		Add("test/panics", func(RuleContext) []domain.Finding { panic("a defect") }).
		Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	out := NewEngine(registry).Evaluate(RuleContext{Graph: g})
	if len(out.Findings()) != 0 {
		t.Fatalf("a rule failure produced findings: %v", out.Findings())
	}
	if !out.Failed() {
		t.Fatal("the failure was not recorded at all")
	}
}

// TestThePanicValueIsNotCaptured is the security clause.
//
// A panic value can hold whatever the panicking code had in hand, and a report
// is designed to be shared. RuleFailure names the rule and nothing else, and
// there is no accessor that could return the value even if something wanted it.
func TestThePanicValueIsNotCaptured(t *testing.T) {
	g, _ := linearGraph(t)

	const secret = "hunter2-this-must-not-appear-anywhere"
	registry, err := NewRuleSet().
		Add("test/panics", func(RuleContext) []domain.Finding { panic(secret) }).
		Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	out := NewEngine(registry).Evaluate(RuleContext{Graph: g})

	rendered := ""
	for _, f := range out.Failures() {
		rendered += f.String() + "\n" + string(f.Rule()) + "\n"
	}
	encoded, err := json.Marshal(out.Findings())
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	rendered += string(encoded)

	if strings.Contains(rendered, secret) {
		t.Fatalf("the panic value reached svcdoctor's own output:\n%s", rendered)
	}

	// And there is no accessor for it. A method returning the recovered value
	// would be the obvious place for it to come back.
	var f any = RuleFailure{}
	if _, ok := f.(interface{ Value() any }); ok {
		t.Error("RuleFailure exposes the recovered value")
	}
	if _, ok := f.(interface{ Stack() string }); ok {
		t.Error("RuleFailure exposes a stack trace")
	}
}

// TestFailuresAreRecordedForEveryPanickingRule pins that one defect does not
// mask another.
func TestFailuresAreRecordedForEveryPanickingRule(t *testing.T) {
	g, _ := linearGraph(t)

	registry, err := NewRuleSet().
		Add("test/first", func(RuleContext) []domain.Finding { panic("one") }).
		Add("test/second", func(RuleContext) []domain.Finding { return nil }).
		Add("test/third", func(RuleContext) []domain.Finding { panic("two") }).
		Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	out := NewEngine(registry).Evaluate(RuleContext{Graph: g})

	var names []RuleID
	for _, f := range out.Failures() {
		names = append(names, f.Rule())
	}
	if want := []RuleID{"test/first", "test/third"}; !slices.Equal(names, want) {
		t.Errorf("Failures() = %v, want %v", names, want)
	}
}

func TestAnOutcomeHandsOutCopies(t *testing.T) {
	g, subject := linearGraph(t)

	registry, err := NewRuleSet().
		Add("test/panics", func(RuleContext) []domain.Finding { panic("a defect") }).
		Add("test/works", func(RuleContext) []domain.Finding {
			return []domain.Finding{findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
				domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
				"a claim", "a-tcp")}
		}).
		Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	out := NewEngine(registry).Evaluate(RuleContext{Graph: g})

	out.Findings()[0] = domain.Finding{}
	out.Failures()[0] = RuleFailure{}

	if out.Findings()[0].IsZero() || out.Failures()[0].IsZero() {
		t.Error("editing a returned slice changed the outcome")
	}
	if (Outcome{}).Failed() {
		t.Error("the zero Outcome reports a failure")
	}
	if got := (RuleFailure{}).String(); got != "<no rule failure>" {
		t.Errorf("the zero RuleFailure renders as %q", got)
	}
}

// TestDIAG042InvalidRuleOutputIsRejectedNotRepaired is ADR 0083 section 2.3's
// other clause, and property P14.
func TestDIAG042InvalidRuleOutputIsRejectedNotRepaired(t *testing.T) {
	g, subject := linearGraph(t)

	valid := findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
		domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
		"a claim resting on evidence that is in the graph", "a-tcp")
	if err := ValidateFinding(valid, g); err != nil {
		t.Errorf("a valid finding was rejected: %v", err)
	}

	dangling := findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
		domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
		"a claim resting on nothing a reader can check", "not-in-this-graph")
	err := ValidateFinding(dangling, g)
	if !errors.Is(err, ErrInvalidRuleOutput) {
		t.Fatalf("a dangling reference was accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "not-in-this-graph") {
		t.Errorf("the error does not name the dangling reference: %v", err)
	}

	if err := ValidateFinding(domain.Finding{}, g); !errors.Is(err, ErrInvalidRuleOutput) {
		t.Errorf("the zero Finding was accepted: %v", err)
	}

	// ValidateFindings stops at the first failure and reports it.
	if err := ValidateFindings([]domain.Finding{valid, dangling}, g); !errors.Is(err, ErrInvalidRuleOutput) {
		t.Errorf("a set containing an invalid finding was accepted: %v", err)
	}
	if err := ValidateFindings([]domain.Finding{valid, valid}, g); err != nil {
		t.Errorf("a set of valid findings was rejected: %v", err)
	}
	if err := ValidateFindings(nil, g); err != nil {
		t.Errorf("an empty set was rejected: %v", err)
	}
}

// TestValidationNeverMutatesTheGraphOrTheFinding pins the "never repaired" half.
//
// Nothing is filled in on a rule's behalf and nothing is dropped from a finding
// to make the rest of it acceptable. Both are values, so this is a property of
// the types; asserting it is cheap and the alternative would be a silent
// downgrade nobody could see in a report.
func TestValidationNeverMutatesTheGraphOrTheFinding(t *testing.T) {
	g, subject := linearGraph(t)

	f := findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
		domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
		"a claim", "a-tcp", "a-dns")

	before, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	nodesBefore := g.Len()

	if err := ValidateFinding(f, g); err != nil {
		t.Fatalf("ValidateFinding: %v", err)
	}

	after, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("validation changed the finding:\nbefore %s\nafter  %s", before, after)
	}
	if g.Len() != nodesBefore {
		t.Errorf("validation changed the graph: %d -> %d nodes", nodesBefore, g.Len())
	}
}
