package diagnosis

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.1a, ADR 0081 sections 2.1, 2.2 and 2.6: semantic identity and
// convergence.
//
// Converge is implemented and unwired. These tests are what make 10.1b's wiring
// a diff about wiring rather than about semantics.

func TestDIAG024IdentityIsCodeAndSubject(t *testing.T) {
	g, subject := linearGraph(t)
	other := endpointSubject(t, "other.example:5432")
	_ = g

	base := findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
		domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
		"nothing accepted a connection on that port", "a-tcp")

	// Different prose, same conclusion.
	reworded := findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
		domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
		"the port refused the connection from this vantage point", "a-dns")
	if IdentityOf(base) != IdentityOf(reworded) {
		t.Error("rewording split one conclusion into two; identity must not come from prose")
	}

	// Same prose, different subject.
	elsewhere := findingAbout(t, "TCP_CONNECTION_REFUSED", other,
		domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
		"nothing accepted a connection on that port", "a-tcp")
	if IdentityOf(base) == IdentityOf(elsewhere) {
		t.Error("two subjects were given one identity")
	}

	// Same subject, different code.
	different := findingAbout(t, "DNS_NO_ADDRESS", subject,
		domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
		"nothing accepted a connection on that port", "a-tcp")
	if IdentityOf(base) == IdentityOf(different) {
		t.Error("two codes were given one identity")
	}

	if IdentityOf(base).Code() != "TCP_CONNECTION_REFUSED" {
		t.Errorf("Code() = %s", IdentityOf(base).Code())
	}
	if IdentityOf(base).Subject() != subject {
		t.Errorf("Subject() = %s", IdentityOf(base).Subject())
	}
	if (SemanticIdentity{}).IsZero() != true {
		t.Error("the zero identity does not report zero")
	}
}

// TestARunLevelClaimHasOneIdentity pins ADR 0081 section 2.1's last sentence: a
// finding with no subject has identity (Code, nothing), and there can be at most
// one of it.
func TestARunLevelClaimHasOneIdentity(t *testing.T) {
	// The two routes state one sentence. Identity is what this test is about,
	// and since Phase 10.2a prose is a merge precondition, so routes that
	// disagreed in prose would demonstrate the precondition rather than the
	// identity. The differing-prose case is TestC03.
	a := findingAbout(t, "TCP_CONNECTION_REFUSED", domain.Subject{},
		domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
		"the run reached one claim", "a-tcp")
	b := findingAbout(t, "TCP_CONNECTION_REFUSED", domain.Subject{},
		domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
		"the run reached one claim", "a-dns")

	if IdentityOf(a) != IdentityOf(b) {
		t.Fatal("two run-level claims with one code got two identities")
	}
	if got := IdentityOf(a).String(); got != "TCP_CONNECTION_REFUSED@<run>" {
		t.Errorf("String() = %q", got)
	}

	merged, err := Converge([]AttributedFinding{{Rule: "a/one", Finding: a}, {Rule: "a/two", Finding: b}})
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("got %d findings, want 1", len(merged))
	}
}

// TestDIAG025TheMergeTable walks ADR 0081 section 2.2 field by field.
func TestDIAG025TheMergeTable(t *testing.T) {
	g, subject := linearGraph(t)
	_ = g

	weak, err := domain.NewFinding(domain.FindingInput{
		Code:             "TCP_CONNECTION_REFUSED",
		Kind:             domain.FindingKindHypothesis,
		Severity:         domain.SeverityWarn,
		Confidence:       domain.ConfidenceLow,
		Layer:            domain.LayerTCP,
		Subject:          subject,
		Summary:          "one claim about this endpoint, reached two ways",
		Detail:           "the shared detail both routes write",
		EvidenceRefs:     []domain.EvidenceID{"a-dns"},
		Recommendations:  []domain.Recommendation{recommendation(t, "look at the second thing")},
		VantageDependent: false,
		Discriminator:    "what would settle the weaker route",
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	strong, err := domain.NewFinding(domain.FindingInput{
		Code:             "TCP_CONNECTION_REFUSED",
		Kind:             domain.FindingKindConfirmed,
		Severity:         domain.SeverityError,
		Confidence:       domain.ConfidenceHigh,
		Layer:            domain.LayerTCP,
		Subject:          subject,
		Summary:          "one claim about this endpoint, reached two ways",
		Detail:           "the shared detail both routes write",
		EvidenceRefs:     []domain.EvidenceID{"a-tcp"},
		Recommendations:  []domain.Recommendation{recommendation(t, "look at the first thing")},
		VantageDependent: true,
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}

	merged, err := Converge([]AttributedFinding{
		{Rule: "b/weaker", Finding: weak},
		{Rule: "a/stronger", Finding: strong},
	})
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("got %d findings, want 1", len(merged))
	}
	got := merged[0]

	if want := []domain.EvidenceID{"a-dns", "a-tcp"}; !slices.Equal(got.EvidenceRefs(), want) {
		t.Errorf("EvidenceRefs = %v, want the union %v", got.EvidenceRefs(), want)
	}
	if got.Confidence() != domain.ConfidenceHigh {
		t.Errorf("Confidence = %s, want the maximum HIGH", got.Confidence())
	}
	if got.Kind() != domain.FindingKindConfirmed {
		t.Errorf("Kind = %s, want CONFIRMED to win over HYPOTHESIS", got.Kind())
	}
	if got.Severity() != domain.SeverityError {
		t.Errorf("Severity = %s, want the maximum ERROR", got.Severity())
	}
	// Prose is MUST_EQUAL since Phase 10.2a, so there is nothing to choose: both
	// routes wrote this sentence and the merged finding carries it unchanged.
	// The rule identities here are deliberately reversed alphabetically against
	// the strong/weak split, so a surviving tie-break would be visible.
	if got.Summary() != strong.Summary() || got.Summary() != weak.Summary() {
		t.Errorf("Summary = %q, want the sentence both routes wrote", got.Summary())
	}
	if got.Detail() != strong.Detail() || got.Detail() != weak.Detail() {
		t.Errorf("Detail = %q, want the detail both routes wrote", got.Detail())
	}
	if !got.VantageDependent() {
		t.Error("VantageDependent = false, want the logical OR")
	}
	if got.Discriminator() != "" {
		t.Errorf("Discriminator = %q; a CONFIRMED finding has no open question left",
			got.Discriminator())
	}
	actions := []string{}
	for _, r := range got.Recommendations() {
		actions = append(actions, r.Action())
	}
	// The union's order is derived from the findings' own content — evidence
	// first — and never from a rule's name. "a-dns" sorts before "a-tcp", so the
	// weaker route's advice comes first even though its rule identity is "b/".
	want := []string{"look at the second thing", "look at the first thing"}
	if !slices.Equal(actions, want) {
		t.Errorf("Recommendations = %v, want the content-ordered union %v", actions, want)
	}
}

// TestDIAG026ConfidenceDoesNotAccumulate is mutation M06's other half.
//
// Two MEDIUM routes make MEDIUM. Promoting on count would make confidence a
// vote, and a vote is what lets three weak rules manufacture a strong claim.
func TestDIAG026ConfidenceDoesNotAccumulate(t *testing.T) {
	_, subject := linearGraph(t)

	// Five independent routes to one claim, all writing the same sentence —
	// which is what "the same claim reached five ways" means once prose is a
	// merge precondition. Their evidence differs, so the union grows while the
	// confidence does not.
	var in []AttributedFinding
	for i, rule := range []RuleID{"a/one", "b/two", "c/three", "d/four", "e/five"} {
		in = append(in, AttributedFinding{Rule: rule, Finding: findingAbout(t,
			"TCP_CONNECTION_REFUSED", subject, domain.FindingKindHypothesis,
			domain.SeverityWarn, domain.ConfidenceMedium,
			"one claim, reached independently", domain.EvidenceID("a-route-"+string(rune('a'+i))))})

		merged, err := Converge(in)
		if err != nil {
			t.Fatalf("Converge: %v", err)
		}
		if len(merged) != 1 {
			t.Fatalf("%d routes merged to %d findings, want 1", len(in), len(merged))
		}
		if got := merged[0].Confidence(); got != domain.ConfidenceMedium {
			t.Fatalf("%d MEDIUM routes produced %s; convergence is MEDIUM and does not "+
				"accumulate (ADR 0081 section 2.2)", len(in), got)
		}
	}
}

// TestP11SeparateSubjectsRemainSeparate is property P11 and mutation M10.
func TestP11SeparateSubjectsRemainSeparate(t *testing.T) {
	first := endpointSubject(t, "a.example:9092")
	second := endpointSubject(t, "b.example:9092")

	merged, err := Converge([]AttributedFinding{
		{Rule: "a/one", Finding: findingAbout(t, "TCP_CONNECTION_REFUSED", first,
			domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
			"identical prose about two different endpoints", "a-tcp")},
		{Rule: "a/two", Finding: findingAbout(t, "TCP_CONNECTION_REFUSED", second,
			domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
			"identical prose about two different endpoints", "a-tcp")},
	})
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if len(merged) != 2 {
		t.Fatalf("got %d findings, want 2; two subjects were merged into one claim", len(merged))
	}
	if merged[0].Subject() == merged[1].Subject() {
		t.Error("the two findings ended up about one subject")
	}
}

// TestP10ConvergenceIsCommutativeAndAssociative is property P10 and ADR 0081
// section 7's determinism requirement.
//
// Every merged field is either order-independent — a maximum, a union, a logical
// OR — or taken from a winner chosen by a total order. Shuffling the input can
// therefore change nothing, and this drives many shuffles because a single one
// would pass by luck.
func TestP10ConvergenceIsCommutativeAndAssociative(t *testing.T) {
	_, subject := linearGraph(t)
	other := endpointSubject(t, "other.example:5432")

	in := []AttributedFinding{
		{Rule: "c/third", Finding: findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
			domain.FindingKindHypothesis, domain.SeverityWarn, domain.ConfidenceLow,
			"c summary", "a-dns")},
		{Rule: "a/first", Finding: findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
			domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
			"a summary", "a-tcp")},
		{Rule: "b/second", Finding: findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
			domain.FindingKindHypothesis, domain.SeverityInfo, domain.ConfidenceMedium,
			"b summary", "a-tls")},
		{Rule: "d/fourth", Finding: findingAbout(t, "DNS_NO_ADDRESS", other,
			domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
			"d summary", "a-dns")},
	}

	want, err := json.Marshal(mustConverge(t, in))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	// Every permutation, not a sample. Four inputs give twenty-four orders, which
	// is cheap and exhaustive — and a random shuffle would need a random source,
	// which depguard denies this package for exactly the reason under test.
	for i, order := range permutations(len(in)) {
		shuffled := make([]AttributedFinding, 0, len(in))
		for _, index := range order {
			shuffled = append(shuffled, in[index])
		}

		got, err := json.Marshal(mustConverge(t, shuffled))
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("permutation %d %v changed the merged result:\nwant %s\ngot  %s",
				i, order, want, got)
		}
	}

	// Associativity: merging a merged pair with the third input gives the same
	// answer as merging all three at once. The re-attribution keeps the winner
	// determinable, which is the only thing the second pass needs.
	pair := mustConverge(t, in[:2])
	regrouped := []AttributedFinding{{Rule: "a/first", Finding: pair[0]}}
	for _, f := range pair[1:] {
		regrouped = append(regrouped, AttributedFinding{Rule: "a/first", Finding: f})
	}
	regrouped = append(regrouped, in[2:]...)

	staged, err := json.Marshal(mustConverge(t, regrouped))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(staged) != string(want) {
		t.Errorf("staged merging differed:\nwant %s\ngot  %s", want, staged)
	}
}

// TestConvergeRefusesAnUnattributedFinding pins that the tie-break input is
// required rather than defaulted.
//
// A finding with no rule identity would fall back on input order, and input
// order is wiring order, which must never reach a report.
func TestConvergeRefusesAnUnattributedFinding(t *testing.T) {
	_, subject := linearGraph(t)

	f := findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
		domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
		"a claim", "a-tcp")

	if _, err := Converge([]AttributedFinding{{Finding: f}}); !errors.Is(err, ErrCannotConverge) {
		t.Errorf("an unattributed finding was accepted: %v", err)
	}
	if _, err := Converge([]AttributedFinding{{Rule: "a/one"}}); !errors.Is(err, ErrCannotConverge) {
		t.Errorf("the zero Finding was accepted: %v", err)
	}
}

func TestConvergeOfNothingIsNothing(t *testing.T) {
	got, err := Converge(nil)
	if err != nil {
		t.Fatalf("Converge(nil): %v", err)
	}
	if got != nil {
		t.Errorf("Converge(nil) = %v, want nil", got)
	}
}

// TestConvergeLeavesASingleFindingExactlyAsProduced is the property that makes
// wiring Converge in 10.1b a bounded change: on a rule set where no two rules
// reach one conclusion, merging is the identity function.
func TestConvergeLeavesASingleFindingExactlyAsProduced(t *testing.T) {
	_, subject := linearGraph(t)

	f := findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
		domain.FindingKindHypothesis, domain.SeverityWarn, domain.ConfidenceLow,
		"one route only", "a-tcp")

	merged := mustConverge(t, []AttributedFinding{{Rule: "a/one", Finding: f}})
	if len(merged) != 1 {
		t.Fatalf("got %d findings, want 1", len(merged))
	}

	before, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	after, err := json.Marshal(merged[0])
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("an unmerged finding changed:\nbefore %s\nafter  %s", before, after)
	}
}

func mustConverge(t *testing.T, in []AttributedFinding) []domain.Finding {
	t.Helper()
	out, err := Converge(in)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	return out
}

func recommendation(t *testing.T, action string) domain.Recommendation {
	t.Helper()
	r, err := domain.NewRecommendation(action)
	if err != nil {
		t.Fatalf("NewRecommendation(%q): %v", action, err)
	}
	return r
}

// permutations returns every ordering of the indices 0..n-1, in a deterministic
// order.
//
// It exists because this package may not import a random source: depguard denies
// math/rand and math/rand/v2 to everything under internal/diagnosis, tests
// included, and that denial is the property several of these tests are about. An
// exhaustive enumeration is a stronger check than sampling anyway.
func permutations(n int) [][]int {
	if n <= 1 {
		return [][]int{make([]int, n)}
	}

	var out [][]int
	for i := range n {
		for _, rest := range permutations(n - 1) {
			order := []int{i}
			for _, index := range rest {
				if index >= i {
					index++
				}
				order = append(order, index)
			}
			out = append(out, order)
		}
	}
	return out
}
